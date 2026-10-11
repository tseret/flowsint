"""Test simplified API for create_node and create_relationship."""

from typing import Any, Dict, List, Optional
from unittest.mock import Mock

import pytest
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher, InvalidEnricherParams
from flowsint_types.domain import Domain
from flowsint_types.individual import Individual


class MockEnricher(Enricher):
    """Simple enricher for testing."""

    InputType = Domain
    OutputType = Domain

    @classmethod
    def name(cls) -> str:
        return "test_enricher"

    @classmethod
    def category(cls) -> str:
        return "Test"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [{"name": "API_KEY", "type": "vaultSecret", "required": False}]

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        return data


def test_create_relationship_with_pydantic_objects():
    """Test that create_relationship works with Pydantic objects."""
    enricher = MockEnricher(sketch_id="test", scan_id="test")

    # Create objects
    individual = Individual(first_name="John", last_name="Doe", full_name="John Doe")
    domain = Domain(domain="example.com")

    # This should not raise an error
    enricher.create_relationship(individual, domain, "HAS_DOMAIN")


def test_create_node_with_property_override():
    """Test that property overrides work with Pydantic objects."""
    enricher = MockEnricher(sketch_id="test", scan_id="test")

    domain = Domain(domain="example.com")

    # Should be able to override properties
    enricher.create_node(domain)


class PrimaryFlagged(BaseModel):
    first: Optional[str] = None
    required_one: str
    flagged: Optional[str] = Field(None, json_schema_extra={"primary": True})


class RequiredOnly(BaseModel):
    first: Optional[str] = None
    required_one: str


class AllOptional(BaseModel):
    first: Optional[str] = None
    second: Optional[str] = None


@pytest.mark.parametrize(
    ("input_type", "expected"),
    [
        (Domain, "domain"),
        (PrimaryFlagged, "flagged"),
        (RequiredOnly, "required_one"),
        (AllOptional, "first"),
        (NotImplemented, None),
    ],
)
def test_default_key_is_input_type_primary_field(input_type, expected):
    enricher_cls = type("KeyedEnricher", (MockEnricher,), {"InputType": input_type})
    assert enricher_cls.key() == expected


def test_primary_field_drives_string_preprocess():
    enricher_cls = type("KeyedEnricher", (MockEnricher,), {"InputType": PrimaryFlagged})
    enricher = enricher_cls(sketch_id="test", scan_id="test")
    # A bare string lands in the primary field; required_one missing -> skipped.
    assert enricher.preprocess(["x", {"required_one": "r", "flagged": "f"}]) == [
        PrimaryFlagged(required_one="r", flagged="f")
    ]


def test_params_schema_defaults_to_declared_schema():
    enricher = MockEnricher(sketch_id="test", scan_id="test")
    assert enricher.params_schema == MockEnricher.get_params_schema()


def test_explicit_empty_params_schema_is_kept():
    enricher = MockEnricher(sketch_id="test", scan_id="test", params_schema=[])
    assert enricher.params_schema == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "issue,results,expected",
    [
        (None, [], "no_matches"),
        (None, [Domain(domain="example.com")], "results"),
        ("quota_exceeded", [], "quota_exceeded"),
        ("failed", [Domain(domain="example.com")], "partial"),
    ],
)
async def test_execution_summary_distinguishes_results_and_provider_errors(
    issue, results, expected
):
    from unittest.mock import MagicMock

    class ResultEnricher(MockEnricher):
        async def scan(self, values):
            if issue:
                self.report_issue(issue, "Provider unavailable")
            return results

    enricher = ResultEnricher(graph_service=MagicMock(), scan_id="run-1")
    assert await enricher.execute([Domain(domain="example.com")]) == results
    assert enricher.execution_summary["outcome"] == expected
    assert enricher.execution_summary["input_count"] == 1
    assert enricher.execution_summary["output_count"] == len(results)
    assert enricher.execution_summary["scan_id"] == "run-1"


@pytest.mark.asyncio
async def test_scan_exception_is_recorded_as_failure():
    from unittest.mock import MagicMock

    class BrokenEnricher(MockEnricher):
        async def scan(self, values):
            raise RuntimeError("Provider unavailable")

    graph = MagicMock()
    enricher = BrokenEnricher(graph_service=graph)
    assert await enricher.execute([Domain(domain="example.com")]) == []
    assert enricher.execution_summary["outcome"] == "failed"
    graph.repository.clear_batch.assert_called_once()


@pytest.mark.asyncio
async def test_legacy_logged_failures_are_isolated_between_concurrent_runs(monkeypatch):
    import asyncio
    from queue import Queue
    from unittest.mock import MagicMock

    from flowsint_core.core.logger import LoggerSingleton, enrichment_errors

    logger = object.__new__(LoggerSingleton)
    logger._get_next_sequence = MagicMock(return_value=1)
    logger._emit_event = MagicMock()
    logger._log_queue = Queue()
    logger._batch_size = 1000
    logger.completed = MagicMock()
    logger.warn = MagicMock()
    logger.status = MagicMock()
    monkeypatch.setattr("flowsint_core.core.enricher_base.Logger", logger)

    class LegacyEnricher(MockEnricher):
        async def scan(self, values):
            await asyncio.sleep(0)
            if self.scan_id == "bad":
                logger.error(self.sketch_id, {"message": "Provider HTTP 429"})
            await asyncio.sleep(0)
            return []

    failed = LegacyEnricher(scan_id="bad", graph_service=MagicMock())
    empty = LegacyEnricher(scan_id="empty", graph_service=MagicMock())
    await asyncio.gather(
        failed.execute([Domain(domain="bad.com")]),
        empty.execute([Domain(domain="empty.com")]),
    )
    assert failed.execution_summary["outcome"] == "quota_exceeded"
    assert empty.execution_summary["outcome"] == "no_matches"
    assert enrichment_errors.get() is None
    assert logger.completed.call_count == 1


@pytest.mark.asyncio
async def test_explicit_and_legacy_issues_are_both_retained_without_duplicate_messages(
    monkeypatch,
):
    from unittest.mock import MagicMock

    from flowsint_core.core.logger import enrichment_errors

    class MixedEnricher(MockEnricher):
        async def scan(self, values):
            self.report_issue("partial", "Truncated response")
            enrichment_errors.get().extend(
                ["Truncated response", "Provider HTTP 429", "Provider HTTP 429"]
            )
            return [Domain(domain="example.com")]

    monkeypatch.setattr("flowsint_core.core.enricher_base.Logger", MagicMock())
    enricher = MixedEnricher(graph_service=MagicMock())
    await enricher.execute([Domain(domain="example.com")])
    assert enricher.execution_summary["errors"] == [
        {"outcome": "partial", "message": "Truncated response"},
        {"outcome": "quota_exceeded", "message": "Provider HTTP 429"},
    ]


@pytest.mark.asyncio
async def test_invalid_params_identify_missing_field_without_logging_resolved_secret():
    vault = Mock()
    vault.get_secret.return_value = "sensitive-api-key"
    enricher = MockEnricher(
        vault=vault,
        graph_service=Mock(),
        params_schema=[
            {"name": "API_KEY", "type": "vaultSecret", "required": True},
            {"name": "port", "type": "number", "required": True},
        ],
    )

    with pytest.raises(InvalidEnricherParams, match=r"port \(missing\)") as error:
        await enricher.async_init()

    assert "sensitive-api-key" not in str(error.value)


@pytest.mark.asyncio
async def test_failure_after_automatic_batch_commit_reports_saved_graph():
    from unittest.mock import MagicMock

    from flowsint_core.core.graph.repository import Neo4jGraphRepository
    from flowsint_core.core.graph.service import GraphService

    connection = MagicMock()
    repository = Neo4jGraphRepository(connection)
    checkpoints = []
    repository.on_commit = checkpoints.append
    graph = GraphService("test", repository, enable_batching=True)

    class LateFailure(MockEnricher):
        async def scan(self, values):
            for index in range(101):
                self.create_node(Domain(domain=f"node-{index}.example.com"))
            raise RuntimeError("Provider failed after the first committed batch")

    enricher = LateFailure(graph_service=graph)
    assert await enricher.execute([]) == []
    assert enricher.execution_summary["outcome"] == "partial"
    assert enricher.execution_summary["committed_graph_operations"] == 100
    assert checkpoints == [100]
    connection.execute_batch.assert_called_once()
    assert repository._batch_operations == []


@pytest.mark.asyncio
async def test_failed_batch_is_not_counted_as_committed():
    from unittest.mock import MagicMock

    from flowsint_core.core.graph.repository import Neo4jGraphRepository
    from flowsint_core.core.graph.service import GraphService

    connection = MagicMock()
    connection.execute_batch.side_effect = RuntimeError("Transaction rolled back")
    repository = Neo4jGraphRepository(connection)
    graph = GraphService("test", repository, enable_batching=True)

    class FailedWrite(MockEnricher):
        async def scan(self, values):
            self.create_node(Domain(domain="example.com"))
            return values

    enricher = FailedWrite(graph_service=graph)
    assert await enricher.execute([]) == []
    assert enricher.execution_summary["outcome"] == "failed"
    assert enricher.execution_summary["committed_graph_operations"] == 0


def test_relationship_snapshots_safe_facts_before_target_changes():
    from unittest.mock import MagicMock

    from flowsint_types.ip import Ip
    from flowsint_types.port import Port
    from flowsint_types.ssl_certificate import SSLCertificate

    graph = MagicMock()
    enricher = MockEnricher(graph_service=graph)
    source = Ip(address="192.0.2.1")
    port = Port(
        number=0,
        protocol="tcp",
        service="nginx",
        state="open",
        fingerprints={
            "banner_hash": 0,
            "tls_sha256": "a" * 64,
            "api_key": "secret",
            "html_hash": "x" * 513,
        },
        banner="sensitive banner",
        password="secret",
    )
    enricher.create_relationship(source, port)
    observation = graph.create_relationship.call_args.kwargs["observation"]
    port.service = "changed"
    port.fingerprints["tls_sha256"] = "changed"
    assert observation["facts"] == {
        "number": 0,
        "protocol": "tcp",
        "service": "nginx",
        "status": "open",
        "fingerprints": {"banner_hash": 0, "tls_sha256": "a" * 64},
    }
    certificate = SSLCertificate(
        subject="example.com", is_valid=False, fingerprint_sha256="b" * 64
    )
    enricher.create_relationship(source, certificate)
    facts = graph.create_relationship.call_args.kwargs["observation"]["facts"]
    assert facts["is_valid"] is False
    assert facts["fingerprints"] == {"certificate_sha256": "b" * 64}


def test_cached_relationship_retains_original_retrieval_and_response_association():
    from unittest.mock import MagicMock

    from flowsint_types.port import Port

    graph = MagicMock()
    enricher = MockEnricher(graph_service=graph, scan_id="current-scan")
    original = {
        "fetched_at": "2026-01-01T12:00:00Z",
        "source_scan_id": "first-scan",
        "request_id": "request-one",
        "cache_hit": True,
        "secret": "hidden",
    }
    enricher.provider_evidence = [original, {"fetched_at": "2026-02-01T12:00:00Z"}]
    enricher.create_relationship(
        Domain(domain="example.com"), Port(number=443), provider_evidence=original
    )
    observation = graph.create_relationship.call_args.kwargs["observation"]
    assert observation["retrieved_at"] == original["fetched_at"]
    assert observation["source_scan_id"] == "first-scan"
    assert observation["scan_id"] == "current-scan"
    assert observation["cache_hit"] is True
    assert "secret" not in observation
    enricher.create_relationship(Domain(domain="example.com"), Port(number=80))
    ambiguous = graph.create_relationship.call_args.kwargs["observation"]
    assert "source_scan_id" not in ambiguous
    assert "cache_hit" not in ambiguous
