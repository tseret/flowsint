"""Test simplified API for create_node and create_relationship."""

from typing import Any, Dict, List, Optional

import pytest
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher
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
