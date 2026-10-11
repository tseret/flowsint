"""Tests that the enricher Celery tasks forward launch params downstream."""

import uuid
from contextlib import nullcontext
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from flowsint_core.tasks import enricher as enricher_task


@pytest.fixture(autouse=True)
def mocked_lease(monkeypatch):
    monkeypatch.setattr(
        enricher_task, "task_lease", lambda session, task_id: nullcontext(True)
    )


def fresh_session():
    session = MagicMock()
    session.get.return_value = None
    return session


class RecordingEnricher:
    """Stands in for a real enricher: records nothing, executes to no results."""

    async def execute(self, values: List[dict]) -> List[Any]:
        return []


@pytest.fixture
def captured_kwargs(monkeypatch):
    """Neutralise the task's DB and vault work, capture the enricher kwargs."""
    monkeypatch.setattr(
        enricher_task, "SessionLocal", MagicMock(return_value=fresh_session())
    )
    monkeypatch.setattr(enricher_task, "create_vault_service", MagicMock())

    captured: Dict[str, Any] = {}

    def fake_get_enricher(**kwargs):
        captured.update(kwargs)
        return RecordingEnricher()

    monkeypatch.setattr(
        enricher_task.ENRICHER_REGISTRY, "enricher_exists", lambda name: True
    )
    monkeypatch.setattr(
        enricher_task.ENRICHER_REGISTRY, "get_enricher", fake_get_enricher
    )
    return captured


def _run(**kwargs):
    return enricher_task.run_enricher.apply(
        args=["some_enricher", [], str(uuid.uuid4()), str(uuid.uuid4())],
        kwargs=kwargs,
        throw=True,
    )


def test_run_enricher_forwards_params_to_the_enricher(captured_kwargs):
    _run(params={"api_key": "abc123", "limit": "10"})

    assert captured_kwargs["params"] == {"api_key": "abc123", "limit": "10"}


def test_run_enricher_without_params_passes_an_empty_dict(captured_kwargs):
    # The shape of a message queued by an API instance that predates `params`.
    _run()

    assert captured_kwargs["params"] == {}


def test_run_template_enricher_forwards_params_to_the_template_enricher(monkeypatch):
    monkeypatch.setattr(
        enricher_task, "SessionLocal", MagicMock(return_value=fresh_session())
    )
    monkeypatch.setattr(enricher_task, "create_vault_service", MagicMock())

    db_template = MagicMock()
    db_template.content = {
        "name": "example",
        "category": "Ip",
        "version": 1.0,
        "input": {"type": "Ip"},
        "request": {"url": "https://api.example.com/{{address}}"},
        "response": {},
        "output": {"type": "Ip"},
    }
    template_service = MagicMock()
    template_service.find_by_name.return_value = db_template
    monkeypatch.setattr(
        enricher_task, "create_enricher_template_service", lambda s: template_service
    )

    captured: Dict[str, Any] = {}

    def fake_template_enricher(**kwargs):
        captured.update(kwargs)
        return RecordingEnricher()

    monkeypatch.setattr(enricher_task, "TemplateEnricher", fake_template_enricher)

    enricher_task.run_template_enricher.apply(
        args=["example", [], str(uuid.uuid4()), str(uuid.uuid4())],
        kwargs={"params": {"GITHUB_TOKEN": "ghp_xxx"}},
        throw=True,
    )

    assert captured["params"] == {"GITHUB_TOKEN": "ghp_xxx"}


def test_task_does_not_mark_recorded_provider_failure_completed(monkeypatch):
    from flowsint_core.core.enums import EventLevel

    session = fresh_session()
    monkeypatch.setattr(enricher_task, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        enricher_task.ENRICHER_REGISTRY, "enricher_exists", lambda name: True
    )

    class FailedEnricher(RecordingEnricher):
        execution_summary = {
            "outcome": "quota_exceeded",
            "errors": [{"outcome": "quota_exceeded", "message": "Quota reached"}],
        }

    monkeypatch.setattr(
        enricher_task.ENRICHER_REGISTRY,
        "get_enricher",
        lambda **kwargs: FailedEnricher(),
    )
    result = enricher_task.run_enricher.apply(
        args=["example", [], str(uuid.uuid4())], throw=True
    ).result
    scan = session.add.call_args.args[0]
    assert scan.status == EventLevel.FAILED
    assert scan.details == []
    assert scan.summary["outcome"] == "quota_exceeded"
    assert scan.completed_at is not None
    assert result["summary"] == scan.summary


@pytest.mark.parametrize("task_name", ["run_enricher", "run_template_enricher"])
@pytest.mark.parametrize(
    "outcome",
    [
        "results",
        "no_matches",
        "partial",
        "failed",
        "missing_credentials",
        "quota_exceeded",
    ],
)
def test_terminal_status_is_published_after_summary_commit(
    monkeypatch, task_name, outcome
):
    from flowsint_core.core.enums import EventLevel

    session = fresh_session()
    monkeypatch.setattr(enricher_task, "SessionLocal", lambda: session)
    monkeypatch.setattr(enricher_task, "create_vault_service", MagicMock())
    enricher = RecordingEnricher()
    enricher.execution_summary = {"outcome": outcome, "scan_id": "run", "errors": []}
    monkeypatch.setattr(
        enricher_task.ENRICHER_REGISTRY, "enricher_exists", lambda name: True
    )
    monkeypatch.setattr(
        enricher_task.ENRICHER_REGISTRY, "get_enricher", lambda **kwargs: enricher
    )
    template_service = MagicMock()
    template_service.find_by_name.return_value.content = {
        "name": "example",
        "category": "Ip",
        "version": 1.0,
        "input": {"type": "Ip"},
        "request": {"url": "https://api.example.com/{{address}}"},
        "response": {},
        "output": {"type": "Ip"},
    }
    monkeypatch.setattr(
        enricher_task,
        "create_enricher_template_service",
        lambda session: template_service,
    )
    monkeypatch.setattr(enricher_task, "TemplateEnricher", lambda **kwargs: enricher)
    logger = MagicMock()
    monkeypatch.setattr(enricher_task, "Logger", logger)

    def observe_status(sketch_id, level, message):
        scan = session.add.call_args.args[0]
        assert session.commit.call_count == 2
        assert scan.summary == message["summary"]
        assert scan.summary["outcome"] == outcome
        assert scan.completed_at is not None
        expected = (
            EventLevel.WARNING
            if outcome == "partial"
            else EventLevel.FAILED
            if outcome in {"failed", "missing_credentials", "quota_exceeded"}
            else EventLevel.COMPLETED
        )
        assert level == expected

    logger.status.side_effect = observe_status
    task = getattr(enricher_task, task_name)
    task.apply(args=["example", [], str(uuid.uuid4()), str(uuid.uuid4())], throw=True)
    logger.status.assert_called_once()
    assert enricher.defer_status_until_commit is True


@pytest.mark.parametrize("task_name", ["run_enricher", "run_template_enricher"])
def test_task_setup_failure_also_emits_committed_failed_summary(monkeypatch, task_name):
    session = fresh_session()
    session.query.return_value.filter.return_value.first.side_effect = lambda: (
        session.add.call_args.args[0]
    )
    monkeypatch.setattr(enricher_task, "SessionLocal", lambda: session)
    monkeypatch.setattr(enricher_task, "create_vault_service", MagicMock())
    monkeypatch.setattr(
        enricher_task.ENRICHER_REGISTRY, "enricher_exists", lambda name: False
    )
    template_service = MagicMock()
    template_service.find_by_name.return_value = None
    monkeypatch.setattr(
        enricher_task,
        "create_enricher_template_service",
        lambda session: template_service,
    )
    logger = MagicMock()
    monkeypatch.setattr(enricher_task, "Logger", logger)
    task = getattr(enricher_task, task_name)
    monkeypatch.setattr(task, "update_state", MagicMock())
    with pytest.raises(ValueError):
        task.apply(
            args=["missing", [], str(uuid.uuid4()), str(uuid.uuid4())], throw=True
        )
    assert session.commit.call_count == 2
    logger.status.assert_called_once()
    assert logger.status.call_args.args[2]["summary"]["outcome"] == "failed"
    summary = logger.status.call_args.args[2]["summary"]
    assert {
        "duration_ms",
        "scan_id",
        "enricher",
        "provider",
        "input_count",
        "output_count",
        "errors",
    } <= summary.keys()
    assert summary["duration_ms"] >= 0


@pytest.mark.parametrize("task_name", ["run_enricher", "run_template_enricher"])
def test_duplicate_completed_delivery_returns_saved_result(monkeypatch, task_name):
    from datetime import datetime, timezone

    from flowsint_core.core.enums import EventLevel
    from flowsint_core.core.models import Scan

    session = fresh_session()
    scan = Scan(
        id=uuid.uuid4(),
        status=EventLevel.COMPLETED,
        details=[{"saved": True}],
        summary={"outcome": "results"},
        completed_at=datetime.now(timezone.utc),
    )
    session.get.return_value = scan
    monkeypatch.setattr(enricher_task, "SessionLocal", lambda: session)
    factory = MagicMock()
    monkeypatch.setattr(enricher_task.ENRICHER_REGISTRY, "get_enricher", factory)
    result = (
        getattr(enricher_task, task_name)
        .apply(
            args=["example", [], None, str(uuid.uuid4())],
            task_id=str(scan.id),
            throw=True,
        )
        .result
    )
    assert result == {"result": scan.details, "summary": scan.summary}
    factory.assert_not_called()
    session.add.assert_not_called()
    session.commit.assert_not_called()


def test_concurrent_delivery_does_not_change_scan(monkeypatch):
    session = fresh_session()
    monkeypatch.setattr(enricher_task, "SessionLocal", lambda: session)
    monkeypatch.setattr(enricher_task, "task_lease", lambda *args: nullcontext(False))
    result = _run().result
    assert result["in_progress"] is True
    session.get.assert_not_called()
    session.commit.assert_not_called()


def test_orphaned_delivery_retains_checkpoint_without_repeating_calls(monkeypatch):
    from flowsint_core.core.enums import EventLevel
    from flowsint_core.core.models import Scan

    session = fresh_session()
    scan = Scan(
        id=uuid.uuid4(),
        status=EventLevel.RUNNING,
        summary={"committed_graph_operations": 100, "provider_request_count": 2},
    )
    session.get.return_value = scan
    monkeypatch.setattr(enricher_task, "SessionLocal", lambda: session)
    factory = MagicMock()
    monkeypatch.setattr(enricher_task.ENRICHER_REGISTRY, "get_enricher", factory)
    result = _run().result
    assert result["summary"]["committed_graph_operations"] == 100
    assert result["summary"]["provider_request_count"] == 2
    assert result["summary"]["graph_commit_uncertain"] is True
    assert result["summary"]["output_count"] is None
    assert result["summary"]["outcome"] == "partial"
    assert scan.completed_at is not None
    factory.assert_not_called()


def test_graph_checkpoint_records_committed_progress_and_provider_evidence():
    from types import SimpleNamespace

    from flowsint_core.core.graph.repository import Neo4jGraphRepository
    from flowsint_core.core.models import Scan

    session = fresh_session()
    repository = Neo4jGraphRepository(MagicMock())
    scan = Scan(id=uuid.uuid4(), summary={"outcome": "running"})
    enricher = SimpleNamespace(_graph_service=SimpleNamespace(repository=repository))
    enricher_task._checkpoint_enricher(
        enricher, scan, session, {"max_new_entities": 20, "max_provider_requests": 3}
    )
    enricher.provider_request_count = 1
    enricher.provider_evidence = [
        {"provider": "example", "source_scan_id": str(scan.id)}
    ]
    repository._record_commit(100)
    assert scan.summary["committed_graph_operations"] == 100
    assert scan.summary["provider_request_count"] == 1
    assert scan.summary["provider_evidence"] == enricher.provider_evidence
    assert repository.max_new_entities == 20
    assert enricher.provider_request_limit == 3
    session.commit.assert_called_once()
