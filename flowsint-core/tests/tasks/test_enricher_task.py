"""Tests that the enricher Celery tasks forward launch params downstream."""

import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from flowsint_core.tasks import enricher as enricher_task


class RecordingEnricher:
    """Stands in for a real enricher: records nothing, executes to no results."""

    async def execute(self, values: List[dict]) -> List[Any]:
        return []


@pytest.fixture
def captured_kwargs(monkeypatch):
    """Neutralise the task's DB and vault work, capture the enricher kwargs."""
    monkeypatch.setattr(enricher_task, "SessionLocal", MagicMock())
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
    monkeypatch.setattr(enricher_task, "SessionLocal", MagicMock())
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

    session = MagicMock()
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

    session = MagicMock()
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
    session = MagicMock()
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
