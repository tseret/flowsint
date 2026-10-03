"""Autonomous agent loop: passive dispatch, cancellation, citations, failures."""

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from flowsint_core.core.graph.types import GraphData, GraphNode, NodeMetadata
from flowsint_core.core.llm.protocol import SubscriptionError
from flowsint_core.core.models import (
    AgentRun,
    CaseItem,
    Investigation,
    InvestigationUserRole,
    Profile,
    Scan,
    Sketch,
)
from flowsint_core.core.types import Role
from flowsint_core.tasks import agent
from flowsint_types import Domain


def _node(node_id: str) -> GraphNode:
    return GraphNode(
        id=node_id,
        nodeLabel="example.org",
        nodeType="domain",
        nodeProperties=Domain(domain="example.org"),
        nodeMetadata=NodeMetadata(),
    )


class Provider:
    """Replays model replies; a callable reply runs a side effect first."""

    def __init__(self, replies: list[Any]):
        self.replies = replies
        self.calls = 0

    async def complete(self, messages) -> str:
        self.calls += 1
        reply = self.replies.pop(0)
        return reply() if callable(reply) else reply


@pytest.fixture
def env(db_session, monkeypatch):
    owner = Profile(id=uuid4(), email="a@test.invalid", hashed_password="x")
    db_session.add(owner)
    db_session.flush()
    inv = Investigation(id=uuid4(), name="Case", owner_id=owner.id)
    db_session.add(inv)
    db_session.flush()
    db_session.add(
        InvestigationUserRole(
            id=uuid4(), user_id=owner.id, investigation_id=inv.id, roles=[Role.OWNER]
        )
    )
    sketch = Sketch(id=uuid4(), investigation_id=inv.id, title="S")
    db_session.add(sketch)
    db_session.commit()

    state = SimpleNamespace(
        provider=Provider([]),
        graph=GraphData(nodes=[_node("seed")], edges=[]),
        dispatched=[],
        scan_status="COMPLETED",
        on_dispatch=None,
        session=db_session,
    )
    chat = MagicMock()
    chat.get_subscription_provider.side_effect = lambda owner_id: state.provider
    monkeypatch.setattr(agent, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(agent, "create_chat_service", lambda db: chat)
    monkeypatch.setattr(agent, "create_type_registry_service", MagicMock())
    monkeypatch.setattr(
        agent,
        "create_graph_service",
        lambda **kw: SimpleNamespace(get_sketch_graph=lambda: state.graph),
    )
    monkeypatch.setattr(
        agent.ENRICHER_REGISTRY,
        "list",
        lambda: [
            {"name": "domain_to_whois", "inputs": {"type": "Domain"}},
            {"name": "domain_to_root_domain", "inputs": {"type": "Domain"}},
            {"name": "domain_to_dns", "inputs": {"type": "Domain"}},
        ],
    )
    monkeypatch.setattr(agent, "Logger", MagicMock())
    monkeypatch.setattr(agent, "POLL_S", 0)

    def send_task(name, args, kwargs):
        scan_id = uuid4()
        state.dispatched.append((name, args[0]))
        db_session.add(
            Scan(
                id=scan_id,
                sketch_id=sketch.id,
                status=state.scan_status,
                summary={"outcome": "results", "output_count": 2, "errors": []},
                details=[{"registrar": "Example"}],
            )
        )
        db_session.commit()
        if state.on_dispatch:
            state.on_dispatch()
        return SimpleNamespace(id=str(scan_id))

    monkeypatch.setattr(agent.celery, "send_task", send_task)

    def start(max_steps: int = 5) -> AgentRun:
        run = AgentRun(
            sketch_id=sketch.id,
            owner_id=owner.id,
            objective="Map the domain",
            seed_ids=["seed"],
            max_steps=max_steps,
        )
        db_session.add(run)
        db_session.commit()
        state.run_id = run.id
        return run

    state.start = start
    return state


def _cancel(env) -> None:
    run = env.session.get(AgentRun, env.run_id)
    run.status = "cancelled"
    env.session.commit()


def _execute(env) -> AgentRun:
    agent.run_investigation_agent.apply(args=[str(env.run_id)], throw=True)
    return env.session.get(AgentRun, env.run_id, populate_existing=True)


ENRICH = json.dumps(
    {
        "thought": "t",
        "action": "enrich",
        "enricher": "domain_to_whois",
        "node_ids": ["seed"],
    }
)
FINISH = json.dumps({"action": "finish"})


def _report(env, cite: str | None = None) -> str:
    scan = cite or env.session.query(Scan).first().id
    return json.dumps(
        {
            "report": f"Registered via Example [scan:{scan}].",
            "findings": [
                {
                    "body": "Registrar is Example",
                    "scan_ids": [str(scan)],
                    "target_node_id": "seed",
                },
                {"body": "Foreign", "scan_ids": [str(uuid4())]},
            ],
        }
    )


def test_agent_runs_passive_steps_then_publishes_cited_draft_findings(env):
    env.start()
    env.provider = Provider(
        [
            "Plan:\n" + ENRICH,
            # Repeating the same lookup is rejected and fed back, not dispatched.
            ENRICH,
            FINISH,
            lambda: _report(env),
        ]
    )
    run = _execute(env)

    assert run.status == "completed", run.error
    assert env.dispatched == [("run_enricher", "domain_to_whois")]
    assert [
        (s["step"], s["enricher"], s["outcome"], s["output_count"]) for s in run.steps
    ] == [(1, "domain_to_whois", "results", 2)]
    assert run.report.startswith("Registered via Example [scan:")
    item = env.session.query(CaseItem).one()
    assert (item.kind, item.decision, item.target_id) == ("finding", "pending", "seed")
    assert json.loads(item.evidence)["scan_ids"] == [run.steps[0]["scan_id"]]
    assert run.finding_ids == [str(item.id)]


def test_repeated_invalid_decisions_still_report_gathered_evidence(env):
    env.start()
    env.provider = Provider(
        [ENRICH, "not json", ENRICH, '{"action": "scan"}', lambda: _report(env)]
    )
    run = _execute(env)
    assert run.status == "completed", run.error
    assert len(run.steps) == 1 and env.provider.calls == 5


def test_subscription_error_fails_run_verbatim_without_lookups(env):
    env.start()
    message = "Connect your ChatGPT subscription in Profile to use the copilot."
    agent.create_chat_service(
        None
    ).get_subscription_provider.side_effect = SubscriptionError(message)
    run = _execute(env)
    assert (run.status, run.error) == ("failed", message)
    assert env.dispatched == []


def test_cancel_during_step_stops_without_report(env):
    env.start(max_steps=5)
    env.provider = Provider([ENRICH])
    env.on_dispatch = lambda: _cancel(env)
    run = _execute(env)
    assert run.status == "cancelled"
    assert len(run.steps) == 1 and run.report is None
    assert env.provider.calls == 1


def test_cancel_while_writing_report_never_publishes(env):
    env.start(max_steps=1)

    def cancel_then_report():
        _cancel(env)
        return _report(env)

    env.provider = Provider([ENRICH, cancel_then_report])
    run = _execute(env)
    assert run.status == "cancelled"
    assert run.report is None
    assert env.session.query(CaseItem).count() == 0


def test_foreign_report_citation_fails_run(env):
    env.start(max_steps=1)
    foreign = str(uuid4())
    env.provider = Provider([ENRICH, _report(env, foreign), _report(env, foreign)])
    run = _execute(env)
    assert run.status == "failed"
    assert "unknown scans" in run.error
    assert env.session.query(CaseItem).count() == 0


def test_stalled_scan_is_recorded_as_timeout_and_loop_continues(env, monkeypatch):
    monkeypatch.setattr(agent, "STEP_TIMEOUT_S", 0)
    env.start(max_steps=2)
    env.scan_status = "PENDING"
    env.provider = Provider(
        [
            ENRICH,
            FINISH,
            lambda: json.dumps(
                {
                    "report": "Lookup timed out "
                    f"[scan:{env.session.query(Scan).first().id}].",
                    "findings": [],
                }
            ),
        ]
    )
    run = _execute(env)
    assert run.status == "completed", run.error
    assert run.steps[0]["outcome"] == "timeout"
    assert isinstance(UUID(run.steps[0]["scan_id"]), UUID)
