"""Copilot plans are reviewed, scoped, and validated before worker execution."""

import json
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from app.api.routes import copilot as route
from app.api.routes.flows import compute_flow_branches
from flowsint_core.core.graph import GraphNode
from flowsint_core.core.graph.types import NodeMetadata
from flowsint_core.core.models import Flow, Key, Profile, Scan
from flowsint_core.core.types import FlowEdge, FlowNode, Role
from flowsint_types import Domain, Ip
from tests.test_enrichers import _seed_user


@pytest.fixture
def backend(monkeypatch):
    nodes = [
        GraphNode(
            id="domain-1",
            nodeLabel="sub.example.org",
            nodeType="domain",
            nodeProperties=Domain(domain="sub.example.org"),
            nodeMetadata=NodeMetadata(),
            version=2,
        ),
        GraphNode(
            id="ip-1",
            nodeLabel="192.0.2.1",
            nodeType="ip",
            nodeProperties=Ip(address="192.0.2.1"),
            nodeMetadata=NodeMetadata(),
            version=1,
        ),
    ]
    graph = MagicMock()
    graph.get_nodes_by_ids.side_effect = lambda ids: [
        node for node in nodes if node.id in ids
    ]
    graph.query.return_value = []
    factory = MagicMock(return_value=graph)
    monkeypatch.setattr(route, "create_graph_service", factory)
    monkeypatch.setattr(route, "_provider", lambda db, user: None)
    task = MagicMock(side_effect=lambda *args, **kwargs: MagicMock(id=str(uuid4())))
    monkeypatch.setattr(route.celery, "send_task", task)
    return graph, factory, task, nodes


def _request(sketch_id, node_ids=None):
    return {
        "sketch_id": sketch_id,
        "node_ids": node_ids or ["domain-1"],
        "question": "What existing intelligence supports this case?",
    }


def _plan(sketch_id, steps=None, node_ids=None):
    selected = node_ids or ["domain-1"]
    return {
        **_request(sketch_id, selected),
        "analysis": "Passive lookup",
        "steps": steps
        if steps is not None
        else [
            {
                "enricher": "domain_to_root_domain",
                "node_ids": ["domain-1"],
                "reason": "Derive the parent domain",
                "missing_keys": [],
            }
        ],
        "context_truncated": False,
        "node_versions": {
            node_id: 2 if node_id == "domain-1" else 1 for node_id in selected
        },
    }


def _key(db_session, sketch_id):
    from flowsint_core.core.models import Sketch

    owner_id = db_session.get(Sketch, UUID(sketch_id)).owner_id
    key = Key(
        id=uuid4(),
        owner_id=owner_id,
        name="THREATFOX_API_KEY",
        ciphertext=b"test",
        iv=b"test",
        salt=b"test",
        key_version="V1",
    )
    db_session.add(key)
    db_session.commit()
    return key


@pytest.mark.parametrize("endpoint", ["plan", "run", "save"])
def test_permissions_checked_before_graph_access(client, db_session, backend, endpoint):
    headers, sketch_id = _seed_user(db_session, ())
    body = _request(sketch_id) if endpoint == "plan" else _plan(sketch_id)
    if endpoint == "save":
        body["name"] = "Recipe"
    response = client.post(f"/api/copilot/{endpoint}", headers=headers, json=body)
    assert response.status_code == 403
    backend[1].assert_not_called()
    backend[2].assert_not_called()


def test_viewer_can_plan_but_cannot_run(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.VIEWER,))
    response = client.post(
        "/api/copilot/plan", headers=headers, json=_request(sketch_id)
    )
    assert response.status_code == 200
    assert response.json()["node_versions"] == {"domain-1": 2}
    backend[1].reset_mock()
    response = client.post("/api/copilot/run", headers=headers, json=response.json())
    assert response.status_code == 403
    backend[1].assert_not_called()
    backend[2].assert_not_called()


def test_missing_or_other_sketch_entity_rejected(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    response = client.post(
        "/api/copilot/plan",
        headers=headers,
        json=_request(sketch_id, ["domain-1", "other-sketch-node"]),
    )
    assert response.status_code == 404
    assert backend[1].call_args.kwargs["sketch_id"] == sketch_id
    backend[0].query.assert_not_called()


def test_no_model_fallback_is_explicit_and_passive(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    response = client.post(
        "/api/copilot/plan", headers=headers, json=_request(sketch_id)
    )
    assert response.status_code == 200
    result = response.json()
    assert "No LLM was used" in result["analysis"]
    assert {step["enricher"] for step in result["steps"]} == {
        "domain_to_root_domain",
        "domain_to_threatfox",
    }
    threatfox = next(
        step for step in result["steps"] if step["enricher"] == "domain_to_threatfox"
    )
    assert threatfox["missing_keys"] == ["THREATFOX_API_KEY"]
    backend[2].assert_not_called()


def test_fabricated_model_plan_rejected(client, db_session, backend, monkeypatch):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    provider = MagicMock()
    provider.complete = AsyncMock(
        return_value=json.dumps(
            {
                "analysis": "probe",
                "steps": [
                    {
                        "enricher": "active_probe",
                        "node_ids": ["domain-1"],
                        "reason": "do it",
                    }
                ],
            }
        )
    )
    monkeypatch.setattr(route, "_provider", lambda db, user: provider)
    response = client.post(
        "/api/copilot/plan", headers=headers, json=_request(sketch_id)
    )
    assert response.status_code == 502
    backend[2].assert_not_called()


def test_valid_model_plan_uses_provider_interface_and_server_prerequisites(
    client, db_session, backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    provider = MagicMock()
    provider.complete = AsyncMock(
        return_value=json.dumps(
            {
                "analysis": "Existing IOC intelligence may inform this hypothesis.",
                "steps": [
                    {
                        "enricher": "domain_to_threatfox",
                        "node_ids": ["domain-1"],
                        "reason": "Consult recorded malware indicators",
                        "missing_keys": [],
                    }
                ],
            }
        )
    )
    monkeypatch.setattr(route, "_provider", lambda db, user: provider)
    response = client.post(
        "/api/copilot/plan", headers=headers, json=_request(sketch_id)
    )
    assert response.status_code == 200
    result = response.json()
    assert result["analysis"] == "Existing IOC intelligence may inform this hypothesis."
    assert result["steps"][0]["missing_keys"] == ["THREATFOX_API_KEY"]
    assert result["node_versions"] == {"domain-1": 2}
    provider.complete.assert_awaited_once()
    messages = provider.complete.call_args.args[0]
    assert [message.role.value for message in messages] == ["system", "user"]
    context = json.loads(messages[1].content)
    assert context["question"] == _request(sketch_id)["question"]
    backend[2].assert_not_called()


def test_run_refreshes_missing_credentials(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    body = _plan(
        sketch_id,
        [
            {
                "enricher": "domain_to_threatfox",
                "node_ids": ["domain-1"],
                "reason": "Existing evidence",
                "missing_keys": [],
            }
        ],
    )
    assert (
        client.post("/api/copilot/run", headers=headers, json=body).status_code == 422
    )
    backend[2].assert_not_called()
    key = _key(db_session, sketch_id)
    body["steps"][0]["missing_keys"] = ["THREATFOX_API_KEY"]
    assert (
        client.post("/api/copilot/run", headers=headers, json=body).status_code == 200
    )
    assert backend[2].call_count == 1
    db_session.delete(key)
    db_session.commit()
    backend[2].reset_mock()
    assert (
        client.post("/api/copilot/run", headers=headers, json=body).status_code == 422
    )
    backend[2].assert_not_called()


def test_changed_entity_version_requires_new_plan(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    body = _plan(sketch_id)
    body["node_versions"]["domain-1"] = 1
    response = client.post("/api/copilot/run", headers=headers, json=body)
    assert response.status_code == 409
    backend[2].assert_not_called()
    assert db_session.query(Flow).count() == 0


def test_all_inputs_serialized_before_queue(client, db_session, backend, monkeypatch):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    _key(db_session, sketch_id)
    body = _plan(
        sketch_id,
        [
            {
                "enricher": "domain_to_root_domain",
                "node_ids": ["domain-1"],
                "reason": "Parent domain",
            },
            {
                "enricher": "ip_to_threatfox",
                "node_ids": ["ip-1"],
                "reason": "Existing intelligence",
            },
        ],
        ["domain-1", "ip-1"],
    )
    serializer = MagicMock(
        side_effect=[
            Domain(domain="sub.example.org"),
            ValueError("Invalid persisted entity"),
        ]
    )
    monkeypatch.setattr(
        route.GraphSerializer, "graph_node_to_flowsint_type", serializer
    )
    response = client.post("/api/copilot/run", headers=headers, json=body)
    assert response.status_code == 422
    assert serializer.call_count == 2
    backend[2].assert_not_called()


def test_partial_broker_failure_reports_already_queued_runs(
    client, db_session, backend
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    _key(db_session, sketch_id)
    body = _plan(
        sketch_id,
        [
            {
                "enricher": "domain_to_root_domain",
                "node_ids": ["domain-1"],
                "reason": "Parent domain",
            },
            {
                "enricher": "domain_to_threatfox",
                "node_ids": ["domain-1"],
                "reason": "Existing intelligence",
            },
        ],
    )
    backend[2].side_effect = [
        MagicMock(id="already-queued"),
        RuntimeError("Broker unavailable"),
    ]
    response = client.post("/api/copilot/run", headers=headers, json=body)
    assert response.status_code == 200
    assert response.json()["runs"] == [
        {
            "id": "already-queued",
            "enricher": "domain_to_root_domain",
            "node_ids": ["domain-1"],
        }
    ]
    assert "Only part" in response.json()["error"]
    assert backend[2].call_count == 2


def test_initial_broker_failure_returns_unavailable(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    backend[2].side_effect = RuntimeError("Broker unavailable")
    response = client.post("/api/copilot/run", headers=headers, json=_plan(sketch_id))
    assert response.status_code == 503


def test_all_steps_revalidated_before_any_task_is_queued(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    body = _plan(sketch_id)
    body["steps"].append(
        {
            "enricher": "ip_to_threatfox",
            "node_ids": ["domain-1"],
            "reason": "Incompatible",
        }
    )
    response = client.post("/api/copilot/run", headers=headers, json=body)
    assert response.status_code == 422
    backend[2].assert_not_called()


def test_run_queues_persisted_typed_selected_entity(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.EDITOR,))
    response = client.post("/api/copilot/run", headers=headers, json=_plan(sketch_id))
    assert response.status_code == 200
    assert len(response.json()["runs"]) == 1
    call = backend[2].call_args
    assert call.args == ("run_enricher",)
    assert call.kwargs["args"][0] == "domain_to_root_domain"
    assert call.kwargs["args"][1] == [
        Domain(domain="sub.example.org").model_dump(mode="json", serialize_as_any=True)
    ]
    assert call.kwargs["args"][2] == sketch_id
    assert db_session.get(Profile, UUID(call.kwargs["args"][3])) is not None
    assert call.kwargs["kwargs"] == {"params": {}}


def test_saved_recipe_compatible_with_existing_flow_engine(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    body = _plan(sketch_id)
    # The completed enrichment may have incremented versions; a reusable recipe
    # stores no original entity values and can still be saved after that run.
    body["node_versions"]["domain-1"] = 1
    body["name"] = "Passive parent domains"
    response = client.post("/api/copilot/save", headers=headers, json=body)
    assert response.status_code == 200
    flow = db_session.get(Flow, UUID(response.json()["id"]))
    assert flow.category == ["Domain"]
    assert "domain-1" not in json.dumps(flow.flow_schema)
    branches = compute_flow_branches(
        "sub.example.org",
        [FlowNode.model_validate(node) for node in flow.flow_schema["nodes"]],
        [FlowEdge.model_validate(edge) for edge in flow.flow_schema["edges"]],
    )
    assert len(branches) == 1
    assert [step.type for step in branches[0].steps] == ["type", "enricher"]
    assert branches[0].steps[-1].nodeId.startswith("domain_to_root_domain")
    backend[2].assert_not_called()


def test_stale_recipe_still_rechecks_current_entity_type(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    body = _plan(sketch_id)
    body["name"] = "Recipe"
    backend[3][0].nodeType = "ip"
    backend[3][0].version = 3
    response = client.post("/api/copilot/save", headers=headers, json=body)
    assert response.status_code == 422
    assert db_session.query(Flow).count() == 0


def _run(db_session, sketch_id, status="COMPLETED", outcome="no_match"):
    run = Scan(
        id=uuid4(),
        sketch_id=UUID(sketch_id),
        status=status,
        summary={
            "enricher": "domain_to_root_domain",
            "outcome": outcome,
            "input_count": 1,
            "output_count": 0,
        },
        details={"evidence": []},
    )
    db_session.add(run)
    db_session.commit()
    return run


def test_summary_cannot_read_another_sketch_run(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    _, other_sketch = _seed_user(db_session, (Role.OWNER,))
    run = _run(db_session, other_sketch)
    response = client.post(
        "/api/copilot/summary",
        headers=headers,
        json={
            "sketch_id": sketch_id,
            "run_ids": [str(run.id)],
            "question": "Summarize",
        },
    )
    assert response.status_code == 404


def test_pending_summary_waits_for_terminal_runs(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    run = _run(db_session, sketch_id, "RUNNING")
    response = client.post(
        "/api/copilot/summary",
        headers=headers,
        json={
            "sketch_id": sketch_id,
            "run_ids": [str(run.id)],
            "question": "Summarize",
        },
    )
    assert response.status_code == 409


def test_summary_rejects_unknown_model_citations(
    client, db_session, backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    run = _run(db_session, sketch_id)
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=f"Observed evidence [run:{uuid4()}]")
    monkeypatch.setattr(route, "_provider", lambda db, user: provider)
    response = client.post(
        "/api/copilot/summary",
        headers=headers,
        json={
            "sketch_id": sketch_id,
            "run_ids": [str(run.id)],
            "question": "Summarize",
        },
    )
    assert response.status_code == 502


def test_valid_model_summary_returns_scoped_run_evidence(
    client, db_session, backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.VIEWER,))
    run = _run(db_session, sketch_id)
    provider = MagicMock()
    expected = f"No new root domain was recorded [run:{run.id}]. This does not establish absence of threats."
    provider.complete = AsyncMock(return_value=expected)
    monkeypatch.setattr(route, "_provider", lambda db, user: provider)
    response = client.post(
        "/api/copilot/summary",
        headers=headers,
        json={
            "sketch_id": sketch_id,
            "run_ids": [str(run.id)],
            "question": "Summarize",
        },
    )
    assert response.status_code == 200
    assert response.json()["summary"] == expected
    assert [item["run_id"] for item in response.json()["evidence"]] == [str(run.id)]
    provider.complete.assert_awaited_once()
    messages = provider.complete.call_args.args[0]
    assert json.loads(messages[1].content)["evidence"]["runs"][0]["run_id"] == str(
        run.id
    )
    backend[2].assert_not_called()


def test_summary_without_model_reports_limits_and_run_evidence(
    client, db_session, backend
):
    headers, sketch_id = _seed_user(db_session, (Role.VIEWER,))
    run = _run(db_session, sketch_id, "FAILED", "failed")
    response = client.post(
        "/api/copilot/summary",
        headers=headers,
        json={
            "sketch_id": sketch_id,
            "run_ids": [str(run.id)],
            "question": "Summarize",
        },
    )
    assert response.status_code == 200
    result = response.json()
    assert "no LLM used" in result["summary"]
    assert f"[run:{run.id}]" in result["summary"]
    assert "inconclusive" in result["summary"]
    assert result["evidence"][0]["run_id"] == str(run.id)
    backend[2].assert_not_called()
