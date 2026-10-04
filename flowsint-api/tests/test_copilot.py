"""Agent runs and recorded-evidence routes are scoped and validated before work."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from app.api.routes import copilot as route
from flowsint_core.core.graph import GraphNode
from flowsint_core.core.graph.types import NodeMetadata
from flowsint_core.core.llm.protocol import SubscriptionError
from flowsint_core.core.models import AgentRun
from flowsint_core.core.types import Role
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
    monkeypatch.setattr(route, "create_chat_service", MagicMock())
    task = MagicMock(side_effect=lambda *args, **kwargs: MagicMock(id=str(uuid4())))
    monkeypatch.setattr(route.celery, "send_task", task)
    return graph, factory, task, nodes


def _request(sketch_id, node_ids=None):
    return {
        "sketch_id": sketch_id,
        "node_ids": node_ids or ["domain-1"],
        "question": "What existing intelligence supports this case?",
    }


def _agent(sketch_id, **values):
    return {
        "sketch_id": sketch_id,
        "node_ids": ["domain-1", "domain-1"],
        "objective": "Map the infrastructure of this domain",
        "max_steps": 5,
        **values,
    }


def test_agent_start_queues_one_run_for_unique_existing_seeds(
    client, db_session, backend
):
    headers, sketch_id = _seed_user(db_session, (Role.EDITOR,))
    response = client.post(
        "/api/copilot/agent", headers=headers, json=_agent(sketch_id)
    )
    assert response.status_code == 201
    run = response.json()
    assert (run["status"], run["seed_ids"], run["max_steps"]) == (
        "running",
        ["domain-1"],
        5,
    )
    backend[2].assert_called_once_with("run_investigation_agent", args=[run["id"]])


@pytest.mark.parametrize(
    "roles, body, code",
    [
        ((Role.VIEWER,), {}, 403),
        ((Role.OWNER,), {"node_ids": ["domain-1", "other-sketch-node"]}, 404),
        ((Role.OWNER,), {"max_steps": 51}, 422),
        ((Role.OWNER,), {"node_ids": [f"n{i}" for i in range(11)]}, 422),
    ],
)
def test_agent_start_rejects_without_queueing(
    client, db_session, backend, roles, body, code
):
    headers, sketch_id = _seed_user(db_session, roles)
    response = client.post(
        "/api/copilot/agent", headers=headers, json=_agent(sketch_id, **body)
    )
    assert response.status_code == code
    assert db_session.query(AgentRun).count() == 0
    backend[2].assert_not_called()


def test_agent_start_requires_subscription_and_reports_it_verbatim(
    client, db_session, backend
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    message = "The investigation agent requires ChatGPT subscription mode."
    provider = route.create_chat_service.return_value.get_subscription_provider
    provider.side_effect = SubscriptionError(message)
    response = client.post(
        "/api/copilot/agent", headers=headers, json=_agent(sketch_id)
    )
    assert (response.status_code, response.json()["detail"]) == (502, message)
    assert db_session.query(AgentRun).count() == 0
    backend[2].assert_not_called()


def test_agent_broker_failure_keeps_no_run(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    backend[2].side_effect = RuntimeError("Broker unavailable")
    response = client.post(
        "/api/copilot/agent", headers=headers, json=_agent(sketch_id)
    )
    assert response.status_code == 503
    assert db_session.query(AgentRun).count() == 0


def test_agent_latest_run_and_cancel_only_while_running(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    latest = f"/api/copilot/agent?sketch_id={sketch_id}"
    assert client.get(latest, headers=headers).json() is None
    older, run_id = (
        client.post(
            "/api/copilot/agent", headers=headers, json=_agent(sketch_id)
        ).json()["id"]
        for _ in range(2)
    )
    db_session.get(AgentRun, UUID(older)).created_at = datetime(2020, 1, 1)
    db_session.commit()
    assert client.get(latest, headers=headers).json()["id"] == run_id
    cancelled = client.post(f"/api/copilot/agent/{run_id}/cancel", headers=headers)
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["finished_at"]

    run = db_session.get(AgentRun, UUID(run_id))
    run.status = "publishing"
    db_session.commit()
    response = client.post(f"/api/copilot/agent/{run_id}/cancel", headers=headers)
    assert response.json()["status"] == "publishing"
    response = client.get(f"/api/copilot/agent/{run_id}", headers=headers)
    assert response.json()["status"] == "publishing"


def test_agent_run_of_another_sketch_is_hidden(client, db_session, backend):
    owner_headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    other_headers, _ = _seed_user(db_session, (Role.OWNER,))
    run_id = client.post(
        "/api/copilot/agent", headers=owner_headers, json=_agent(sketch_id)
    ).json()["id"]
    for response in (
        client.get(f"/api/copilot/agent/{run_id}", headers=other_headers),
        client.post(f"/api/copilot/agent/{run_id}/cancel", headers=other_headers),
    ):
        assert response.status_code in {403, 404}
    assert db_session.get(AgentRun, UUID(run_id)).status == "running"


@pytest.mark.parametrize(
    "status,started_ago,expected",
    [
        ("running", 3601, "failed"),
        ("publishing", 3601, "failed"),
        ("running", 3500, "running"),
        ("running", None, "running"),
    ],
)
def test_agent_run_lost_past_worker_time_limit_reads_as_failed(
    client, db_session, backend, status, started_ago, expected
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    run_id = client.post(
        "/api/copilot/agent", headers=headers, json=_agent(sketch_id)
    ).json()["id"]
    run = db_session.get(AgentRun, UUID(run_id))
    run.status = status
    run.created_at = datetime(2020, 1, 1)
    if started_ago is not None:
        run.started_at = datetime.now(timezone.utc) - timedelta(seconds=started_ago)
    db_session.commit()

    latest = client.get(f"/api/copilot/agent?sketch_id={sketch_id}", headers=headers)
    by_id = client.get(f"/api/copilot/agent/{run_id}", headers=headers)
    for body in (latest.json(), by_id.json()):
        assert body["status"] == expected
        assert bool(body["error"]) == (expected == "failed")
        assert bool(body["finished_at"]) == (expected == "failed")


def test_candidate_review_is_read_only_and_sketch_scoped(client, db_session, backend):
    headers, sketch_id = _seed_user(db_session, (Role.VIEWER,))
    backend[0].query.return_value = [
        {
            "source_id": "ip-1",
            "source_label": "192.0.2.1",
            "node_id": "peer",
            "label": "192.0.2.2",
            "candidate_type": "ip",
            "evidence_type": "phrase",
            "evidence_id": "imported",
            "evidence_label": "Modat fingerprint",
            "relationships": ["HAS_MODAT_PIVOT", "MATCHES_MODAT_PIVOT"],
            "observations": [],
        }
    ]
    response = client.post(
        "/api/copilot/candidates", headers=headers, json=_request(sketch_id, ["ip-1"])
    )
    assert response.status_code == 200
    assert response.json()["candidates"][0]["node_id"] == "peer"
    assert backend[0].query.call_args.args[1] == {
        "sketch_id": sketch_id,
        "node_ids": ["ip-1"],
    }
    assert (
        "candidate.sketch_id = $sketch_id" in backend[0].query.call_args_list[0].args[0]
    )
    assert "port.sketch_id = $sketch_id" in backend[0].query.call_args.args[0]
    backend[2].assert_not_called()


@pytest.mark.parametrize("ids", [["domain-1"], ["unknown"], ["ip-1", "domain-1"]])
def test_candidate_review_rejects_invalid_selection(client, db_session, backend, ids):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    response = client.post(
        "/api/copilot/candidates", headers=headers, json=_request(sketch_id, ids)
    )
    assert response.status_code in {404, 422}
    backend[0].query.assert_not_called()
    backend[2].assert_not_called()


def test_candidate_review_exposes_service_hashes_without_external_queries(
    client, db_session, backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.VIEWER,))
    backend[0].query.side_effect = [
        [],
        [
            {
                "source_id": "ip-1",
                "source_label": "192.0.2.1",
                "service_id": "service-22",
                "data": {
                    "nodeProperties.number": 22,
                    "nodeProperties.service": "ssh",
                    "nodeProperties.fingerprints.ssh.hassh": "ab" * 16,
                },
            }
        ],
    ]
    chat = route.create_chat_service
    response = client.post(
        "/api/copilot/candidates", headers=headers, json=_request(sketch_id, ["ip-1"])
    )
    assert response.status_code == 200
    assert response.json()["candidates"] == []
    assert response.json()["services"][0]["fingerprints"] == {"ssh.hassh": "ab" * 16}
    chat.assert_not_called()
    backend[2].assert_not_called()


@pytest.fixture
def service_backend(backend):
    from flowsint_types.port import Port

    backend[3].append(
        GraphNode(
            id="service-22",
            nodeLabel="22 ssh",
            nodeType="port",
            version=3,
            nodeProperties=Port(
                host="192.0.2.1",
                number=22,
                protocol="TCP",
                service="ssh",
                provider="Modat",
                fingerprints={"ssh.hassh": "ab" * 16},
            ),
            nodeMetadata=NodeMetadata(),
        )
    )
    backend[0].query.return_value = [
        {
            "source_id": "ip-1",
            "source_label": "192.0.2.1",
            "source_address": "192.0.2.1",
            "service_id": "service-22",
            "data": {
                "version": 3,
                "nodeProperties.host": "192.0.2.1",
                "nodeProperties.number": 22,
                "nodeProperties.protocol": "TCP",
                "nodeProperties.service": "ssh",
                "nodeProperties.provider": "Modat",
                "nodeProperties.fingerprints.ssh.hassh": "ab" * 16,
            },
        }
    ]
    return backend


def _service_request(sketch_id):
    return {
        "sketch_id": sketch_id,
        "service_id": "service-22",
        "service_version": 3,
        "fingerprint": "ssh.hassh",
    }


def test_viewer_reads_service_context_without_provider_calls(
    client, db_session, service_backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.VIEWER,))
    lookup = MagicMock()
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    response = client.post(
        "/api/copilot/service-context",
        headers=headers,
        json={"sketch_id": sketch_id, "service_id": "service-22"},
    )
    assert response.status_code == 200
    assert response.json()["modat_queries"]["ssh.hassh"].startswith(
        'port=22 protocol="ssh" transport="tcp"'
    )
    assert response.json()["host"] == "192.0.2.1"
    assert response.json()["service_version"] == 3
    lookup.assert_not_called()
    service_backend[2].assert_not_called()
    service_backend[1].reset_mock()
    assert (
        client.post(
            "/api/copilot/fingerprint",
            headers=headers,
            json=_service_request(sketch_id),
        ).status_code
        == 403
    )
    service_backend[1].assert_not_called()
    lookup.assert_not_called()


def test_fingerprint_lookup_uses_only_current_owned_graph_evidence(
    client, db_session, service_backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    vault = MagicMock()
    vault.return_value.get_secret.return_value = "private-key"
    monkeypatch.setattr(route, "Vault", vault)
    lookup = MagicMock(return_value={"matches": []})
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    response = client.post(
        "/api/copilot/fingerprint", headers=headers, json=_service_request(sketch_id)
    )
    assert response.status_code == 200
    assert lookup.call_args.args[0]["host"] == "192.0.2.1"
    assert lookup.call_args.args[0]["fingerprints"] == {"ssh.hassh": "ab" * 16}
    assert lookup.call_args.args[1:] == ("ssh.hassh", "private-key")
    service_backend[2].assert_not_called()


@pytest.mark.parametrize(
    "override,code",
    [
        ({"service_version": 2}, 409),
        ({"fingerprint": "anything"}, 422),
        ({"service_id": "missing"}, 404),
        ({"service_id": "ip-1"}, 422),
        ({"query": "attacker query"}, 422),
        ({"hash": "different"}, 422),
    ],
)
def test_bad_stale_or_custom_lookup_is_rejected_before_provider(
    client, db_session, service_backend, monkeypatch, override, code
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    lookup = MagicMock()
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    assert (
        client.post(
            "/api/copilot/fingerprint",
            headers=headers,
            json={**_service_request(sketch_id), **override},
        ).status_code
        == code
    )
    lookup.assert_not_called()
    service_backend[2].assert_not_called()


@pytest.mark.parametrize(
    "owner_rows",
    [
        [],
        [
            {
                "source_id": "ip-1",
                "source_address": "192.0.2.2",
                "data": {"nodeProperties.host": "192.0.2.1"},
            }
        ],
        [None, None],
    ],
)
def test_missing_or_ambiguous_port_owner_rejected(
    client, db_session, service_backend, monkeypatch, owner_rows
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    service_backend[0].query.return_value = owner_rows
    lookup = MagicMock()
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    assert (
        client.post(
            "/api/copilot/fingerprint",
            headers=headers,
            json=_service_request(sketch_id),
        ).status_code
        == 422
    )
    lookup.assert_not_called()


def test_missing_modat_key_rejected_without_query(
    client, db_session, service_backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    vault = MagicMock()
    vault.return_value.get_secret.return_value = None
    monkeypatch.setattr(route, "Vault", vault)
    lookup = MagicMock()
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    assert (
        client.post(
            "/api/copilot/fingerprint",
            headers=headers,
            json=_service_request(sketch_id),
        ).status_code
        == 422
    )
    lookup.assert_not_called()


@pytest.mark.parametrize(
    "status,expected", [(401, 502), (403, 502), (429, 503), (500, 502)]
)
def test_modat_failure_is_actionable_and_redacted(
    client, db_session, service_backend, monkeypatch, status, expected
):
    import requests

    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    vault = MagicMock()
    vault.return_value.get_secret.return_value = "private-key"
    monkeypatch.setattr(route, "Vault", vault)
    response = requests.Response()
    response.status_code = status
    response._content = b"private-key provider details"
    lookup = MagicMock(side_effect=requests.HTTPError("private-key", response=response))
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    result = client.post(
        "/api/copilot/fingerprint", headers=headers, json=_service_request(sketch_id)
    )
    assert result.status_code == expected
    assert "private-key" not in result.text


def test_lookup_checks_version_of_query_snapshot_even_if_initial_node_read_is_older(
    client, db_session, service_backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    service_backend[0].query.return_value[0]["data"]["version"] = 4
    lookup = MagicMock()
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    result = client.post(
        "/api/copilot/fingerprint", headers=headers, json=_service_request(sketch_id)
    )
    assert result.status_code == 409
    lookup.assert_not_called()


def _fingerprint_finding(db_session, sketch_id):
    from flowsint_core.core.models import CaseItem, Sketch

    sketch = db_session.get(Sketch, UUID(sketch_id))
    evidence = {
        "query": 'port=22 protocol="ssh" transport="tcp" ssh.hassh="' + "ab" * 16 + '"',
        "source": {
            "source_id": "ip-1",
            "service_id": "service-22",
            "host": "192.0.2.1",
            "port": 22,
            "transport": "TCP",
            "service": "ssh",
            "fingerprints": {"ssh.hassh": "ab" * 16},
        },
        "candidate": {
            "ip": "192.0.2.2",
            "port": 22,
            "transport": "tcp",
            "protocol": "ssh",
            "banner": "SSH-test",
            "observed_at": "2026-10-01",
            "fingerprints": {"ssh.hassh": "ab" * 16},
            "matching_fingerprints": ["ssh.hassh"],
        },
        "matching_fingerprints": ["ssh.hassh"],
        "retrieved_at": "2026-10-02",
    }
    item = CaseItem(
        investigation_id=sketch.investigation_id,
        sketch_id=sketch.id,
        author_id=sketch.owner_id,
        kind="finding",
        target_kind="entity",
        target_id="service-22",
        body="Unverified fingerprint candidate",
        evidence=json.dumps(evidence),
    )
    db_session.add(item)
    db_session.commit()
    return item, evidence


def test_import_saved_fingerprint_adds_host_specific_service_and_evidence(
    client, db_session, service_backend, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    finding, evidence = _fingerprint_finding(db_session, sketch_id)
    graph = service_backend[0]
    context = graph.query.return_value
    imported = {
        "ip_id": "candidate-ip",
        "service_id": "candidate-ssh",
        "source_service_id": "service-22",
    }
    graph.query.side_effect = [context, [imported], context, [imported]]
    lookup = MagicMock()
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    for _ in range(2):
        response = client.post(
            "/api/copilot/fingerprint/import",
            headers=headers,
            json={
                "sketch_id": sketch_id,
                "finding_id": str(finding.id),
                "finding_version": finding.version,
            },
        )
        assert response.status_code == 200, response.text
        assert response.json() == imported
    query, params = graph.query.call_args.args
    assert "ON CREATE SET service += $port_props" in query
    assert "SHARES_FINGERPRINT" in query and "HAS_PORT" in query
    assert "MERGE (source_ip)-[match:SHARES_FINGERPRINT" in query
    assert "SET legacy.deleted_at = $migrated_at" in query
    assert "observation IN coalesce(legacy.observations, [])" in query
    assert params["source_ip_id"] == "ip-1"
    assert params["caption"] == "Shared SSH HASSH · port 22"
    assert params["port_props"]["nodeProperties.host"] == "192.0.2.2"
    assert params["port_props"]["nodeProperties.fingerprints.ssh.hassh"] == "ab" * 16
    assert params["source_id"] == "service-22" and params["source_version"] == 3
    observation = json.loads(params["observation"])
    assert observation["evidence"] == evidence
    assert observation["finding_id"] == str(finding.id)
    db_session.refresh(finding)
    assert finding.decision == "pending"
    lookup.assert_not_called()
    service_backend[2].assert_not_called()


@pytest.mark.parametrize(
    "change,code",
    [
        ("stale", 409),
        ("rejected", 409),
        ("scope", 404),
        ("hash", 422),
        ("port", 422),
        ("source", 422),
        ("malformed", 422),
        ("viewer", 403),
        ("graph_changed", 409),
    ],
)
def test_import_rejects_stale_unscoped_or_invalid_finding(
    client, db_session, service_backend, monkeypatch, change, code
):
    headers, sketch_id = _seed_user(
        db_session, (Role.VIEWER,) if change == "viewer" else (Role.OWNER,)
    )
    finding, evidence = _fingerprint_finding(db_session, sketch_id)
    if change == "rejected":
        finding.decision = "rejected"
    if change == "scope":
        finding.sketch_id = None
    if change == "hash":
        evidence["candidate"]["fingerprints"]["ssh.hassh"] = "ff" * 16
    if change == "port":
        evidence["candidate"]["port"] = 443
    if change == "source":
        evidence["source"]["host"] = "192.0.2.99"
    finding.evidence = "bad JSON" if change == "malformed" else json.dumps(evidence)
    db_session.commit()
    if change == "graph_changed":
        graph = service_backend[0]
        graph.query.side_effect = [graph.query.return_value, []]
    lookup = MagicMock()
    monkeypatch.setattr(route, "lookup_recorded_fingerprint", lookup)
    response = client.post(
        "/api/copilot/fingerprint/import",
        headers=headers,
        json={
            "sketch_id": sketch_id,
            "finding_id": str(finding.id),
            "finding_version": finding.version + (1 if change == "stale" else 0),
        },
    )
    assert response.status_code == code, response.text
    lookup.assert_not_called()
    service_backend[2].assert_not_called()
    assert (
        not any(
            "MERGE" in call.args[0] for call in service_backend[0].query.call_args_list
        )
        if change != "graph_changed"
        else True
    )
