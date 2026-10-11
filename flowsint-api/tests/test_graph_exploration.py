from unittest.mock import MagicMock

from flowsint_core.core.graph import GraphData
from flowsint_core.core.types import Role
from tests.test_enrichers import _seed_user


def test_graph_slice_validates_limits_and_preserves_permission_checks(
    client, db_session, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.VIEWER,))
    graph = MagicMock()
    graph.get_graph_slice.return_value = GraphData(
        nodes=[], edges=[], total_nodes=5000, total_edges=8000, truncated=True
    )
    monkeypatch.setattr(
        "flowsint_core.core.services.sketch_service.create_graph_service",
        MagicMock(return_value=graph),
    )
    response = client.get(
        f"/api/sketches/{sketch_id}/graph?limit=100&search=example", headers=headers
    )
    assert response.status_code == 200
    assert response.json()["truncated"] is True
    assert response.json()["total_nodes"] == 5000
    graph.get_graph_slice.assert_called_once_with(None, "example", 100, 0)
    assert (
        client.get(
            f"/api/sketches/{sketch_id}/graph?limit=2001", headers=headers
        ).status_code
        == 422
    )
    assert client.get(f"/api/sketches/{sketch_id}/graph?limit=100").status_code == 401


def test_telemetry_preview_is_read_only_and_execution_requires_editor(
    client, db_session, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.VIEWER,))
    graph = MagicMock()
    factory = MagicMock(return_value=graph)
    monkeypatch.setattr(
        "flowsint_core.core.services.sketch_service.create_graph_service", factory
    )
    body = {
        "format": "normalized",
        "content": '{"source":"192.0.2.1","target":"example.org","timestamp":"2026-10-01T12:00:00Z"}',
    }
    response = client.post(
        f"/api/sketches/{sketch_id}/import/telemetry", headers=headers, json=body
    )
    assert response.status_code == 200
    assert response.json()["observation_count"] == 1
    factory.assert_not_called()
    response = client.post(
        f"/api/sketches/{sketch_id}/import/telemetry",
        headers=headers,
        json={**body, "execute": True},
    )
    assert response.status_code == 403
    factory.assert_not_called()


def test_telemetry_import_validates_entire_batch_then_flushes_once(
    client, db_session, monkeypatch
):
    headers, sketch_id = _seed_user(db_session, (Role.EDITOR,))
    graph = MagicMock()
    factory = MagicMock(return_value=graph)
    monkeypatch.setattr(
        "flowsint_core.core.services.sketch_service.create_graph_service", factory
    )
    body = {
        "format": "normalized",
        "execute": True,
        "content": '{"source":"192.0.2.1","target":"example.org","timestamp":"2026-10-01T12:00:00Z"}',
    }
    response = client.post(
        f"/api/sketches/{sketch_id}/import/telemetry",
        headers=headers,
        json={**body, "content": body["content"] + "\n{}"},
    )
    assert response.status_code == 422
    factory.assert_not_called()
    response = client.post(
        f"/api/sketches/{sketch_id}/import/telemetry", headers=headers, json=body
    )
    assert response.status_code == 200
    graph.set_batch_size.assert_called_once_with(4)
    assert graph.create_node_from_flowsint_type.call_count == 2
    graph.flush.assert_called_once()
    observation = graph.create_relationship.call_args.args[3]
    assert observation["provider"] == "Internal telemetry"
    assert observation["observed_at"].startswith("2026-10-01")
