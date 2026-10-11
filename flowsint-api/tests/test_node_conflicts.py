from unittest.mock import MagicMock

from app.api.routes import sketches as sketches_route
from flowsint_core.core.services import ConflictError
from flowsint_core.core.types import Role
from tests.test_enrichers import _seed_user


def test_node_edits_require_a_version(client, db_session):
    headers, sketch_id = _seed_user(db_session, [Role.OWNER])
    response = client.put(
        f"/api/sketches/{sketch_id}/nodes/edit",
        headers=headers,
        json={"nodeId": "entity", "updates": {"nodeLabel": "new"}},
    )
    assert response.status_code == 422


def test_stale_node_edit_returns_conflict(client, db_session, monkeypatch):
    headers, sketch_id = _seed_user(db_session, [Role.OWNER])
    service = MagicMock()
    service.update_node.side_effect = ConflictError(
        "This entity changed. Reload before saving."
    )
    monkeypatch.setattr(sketches_route, "create_sketch_service", lambda db: service)
    response = client.put(
        f"/api/sketches/{sketch_id}/nodes/edit",
        headers=headers,
        json={
            "nodeId": "entity",
            "updates": {"nodeLabel": "new"},
            "expected_version": 2,
        },
    )
    assert response.status_code == 409
    assert "Reload" in response.json()["detail"]
    assert service.update_node.call_args.args[-1] == 2
