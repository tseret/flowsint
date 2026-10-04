from flowsint_core.core.types import Role
from tests.test_enrichers import _seed_user


def test_sketch_read_serializes_persisted_metadata(client, db_session):
    headers, sketch_id = _seed_user(db_session, (Role.OWNER,))
    response = client.get(f"/api/sketches/{sketch_id}", headers=headers)
    assert response.status_code == 200
    metadata = response.json()
    assert metadata["id"] == sketch_id
    assert metadata["title"] == "Board"
    assert metadata["description"] is None
    assert metadata["investigation_id"]
    assert metadata["created_at"]


def test_sketch_read_retains_access_checks(client, db_session):
    _, other_sketch_id = _seed_user(db_session, (Role.OWNER,))
    headers, _ = _seed_user(db_session, (Role.OWNER,))
    response = client.get(f"/api/sketches/{other_sketch_id}", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
