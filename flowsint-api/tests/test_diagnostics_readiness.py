import uuid
from unittest.mock import MagicMock

from app.api.routes import diagnostics as diagnostics_route
from flowsint_core.core.auth import create_access_token
from flowsint_core.core.models import Investigation, Key, Profile, Scan, Sketch


def seed(db):
    user = Profile(
        id=uuid.uuid4(), email=f"{uuid.uuid4()}@example.com", hashed_password="x"
    )
    investigation = Investigation(id=uuid.uuid4(), name="Case", owner_id=user.id)
    sketch = Sketch(
        id=uuid.uuid4(),
        title="Graph",
        owner_id=user.id,
        investigation_id=investigation.id,
    )
    db.add_all([user, investigation, sketch])
    db.commit()
    return (
        user,
        sketch,
        {"Authorization": f"Bearer {create_access_token({'sub': user.email})}"},
    )


def test_diagnostics_requires_authentication(client):
    assert client.get("/api/diagnostics").status_code == 401
    assert client.get("/api/enrichers/readiness").status_code == 401


def test_readiness_does_not_use_another_users_keys_or_runs(client, db_session):
    user, _, headers = seed(db_session)
    other, sketch, _ = seed(db_session)
    db_session.add(
        Key(
            name="VT_API_KEY",
            owner_id=other.id,
            ciphertext=b"private",
            iv=b"x",
            salt=b"x",
            key_version="V1",
        )
    )
    db_session.add(
        Scan(
            sketch_id=sketch.id,
            summary={"enricher": "domain_to_ips_virustotal", "outcome": "results"},
        )
    )
    db_session.commit()
    response = client.get("/api/enrichers/readiness", headers=headers)
    assert response.status_code == 200
    entry = response.json()["domain_to_ips_virustotal"]
    assert entry["missing_required_keys"] == ["VT_API_KEY"]
    assert entry["credentials_configured"] is False
    assert entry["last_run"] is None
    assert "private" not in response.text
    assert str(user.id) not in response.text


def test_readiness_reports_own_key_presence_and_accessible_success(client, db_session):
    user, sketch, headers = seed(db_session)
    db_session.add(
        Key(
            name="VT_API_KEY",
            owner_id=user.id,
            ciphertext=b"private",
            iv=b"x",
            salt=b"x",
            key_version="V1",
        )
    )
    db_session.add(
        Scan(
            sketch_id=sketch.id,
            summary={
                "enricher": "domain_to_ips_virustotal",
                "outcome": "results",
                "output_count": 3,
            },
        )
    )
    db_session.commit()
    response = client.get("/api/enrichers/readiness", headers=headers)
    assert response.status_code == 200
    entry = response.json()["domain_to_ips_virustotal"]
    assert entry["credentials_configured"] is True
    assert entry["last_run"]["output_count"] == 3
    assert entry["last_success_at"] is not None
    assert "private" not in response.text


def test_diagnostics_reports_skew_and_hides_provider_errors(
    client, db_session, monkeypatch
):
    _, _, headers = seed(db_session)
    cache = MagicMock()
    cache.ping.side_effect = RuntimeError("redis://secret@host")
    monkeypatch.setattr(
        diagnostics_route.redis.Redis, "from_url", lambda *args, **kwargs: cache
    )
    monkeypatch.setattr(diagnostics_route, "neo4j_connection", None)
    task = MagicMock()
    task.get.return_value = {"revision": "different", "connectors": []}
    monkeypatch.setattr(diagnostics_route.celery, "send_task", lambda *args: task)
    response = client.get("/api/diagnostics", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["migrations_current"] is False
    assert data["redis"] == "unavailable"
    assert data["neo4j"] == "unavailable"
    assert data["worker_matches_api"] is False
    assert data["expected_migrations"]
    assert "secret" not in response.text
    cache.close.assert_called_once()
