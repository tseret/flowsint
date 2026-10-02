"""Public connection endpoints never return credentials or cross user ownership."""

from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from flowsint_core.core.auth import create_access_token
from flowsint_core.core.models import Profile
from flowsint_core.core.services.chatgpt_subscription_service import (
    SESSION_KEY,
    ChatGPTSubscriptionService,
)


def _user(db_session, email="subscriber@example.org"):
    user = Profile(id=uuid4(), email=email, hashed_password="x", is_active=True)
    db_session.add(user)
    db_session.commit()
    return user, {"Authorization": "Bearer " + create_access_token({"sub": email})}


def test_connection_endpoints_require_auth(client):
    for method, path in [
        ("get", "status"),
        ("get", "models"),
        ("post", "connect"),
        ("delete", "connection"),
    ]:
        assert (
            getattr(client, method)("/api/chatgpt-subscription/" + path).status_code
            == 401
        )
    assert (
        client.put(
            "/api/chatgpt-subscription/settings", json={"mode": "api"}
        ).status_code
        == 401
    )


def test_default_status_uses_subscription_without_exposing_credentials(
    client, db_session
):
    _, headers = _user(db_session)
    response = client.get("/api/chatgpt-subscription/status", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "mode": "subscription",
        "connected": False,
        "account_label": None,
        "model": "gpt-6.1-sol",
        "reasoning_effort": "medium",
        "error": None,
        "accounts": [],
        "active_account_id": None,
    }


def test_connect_returns_only_authorization_url_with_loopback_callback(
    client, db_session
):
    _, headers = _user(db_session)
    response = client.post(
        "/api/chatgpt-subscription/connect", json={}, headers=headers
    )
    assert response.status_code == 200
    assert list(response.json()) == ["authorization_url"]
    query = parse_qs(urlparse(response.json()["authorization_url"]).query)
    assert query["client_id"] == ["dynamic_agent_client"]
    assert query["redirect_uri"] == [
        "http://127.0.0.1:5173/api/chatgpt-subscription/callback"
    ]
    assert "code_verifier" not in query
    assert "access_token" not in query


def test_denied_callback_is_one_use_and_redirects_without_sensitive_query(
    client, db_session
):
    _, headers = _user(db_session)
    response = client.post("/api/chatgpt-subscription/connect", headers=headers)
    state = parse_qs(urlparse(response.json()["authorization_url"]).query)["state"][0]
    response = client.get(
        "/api/chatgpt-subscription/callback",
        params={"state": state, "error": "access_denied"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "http://localhost:5173/dashboard/profile"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    status = client.get("/api/chatgpt-subscription/status", headers=headers).json()
    assert not status["connected"]
    assert "permission was denied" in status["error"]
    response = client.get(
        "/api/chatgpt-subscription/callback",
        params={"state": state, "code": "secret-code"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "secret-code" not in response.text
    assert "secret-code" not in response.headers["location"]


def test_explicit_api_mode_is_persisted_for_just_that_user(client, db_session):
    _, headers = _user(db_session)
    _, other_headers = _user(db_session, "other@example.org")
    response = client.put(
        "/api/chatgpt-subscription/settings", json={"mode": "api"}, headers=headers
    )
    assert response.status_code == 200 and response.json()["mode"] == "api"
    assert (
        client.get("/api/chatgpt-subscription/status", headers=other_headers).json()[
            "mode"
        ]
        == "subscription"
    )
    assert (
        client.put(
            "/api/chatgpt-subscription/settings",
            json={"mode": "subscription", "reasoning_effort": "high"},
            headers=headers,
        ).status_code
        == 422
    )


def test_missing_connection_has_actionable_model_error(client, db_session):
    _, headers = _user(db_session)
    response = client.get("/api/chatgpt-subscription/models", headers=headers)
    assert response.status_code == 502
    assert "Connect your ChatGPT subscription" in response.json()["detail"]


def test_saved_account_connect_cannot_select_other_user(client, db_session):
    owner, headers = _user(db_session)
    _, other_headers = _user(db_session, "other@example.org")
    svc = ChatGPTSubscriptionService(db_session)
    config = svc._config(owner.id)
    config["accounts"] = {
        "oaiapp_saved": {
            "client_id": "oaiapp_saved",
            "label": "saved account",
            "subject": "subject",
        }
    }
    config["active_account_id"] = "oaiapp_saved"
    svc._write(owner.id, SESSION_KEY, config)
    db_session.commit()
    assert (
        client.post(
            "/api/chatgpt-subscription/connect",
            json={"account_id": "oaiapp_saved"},
            headers=other_headers,
        ).status_code
        == 400
    )
    response = client.post(
        "/api/chatgpt-subscription/connect",
        json={"account_id": "oaiapp_saved"},
        headers=headers,
    )
    assert parse_qs(urlparse(response.json()["authorization_url"]).query)[
        "client_id"
    ] == ["oaiapp_saved"]


def test_disconnect_does_not_enable_paid_api(client, db_session):
    _, headers = _user(db_session)
    response = client.delete("/api/chatgpt-subscription/connection", headers=headers)
    assert response.status_code == 200
    assert response.json()["mode"] == "subscription"
    assert not response.json()["connected"]
