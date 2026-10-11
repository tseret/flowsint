"""OAuth sessions are per-user, one-use, verified, and never fall back to API spend."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from sqlalchemy import select

from flowsint_core.core.llm.protocol import SubscriptionError
from flowsint_core.core.models import Key, Profile
from flowsint_core.core.services.chatgpt_subscription_service import (
    CALLBACK_URI,
    DEFAULT_MODEL,
    ISSUER,
    RESOURCE,
    SCOPES,
    SESSION_KEY,
    TOKEN_URL,
    ChatGPTSubscriptionService,
    _state_name,
)


@pytest.fixture
def service(db_session):
    user = Profile(id=uuid4(), email="subscriber@example.org", hashed_password="x")
    db_session.add(user)
    db_session.commit()
    return ChatGPTSubscriptionService(db_session), user.id


@pytest.fixture(scope="module")
def signing_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()

    def encoded(value):
        return (
            base64.urlsafe_b64encode(
                value.to_bytes((value.bit_length() + 7) // 8, "big")
            )
            .rstrip(b"=")
            .decode()
        )

    return private, {
        "kty": "RSA",
        "kid": "test-signing-key",
        "use": "sig",
        "alg": "RS256",
        "n": encoded(numbers.n),
        "e": encoded(numbers.e),
    }


def _begin(service, user):
    query = parse_qs(urlparse(service.connect(user)["authorization_url"]).query)
    state = query["state"][0]
    pending = service._read(service._row(user, _state_name(state)))
    return state, pending, query


def _identity(signing_key, pending, client="oaiapp_test", **changes):
    claims = {
        "iss": ISSUER,
        "aud": client,
        "exp": int(time.time()) + 3600,
        "sub": "subject-1",
        "nonce": pending["nonce"],
        "email": "subscriber@example.org",
    }
    claims.update(changes)
    return jwt.encode(
        claims, signing_key[0], algorithm="RS256", headers={"kid": "test-signing-key"}
    )


def _mock_identity(httpx_mock, signing_key):
    httpx_mock.add_response(
        url=ISSUER + "/.well-known/openid-configuration",
        json={
            "issuer": ISSUER,
            "jwks_uri": ISSUER + "/jwks",
            "revocation_endpoint": ISSUER + "/revoke",
        },
    )
    httpx_mock.add_response(url=ISSUER + "/jwks", json={"keys": [signing_key[1]]})


def _mock_exchange(httpx_mock, signing_key, pending, **changes):
    response = {
        "access_token": "test-access",
        "refresh_token": "test-refresh",
        "id_token": _identity(signing_key, pending),
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": SCOPES,
        "earliest_refresh_at": 0,
    }
    response.update(changes)
    httpx_mock.add_response(url=TOKEN_URL, method="POST", json=response)
    _mock_identity(httpx_mock, signing_key)


def _connect(service, user, httpx_mock, signing_key):
    state, pending, _ = _begin(service, user)
    _mock_exchange(httpx_mock, signing_key, pending)
    service.callback(state, "test-code", "oaiapp_test", None)


def _models(httpx_mock, slugs=(DEFAULT_MODEL,)):
    httpx_mock.add_response(
        url=RESOURCE + "/models",
        json={
            "models": [
                {"slug": slug, "display_name": slug, "visibility": "list"}
                for slug in slugs
            ]
            + [{"slug": "hidden", "visibility": "hidden"}]
        },
    )


def test_connect_has_fresh_pkce_and_stable_host(service):
    svc, user = service
    state, pending, first = _begin(svc, user)
    second = parse_qs(urlparse(svc.connect(user)["authorization_url"]).query)
    assert first["ext_agent_host_id"] == second["ext_agent_host_id"]
    assert first["state"] != second["state"]
    assert first["nonce"] != second["nonce"]
    assert first["redirect_uri"] == [CALLBACK_URI]
    assert first["client_id"] == ["dynamic_agent_client"]
    assert first["agent_name_hint"] == ["Flowsint"]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(pending["verifier"].encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert first["code_challenge"] == [challenge]
    assert svc._row(user, _state_name(state)) is None


def test_verified_callback_encrypts_credentials_and_uses_issued_client(
    service, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    status = svc.status(user)
    assert status["connected"] and status["mode"] == "subscription"
    assert status["accounts"][0]["id"] == "oaiapp_test"
    assert "test-access" not in json.dumps(status)
    assert "test-refresh" not in json.dumps(status)
    assert b"test-access" not in svc._row(user, SESSION_KEY).ciphertext
    request = next(
        item for item in httpx_mock.get_requests() if str(item.url) == TOKEN_URL
    )
    data = parse_qs(request.content.decode())
    assert data["client_id"] == ["oaiapp_test"]
    assert data["redirect_uri"] == [CALLBACK_URI]
    assert data["resource"] == [RESOURCE]
    assert "client_secret" not in data
    _models(httpx_mock)
    assert svc.get_provider_data(user) == {
        "access_token": "test-access",
        "model": DEFAULT_MODEL,
        "reasoning_effort": "medium",
    }
    with pytest.raises(SubscriptionError, match="already used"):
        svc.callback(
            parse_qs(urlparse(svc.connect(user)["authorization_url"]).query)["state"][0]
            + "invalid",
            "code",
            "oaiapp_test",
            None,
        )


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "wrong"},
        {"aud": "different-client"},
        {"iss": "https://other.example"},
        {"exp": 1},
    ],
)
def test_callback_rejects_unverified_identity(service, httpx_mock, signing_key, change):
    svc, user = service
    state, pending, _ = _begin(svc, user)
    _mock_exchange(
        httpx_mock,
        signing_key,
        pending,
        id_token=_identity(signing_key, pending, **change),
    )
    with pytest.raises(SubscriptionError, match="identity"):
        svc.callback(state, "test-code", "oaiapp_test", None)
    assert not svc.status(user)["connected"]
    assert svc.status(user)["error"]
    with pytest.raises(SubscriptionError, match="already used"):
        svc.callback(state, "test-code", "oaiapp_test", None)


def test_callback_rejects_signature_from_unknown_key(service, httpx_mock, signing_key):
    svc, user = service
    state, pending, _ = _begin(svc, user)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "oaiapp_test",
            "exp": int(time.time()) + 600,
            "sub": "s",
            "nonce": pending["nonce"],
        },
        other,
        algorithm="RS256",
        headers={"kid": "test-signing-key"},
    )
    _mock_exchange(httpx_mock, signing_key, pending, id_token=token)
    with pytest.raises(SubscriptionError, match="identity"):
        svc.callback(state, "code", "oaiapp_test", None)


def test_callback_granted_scopes_not_callback_scope_enable_usage(
    service, httpx_mock, signing_key
):
    svc, user = service
    state, pending, _ = _begin(svc, user)
    _mock_exchange(httpx_mock, signing_key, pending, scope="openid profile email")
    with pytest.raises(SubscriptionError, match="not authorized"):
        svc.callback(state, "code", "oaiapp_test", None)
    assert not svc.status(user)["connected"]


@pytest.mark.parametrize("expired,error", [(True, None), (False, "access_denied")])
def test_expired_or_denied_callback_is_consumed_without_exchange(
    service, expired, error
):
    svc, user = service
    state, pending, _ = _begin(svc, user)
    if expired:
        pending["expires_at"] = 1
        svc._write(user, _state_name(state), pending)
        svc.db.commit()
    with pytest.raises(SubscriptionError):
        svc.callback(state, "code", "oaiapp_test", error)
    assert svc._row(user, _state_name(state)) is None


def test_returning_registration_preserves_identity_and_client(
    service, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    state, pending, query = _begin(svc, user)
    assert query["client_id"] == ["oaiapp_test"]
    assert "agent_name_hint" not in query
    assert "id_token_hint" not in query  # No bearer-like token in browser URLs.
    with pytest.raises(SubscriptionError, match="registration"):
        svc.callback(state, "code", "oaiapp_other", None)
    assert svc.status(user)["connected"]
    state, pending, _ = _begin(svc, user)
    _mock_exchange(
        httpx_mock,
        signing_key,
        pending,
        id_token=_identity(signing_key, pending, sub="other-person"),
    )
    with pytest.raises(SubscriptionError, match="identity"):
        svc.callback(state, "code", None, None)
    assert svc.status(user)["connected"]


def test_refresh_rotates_tokens_together_and_keeps_model(
    service, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    config = svc._config(user)
    config["accounts"]["oaiapp_test"]["expires_at"] = 1
    svc._write(user, SESSION_KEY, config)
    svc.db.commit()
    httpx_mock.add_response(
        url=TOKEN_URL,
        method="POST",
        json={
            "access_token": "replacement-access",
            "refresh_token": "replacement-refresh",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": SCOPES,
        },
    )
    _models(httpx_mock)
    assert svc.get_provider_data(user)["access_token"] == "replacement-access"
    assert (
        svc._config(user)["accounts"]["oaiapp_test"]["refresh_token"]
        == "replacement-refresh"
    )
    refresh = [
        item for item in httpx_mock.get_requests() if str(item.url) == TOKEN_URL
    ][-1]
    data = parse_qs(refresh.content.decode())
    assert data["grant_type"] == ["refresh_token"]
    assert data["client_id"] == ["oaiapp_test"]
    assert "scope" not in data


def test_missing_model_does_not_escalate_and_catalog_allows_selection(
    service, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    _models(httpx_mock, ("another-model",))
    with pytest.raises(SubscriptionError, match="unavailable"):
        svc.get_provider_data(user)
    assert svc.status(user)["model"] == DEFAULT_MODEL
    _models(httpx_mock, ("another-model",))
    assert svc.models(user) == {
        "models": [{"slug": "another-model", "display_name": "another-model"}]
    }
    _models(httpx_mock, ("another-model",))
    assert (
        svc.settings(user, "subscription", model="another-model")["model"]
        == "another-model"
    )


def test_no_connection_requires_explicit_api_selection(service):
    svc, user = service
    with pytest.raises(SubscriptionError, match="No paid API fallback"):
        svc.get_provider_data(user)
    with pytest.raises(SubscriptionError, match="medium"):
        svc.settings(user, "subscription", reasoning_effort="high")
    assert svc.settings(user, "api")["mode"] == "api"
    assert svc.get_provider_data(user) is None


def test_disconnect_clears_tokens_but_retains_registration_and_host(
    service, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    host_id = svc._config(user)["host_id"]
    httpx_mock.add_response(
        url=ISSUER + "/.well-known/openid-configuration",
        json={
            "issuer": ISSUER,
            "jwks_uri": ISSUER + "/jwks",
            "revocation_endpoint": ISSUER + "/revoke",
        },
    )
    httpx_mock.add_response(url=ISSUER + "/revoke", method="POST", status_code=200)
    status = svc.disconnect(user)
    assert not status["connected"] and status["mode"] == "subscription"
    config = svc._config(user)
    assert config["host_id"] == host_id
    assert config["accounts"]["oaiapp_test"]["subject"] == "subject-1"
    assert "access_token" not in config["accounts"]["oaiapp_test"]
    assert "id_token" not in config["accounts"]["oaiapp_test"]
    _, _, query = _begin(svc, user)
    assert query["client_id"] == ["oaiapp_test"]


def test_owner_isolation_prevents_selecting_other_users_account(
    service, db_session, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    other = Profile(id=uuid4(), email="other@example.org", hashed_password="x")
    db_session.add(other)
    db_session.commit()
    assert not svc.status(other.id)["connected"]
    with pytest.raises(SubscriptionError, match="not found"):
        svc.connect(other.id, "oaiapp_test")
    assert db_session.scalars(select(Key).where(Key.owner_id == other.id)).all() == []


def test_invalid_refresh_clears_credentials_and_keeps_subscription_mode(
    service, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    config = svc._config(user)
    config["accounts"]["oaiapp_test"]["expires_at"] = 1
    svc._write(user, SESSION_KEY, config)
    svc.db.commit()
    httpx_mock.add_response(
        url=TOKEN_URL,
        method="POST",
        status_code=400,
        json={
            "error": "invalid_grant",
            "error_description": "private upstream details",
        },
    )
    with pytest.raises(SubscriptionError, match="expired"):
        svc.get_provider_data(user)
    status = svc.status(user)
    assert not status["connected"] and status["mode"] == "subscription"
    assert "private upstream details" not in status["error"]
    assert "refresh_token" not in svc._config(user)["accounts"]["oaiapp_test"]


def test_unconfirmed_revocation_still_disconnects_locally_and_reports_it(
    service, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    httpx_mock.add_response(
        url=ISSUER + "/.well-known/openid-configuration",
        json={
            "issuer": ISSUER,
            "jwks_uri": ISSUER + "/jwks",
            "revocation_endpoint": ISSUER + "/revoke",
        },
    )
    for _ in range(2):
        httpx_mock.add_response(url=ISSUER + "/revoke", method="POST", status_code=503)
    status = svc.disconnect(user)
    assert not status["connected"]
    assert "remote revocation was not confirmed" in status["error"]
    assert "ChatGPT Settings" in status["error"]
    assert (
        len(
            [
                request
                for request in httpx_mock.get_requests()
                if str(request.url) == ISSUER + "/revoke"
            ]
        )
        == 2
    )


def test_new_account_keeps_existing_registration_and_switches_after_validation(
    service, httpx_mock, signing_key
):
    svc, user = service
    _connect(svc, user, httpx_mock, signing_key)
    host_id = svc._config(user)["host_id"]
    url = svc.connect(user, new_account=True)["authorization_url"]
    query = parse_qs(urlparse(url).query)
    state = query["state"][0]
    assert query["client_id"] == ["dynamic_agent_client"]
    assert svc.status(user)["active_account_id"] == "oaiapp_test"
    pending = svc._read(svc._row(user, _state_name(state)))
    _mock_exchange(
        httpx_mock,
        signing_key,
        pending,
        id_token=_identity(signing_key, pending, client="oaiapp_other"),
        access_token="other-access",
        refresh_token="other-refresh",
    )
    svc.callback(state, "other-code", "oaiapp_other", None)
    config = svc._config(user)
    assert config["host_id"] == host_id
    assert config["active_account_id"] == "oaiapp_other"
    assert config["accounts"]["oaiapp_test"]["access_token"] == "test-access"
    assert config["accounts"]["oaiapp_other"]["access_token"] == "other-access"
