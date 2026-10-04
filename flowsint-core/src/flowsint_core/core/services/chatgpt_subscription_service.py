"""Per-user ChatGPT plan connections, encrypted in the existing Vault.

Only the public, documented OAuth and OpenAI API endpoints are used. Credentials
never leave this service except for the internal provider's bearer token.
"""

import base64
import hashlib
import json
import secrets
import time
from typing import Any, cast
from urllib.parse import urlencode, urlparse
from uuid import UUID, uuid4

import httpx
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..llm.protocol import SubscriptionError
from ..models import Key, Profile
from ..vault import Vault

PREFIX = "__flowsint_chatgpt_"
SESSION_KEY = PREFIX + "session"
PENDING_PREFIX = PREFIX + "pending_"
ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
AUTHORIZE_URL = ISSUER + "/api/accounts/authorize"
TOKEN_URL = ISSUER + "/api/accounts/oauth/token"
CALLBACK_URI = "http://127.0.0.1:5173/api/chatgpt-subscription/callback"
RETURN_URI = "http://localhost:5173/dashboard/profile"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
REQUIRED_SCOPES = {"resource.invoke", "chatgpt.tokens.use.direct"}
DEFAULT_MODEL = "gpt-6.1-sol"
DEFAULT_EFFORT = "medium"


def _state_name(state: str) -> str:
    return PENDING_PREFIX + hashlib.sha256(state.encode()).hexdigest()


class ChatGPTSubscriptionService:
    def __init__(self, db: Session):
        self.db = db

    def _lock_user(self, owner_id: UUID) -> None:
        # The Profile exists before a first connection; locking it also prevents
        # duplicate Vault rows, whose general-purpose names aren't unique.
        user = self.db.scalar(
            select(Profile).where(Profile.id == owner_id).with_for_update()
        )
        if user is None:
            raise SubscriptionError("Flowsint account not found.")

    def _row(self, owner_id: UUID, name: str) -> Key | None:
        return self.db.scalar(
            select(Key)
            .where(Key.owner_id == owner_id, Key.name == name)
            .execution_options(populate_existing=True)
        )

    def _read(self, row: Key) -> dict[str, Any]:
        value = Vault(self.db, row.owner_id)._decrypt_key(
            {"iv": row.iv, "salt": row.salt, "ciphertext": row.ciphertext}
        )
        return cast(dict[str, Any], json.loads(value))

    def _write(self, owner_id: UUID, name: str, data: dict[str, Any]) -> Key:
        vault = Vault(self.db, owner_id)
        encrypted = vault._encrypt_key(json.dumps(data))
        row = self._row(owner_id, name)
        if row is None:
            row = Key(id=uuid4(), owner_id=owner_id, name=name)
            self.db.add(row)
        row.iv = encrypted["iv"]
        row.salt = encrypted["salt"]
        row.ciphertext = encrypted["ciphertext"]
        row.key_version = vault.version
        return row

    def _config(self, owner_id: UUID) -> dict[str, Any]:
        row = self._row(owner_id, SESSION_KEY)
        return (
            self._read(row)
            if row
            else {
                "mode": "subscription",
                "model": DEFAULT_MODEL,
                "reasoning_effort": DEFAULT_EFFORT,
                "accounts": {},
                "active_account_id": None,
            }
        )

    def status(self, owner_id: UUID) -> dict[str, Any]:
        config = self._config(owner_id)
        active_id = config.get("active_account_id")
        account = config["accounts"].get(active_id, {})
        return {
            "mode": config["mode"],
            "connected": bool(account.get("access_token")),
            "account_label": account.get("label"),
            "model": config["model"],
            "reasoning_effort": config["reasoning_effort"],
            "error": config.get("error"),
            "active_account_id": active_id,
            "accounts": [
                {
                    "id": account_id,
                    "label": item["label"],
                    "connected": bool(item.get("access_token")),
                }
                for account_id, item in config["accounts"].items()
            ],
        }

    def connect(
        self, owner_id: UUID, account_id: str | None = None, new_account: bool = False
    ) -> dict[str, str]:
        self._lock_user(owner_id)
        config = self._config(owner_id)
        selected = (
            None if new_account else account_id or config.get("active_account_id")
        )
        if selected and selected not in config["accounts"]:
            self.db.rollback()
            raise SubscriptionError("Saved ChatGPT account not found.")
        account = config["accounts"].get(selected, {})
        host_id = config.setdefault("host_id", "urn:uuid:" + str(uuid4()))
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        old_pending = config.get("pending")
        if old_pending:
            old_row = self._row(owner_id, old_pending)
            if old_row:
                self.db.delete(old_row)
        pending_name = _state_name(state)
        pending = {
            "nonce": nonce,
            "verifier": verifier,
            "expires_at": time.time() + 600,
            "redirect_uri": CALLBACK_URI,
            "account_id": selected,
            "client_id": account.get("client_id", "dynamic_agent_client"),
        }
        config["pending"] = pending_name
        config.pop("error", None)
        self._write(owner_id, SESSION_KEY, config)
        self._write(owner_id, pending_name, pending)
        self.db.commit()
        parameters = {
            "client_id": pending["client_id"],
            "ext_agent_host_id": host_id,
            "response_type": "code",
            "redirect_uri": CALLBACK_URI,
            "scope": SCOPES,
            "resource": RESOURCE,
            "state": state,
            "nonce": nonce,
            "code_challenge_method": "S256",
            "code_challenge": challenge,
        }
        if not selected:
            parameters["agent_name_hint"] = "Flowsint"
        # Keep retained ID tokens server-side. An issued client ID is enough to
        # return to this registration and leaves account selection to OpenAI.
        return {"authorization_url": AUTHORIZE_URL + "?" + urlencode(parameters)}

    def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=15, follow_redirects=False) as client:
                response = client.request(method, url, **kwargs)
            if response.status_code >= 400:
                try:
                    error = response.json().get("error", {})
                    code = error.get("code") if isinstance(error, dict) else error
                except (ValueError, AttributeError):
                    code = None
                if code in {"invalid_grant", "invalid_token"}:
                    raise SubscriptionError(
                        "ChatGPT access has expired. Continue with ChatGPT again."
                    )
                if code in {
                    "subscription_sharing_usage_limit_exceeded",
                    "subscription_sharing_usage_unavailable",
                }:
                    raise SubscriptionError(
                        "ChatGPT subscription usage is unavailable or at its limit. Retry later; no API billing fallback was used."
                    )
                raise SubscriptionError(
                    "ChatGPT could not complete the request. Check account eligibility and retry."
                )
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Invalid response")
            return data
        except (httpx.HTTPError, ValueError):
            raise SubscriptionError(
                "Could not reach ChatGPT securely. Retry the connection."
            ) from None

    def _metadata(self) -> dict[str, Any]:
        metadata = self._request("GET", ISSUER + "/.well-known/openid-configuration")
        if metadata.get("issuer") != ISSUER:
            raise SubscriptionError(
                "ChatGPT identity configuration could not be validated."
            )
        for field in ("jwks_uri", "revocation_endpoint"):
            endpoint = urlparse(metadata.get(field, ""))
            if endpoint.scheme != "https" or endpoint.netloc != "auth.openai.com":
                raise SubscriptionError(
                    "ChatGPT identity configuration could not be validated."
                )
        return metadata

    def _verify_identity(
        self,
        token: str,
        client_id: str,
        nonce: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        metadata = self._metadata()
        jwks = self._request("GET", metadata["jwks_uri"])
        try:
            header = jwt.get_unverified_header(token)
            key = next(
                item for item in jwks["keys"] if item.get("kid") == header.get("kid")
            )
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=client_id,
                issuer=ISSUER,
                access_token=access_token,
                options={
                    "require_exp": True,
                    "require_sub": True,
                    "require_aud": True,
                    "require_iss": True,
                },
            )
            if not claims.get("sub") or (
                nonce is not None
                and not secrets.compare_digest(str(claims.get("nonce", "")), nonce)
            ):
                raise ValueError("Invalid identity")
            return cast(dict[str, Any], claims)
        except (JWTError, ValueError, StopIteration, KeyError, TypeError):
            raise SubscriptionError(
                "ChatGPT identity could not be validated. Start a fresh sign-in."
            ) from None

    def _tokens(self, response: dict[str, Any]) -> dict[str, Any]:
        scopes = str(response.get("scope", "")).split()
        if not REQUIRED_SCOPES.issubset(scopes):
            raise SubscriptionError(
                "ChatGPT plan usage was not authorized. Continue with ChatGPT and allow plan usage."
            )
        try:
            expiry = int(response["expires_in"])
            if (
                not 0 < expiry <= 86400
                or str(response.get("token_type", "")).lower() != "bearer"
            ):
                raise ValueError("Invalid token")
            if not all(
                isinstance(response.get(field), str) and response[field]
                for field in ("access_token", "refresh_token")
            ):
                raise ValueError("Missing token")
            earliest = response.get("earliest_refresh_at", 0)
            # The server may return a numeric epoch or an ISO UTC timestamp.
            if isinstance(earliest, str) and not earliest.isdecimal():
                from datetime import datetime

                earliest = datetime.fromisoformat(
                    earliest.replace("Z", "+00:00")
                ).timestamp()
            return {
                "access_token": response["access_token"],
                "refresh_token": response["refresh_token"],
                "expires_at": time.time() + expiry,
                "earliest_refresh_at": float(earliest),
                "scopes": scopes,
            }
        except (ValueError, KeyError, TypeError, OverflowError):
            raise SubscriptionError(
                "ChatGPT returned incomplete credentials. Start a fresh sign-in."
            ) from None

    def callback(
        self, state: str, code: str | None, client_id: str | None, error: str | None
    ) -> None:
        name = _state_name(state)
        row = self.db.scalar(select(Key).where(Key.name == name))
        if row is None:
            raise SubscriptionError(
                "This ChatGPT sign-in has expired or was already used."
            )
        owner_id = row.owner_id
        self._lock_user(owner_id)
        row = self._row(owner_id, name)
        config = self._config(owner_id)
        if row is None or config.get("pending") != name:
            self.db.rollback()
            raise SubscriptionError(
                "This ChatGPT sign-in has expired or was already used."
            )
        pending = self._read(row)
        # Consume before any network request. Even failed exchanges cannot replay.
        self.db.delete(row)
        self.db.commit()
        try:
            if time.time() > pending["expires_at"]:
                raise SubscriptionError(
                    "This ChatGPT sign-in has expired. Start a new connection."
                )
            if error:
                raise SubscriptionError(
                    "ChatGPT sign-in was cancelled or permission was denied. Continue with ChatGPT to retry."
                )
            issued_id = client_id or pending["client_id"]
            if not code or issued_id == "dynamic_agent_client" or not issued_id:
                raise SubscriptionError(
                    "ChatGPT registration was incomplete. Start a fresh sign-in."
                )
            if (
                pending["client_id"] != "dynamic_agent_client"
                and issued_id != pending["client_id"]
            ):
                raise SubscriptionError(
                    "The returned ChatGPT registration did not match the selected account."
                )
            response = self._request(
                "POST",
                TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": issued_id,
                    "code": code,
                    "code_verifier": pending["verifier"],
                    "redirect_uri": pending["redirect_uri"],
                    "resource": RESOURCE,
                },
            )
            claims = self._verify_identity(
                response.get("id_token", ""),
                issued_id,
                pending["nonce"],
                response.get("access_token"),
            )
            tokens = self._tokens(response)
            self._lock_user(owner_id)
            config = self._config(owner_id)
            if config.get("pending") != name:
                raise SubscriptionError(
                    "This ChatGPT sign-in was superseded. Start a fresh connection."
                )
            previous = config["accounts"].get(pending.get("account_id"), {})
            if previous and previous["subject"] != claims["sub"]:
                raise SubscriptionError(
                    "The returned ChatGPT identity did not match the selected account."
                )
            label = (
                str(claims.get("email") or "ChatGPT account")[:200]
                + " · "
                + issued_id[-8:]
            )
            config["accounts"][issued_id] = {
                "client_id": issued_id,
                "subject": claims["sub"],
                "label": label,
                "id_token": response["id_token"],
                **tokens,
            }
            config.update(mode="subscription", active_account_id=issued_id)
            config.pop("pending", None)
            config.pop("error", None)
            self._write(owner_id, SESSION_KEY, config)
            self.db.commit()
        except SubscriptionError as exc:
            self.db.rollback()
            self._lock_user(owner_id)
            config = self._config(owner_id)
            if config.get("pending") == name:
                config.pop("pending", None)
                config["error"] = str(exc)
                self._write(owner_id, SESSION_KEY, config)
            self.db.commit()
            raise

    def get_provider_data(
        self, owner_id: UUID, *, check_model: bool = True
    ) -> dict[str, str] | None:
        self._lock_user(owner_id)
        config = self._config(owner_id)
        if config["mode"] == "api":
            self.db.commit()
            return None
        account = config["accounts"].get(config.get("active_account_id"), {})
        if not account.get("access_token"):
            self.db.commit()
            raise SubscriptionError(
                "Connect your ChatGPT subscription in Profile to use the copilot. No paid API fallback was used."
            )
        now = time.time()
        if now >= account["expires_at"] - 60 and now >= account.get(
            "earliest_refresh_at", 0
        ):
            try:
                response = self._request(
                    "POST",
                    TOKEN_URL,
                    data={
                        "grant_type": "refresh_token",
                        "client_id": account["client_id"],
                        "refresh_token": account["refresh_token"],
                        "resource": RESOURCE,
                    },
                )
                tokens = self._tokens(response)
                if response.get("id_token"):
                    claims = self._verify_identity(
                        response["id_token"],
                        account["client_id"],
                        access_token=response.get("access_token"),
                    )
                    if claims["sub"] != account["subject"]:
                        raise SubscriptionError(
                            "ChatGPT identity changed during refresh. Connect again."
                        )
                    account["id_token"] = response["id_token"]
                account.update(tokens)
                config.pop("error", None)
                self._write(owner_id, SESSION_KEY, config)
            except SubscriptionError as exc:
                if str(exc).startswith(
                    "ChatGPT access has expired"
                ) or "identity changed" in str(exc):
                    for field in ("access_token", "refresh_token", "id_token"):
                        account.pop(field, None)
                config["error"] = str(exc)
                self._write(owner_id, SESSION_KEY, config)
                self.db.commit()
                raise
        if now >= account["expires_at"]:
            self.db.commit()
            raise SubscriptionError(
                "ChatGPT access is waiting for renewal. Retry later or connect again."
            )
        result = {
            "access_token": account["access_token"],
            "model": config["model"],
            "reasoning_effort": config["reasoning_effort"],
        }
        self.db.commit()
        if check_model:
            available = self._catalog(result["access_token"])
            if result["model"] not in {item["slug"] for item in available}:
                raise SubscriptionError(
                    "The configured copilot model is unavailable to this ChatGPT account. Select an available model in Profile; no model or billing fallback was used."
                )
        return result

    def _catalog(self, access_token: str) -> list[dict[str, str]]:
        response = self._request(
            "GET",
            RESOURCE + "/models",
            headers={"Authorization": "Bearer " + access_token},
        )
        return [
            {
                "slug": item["slug"],
                "display_name": str(item.get("display_name") or item["slug"]),
            }
            for item in response.get("models", [])
            if isinstance(item, dict)
            and item.get("visibility") == "list"
            and isinstance(item.get("slug"), str)
        ]

    def models(self, owner_id: UUID) -> dict[str, Any]:
        provider = self.get_provider_data(owner_id, check_model=False)
        if provider is None:
            raise SubscriptionError(
                "Select ChatGPT subscription billing and connect an account to list its models."
            )
        return {"models": self._catalog(provider["access_token"])}

    def settings(
        self,
        owner_id: UUID,
        mode: str,
        model: str | None = None,
        reasoning_effort: str | None = None,
    ) -> dict[str, Any]:
        if mode not in {"subscription", "api"}:
            raise SubscriptionError("Choose subscription or API billing explicitly.")
        if reasoning_effort not in {None, DEFAULT_EFFORT}:
            raise SubscriptionError(
                "The investigation copilot uses medium reasoning effort."
            )
        selected = self.status(owner_id)["active_account_id"]
        if model is not None:
            models = self.models(owner_id)["models"]
            if model not in {item["slug"] for item in models}:
                raise SubscriptionError(
                    "This model is unavailable to the selected ChatGPT account."
                )
        self._lock_user(owner_id)
        config = self._config(owner_id)
        if model is not None and config.get("active_account_id") != selected:
            self.db.rollback()
            raise SubscriptionError(
                "The active ChatGPT account changed. Reload its models and retry."
            )
        config["mode"] = mode
        if model is not None:
            config["model"] = model
        config["reasoning_effort"] = DEFAULT_EFFORT
        self._write(owner_id, SESSION_KEY, config)
        self.db.commit()
        return self.status(owner_id)

    def disconnect(self, owner_id: UUID) -> dict[str, Any]:
        self._lock_user(owner_id)
        config = self._config(owner_id)
        account = config["accounts"].get(config.get("active_account_id"), {})
        confirmed = not account.get("refresh_token")
        if account.get("refresh_token"):
            try:
                endpoint = self._metadata()["revocation_endpoint"]
                for attempt in range(2):
                    try:
                        with httpx.Client(timeout=15, follow_redirects=False) as client:
                            response = client.post(
                                endpoint,
                                data={
                                    "token": account["refresh_token"],
                                    "token_type_hint": "refresh_token",
                                    "client_id": account["client_id"],
                                },
                            )
                        confirmed = response.status_code == 200
                        if confirmed or response.status_code < 500:
                            break
                    except httpx.HTTPError:
                        confirmed = False
                    if attempt == 0:
                        time.sleep(0.25)
            except (httpx.HTTPError, SubscriptionError):
                confirmed = False
        for field in (
            "access_token",
            "refresh_token",
            "id_token",
            "expires_at",
            "earliest_refresh_at",
            "scopes",
        ):
            account.pop(field, None)
        pending = config.pop("pending", None)
        if pending:
            row = self._row(owner_id, pending)
            if row:
                self.db.delete(row)
        if confirmed:
            config.pop("error", None)
        else:
            config["error"] = (
                "Disconnected locally; remote revocation was not confirmed. Disconnect Flowsint in ChatGPT Settings as well."
            )
        self._write(owner_id, SESSION_KEY, config)
        self.db.commit()
        return self.status(owner_id)
