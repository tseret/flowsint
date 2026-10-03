"""Local ChatGPT OAuth connections; access/refresh tokens are never API responses."""

from typing import Any, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from flowsint_core.core.llm.protocol import SubscriptionError
from flowsint_core.core.models import Profile
from flowsint_core.core.postgre_db import get_db
from flowsint_core.core.services.chatgpt_subscription_service import (
    RETURN_URI,
    ChatGPTSubscriptionService,
)

router = APIRouter()


class ConnectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_id: str | None = Field(default=None, min_length=1, max_length=200)
    new_account: bool = False


class SettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["subscription", "api"]
    model: str | None = Field(default=None, min_length=1, max_length=100)
    reasoning_effort: Literal["medium"] | None = None


@router.get("/status")
def status(
    db: Session = Depends(get_db), user: Profile = Depends(get_current_user)
) -> dict[str, Any]:
    return cast(dict[str, Any], ChatGPTSubscriptionService(db).status(user.id))


@router.post("/connect")
def connect(
    request: Request,
    payload: ConnectRequest | None = None,
    db: Session = Depends(get_db),
    user: Profile = Depends(get_current_user),
) -> dict[str, str]:
    # This OSS OAuth flow is supported only on the host running Flowsint.
    # A shared remote deployment must implement the separate supported VM flow.
    if request.url.hostname not in {"localhost", "127.0.0.1", "testserver"}:
        raise HTTPException(
            400, "ChatGPT subscription sign-in requires the local Flowsint host."
        )
    payload = payload or ConnectRequest()
    try:
        return cast(
            dict[str, str],
            ChatGPTSubscriptionService(db).connect(
                user.id, payload.account_id, payload.new_account
            ),
        )
    except SubscriptionError as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("/callback")
def callback(
    state: str = Query(min_length=20, max_length=200),
    code: str | None = Query(default=None, max_length=4096),
    client_id: str | None = Query(default=None, max_length=200),
    error: str | None = Query(default=None, max_length=200),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    # The one-use random state associates the callback with the authenticated
    # connect request. Loopback uses a different host from the UI's auth cookie.
    try:
        ChatGPTSubscriptionService(db).callback(state, code, client_id, error)
    except SubscriptionError:
        pass  # Valid attempts save a safe reason for the authenticated status UI.
    return RedirectResponse(
        RETURN_URI,
        status_code=303,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@router.get("/models")
def models(
    db: Session = Depends(get_db), user: Profile = Depends(get_current_user)
) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], ChatGPTSubscriptionService(db).models(user.id))
    except SubscriptionError as exc:
        raise HTTPException(502, str(exc)) from None


@router.put("/settings")
def settings(
    payload: SettingsRequest,
    db: Session = Depends(get_db),
    user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        return cast(
            dict[str, Any],
            ChatGPTSubscriptionService(db).settings(
                user.id, payload.mode, payload.model, payload.reasoning_effort
            ),
        )
    except SubscriptionError as exc:
        raise HTTPException(400, str(exc)) from None


@router.delete("/connection")
def disconnect(
    db: Session = Depends(get_db), user: Profile = Depends(get_current_user)
) -> dict[str, Any]:
    return cast(dict[str, Any], ChatGPTSubscriptionService(db).disconnect(user.id))
