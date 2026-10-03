from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from flowsint_core.core.llm.protocol import SubscriptionError
from flowsint_core.core.models import Key
from flowsint_core.core.services.exceptions import DatabaseError, NotFoundError
from flowsint_core.core.services.key_service import keyService


def test_subscription_records_are_hidden_and_cannot_be_overwritten_or_deleted():
    owner = uuid4()
    hidden = Key(id=uuid4(), name="__flowsint_chatgpt_session", owner_id=owner)
    normal = Key(id=uuid4(), name="OPENAI_API_KEY", owner_id=owner)
    repo = MagicMock()
    repo.get_by_owner.return_value = [hidden, normal]
    repo.get_by_id_and_owner.return_value = hidden
    vault = MagicMock()
    service = keyService(MagicMock(), repo, vault)
    assert service.get_keys_for_user(owner) == [normal]
    assert service.get_key_by_owner_and_name(owner, hidden.name) is None
    for operation in (service.get_key_by_id, service.delete_key):
        with pytest.raises(NotFoundError):
            operation(hidden.id, owner)
    assert service.get_decrypted_key(hidden.name, owner) is None
    assert service.get_decrypted_key(str(hidden.id), owner) is None
    with pytest.raises(DatabaseError, match="reserved"):
        service.create_key(hidden.name, "replacement", owner)
    vault.get_secret.assert_not_called()
    vault.set_secret.assert_not_called()
    repo.delete.assert_not_called()


def test_disconnected_subscription_does_not_call_paid_api_factory():
    from flowsint_core.core.services.chat_service import create_chat_service

    with (
        patch(
            "flowsint_core.core.services.chatgpt_subscription_service.ChatGPTSubscriptionService"
        ) as subscription,
        patch("flowsint_core.core.services.chat_service.create_llm_provider") as paid,
    ):
        subscription.return_value.get_provider_data.side_effect = SubscriptionError(
            "Connect ChatGPT in Profile"
        )
        with pytest.raises(SubscriptionError, match="Connect ChatGPT"):
            create_chat_service(MagicMock()).get_llm_provider(uuid4())
        paid.assert_not_called()


def test_subscription_provider_does_not_consult_api_key_vault():
    from flowsint_core.core.llm.providers.chatgpt_subscription import (
        ChatGPTSubscriptionProvider,
    )
    from flowsint_core.core.services.chat_service import create_chat_service

    with (
        patch(
            "flowsint_core.core.services.chatgpt_subscription_service.ChatGPTSubscriptionService"
        ) as subscription,
        patch("flowsint_core.core.services.chat_service.create_llm_provider") as paid,
    ):
        subscription.return_value.get_provider_data.return_value = {
            "access_token": "test-only",
            "model": "gpt-6.1-sol",
            "reasoning_effort": "medium",
        }
        service = create_chat_service(MagicMock())
        service._vault_service = MagicMock()
        assert isinstance(
            service.get_llm_provider(uuid4()), ChatGPTSubscriptionProvider
        )
        service._vault_service.get_secret.assert_not_called()
        paid.assert_not_called()


@pytest.mark.asyncio
async def test_failed_subscription_chat_is_not_saved_as_completed():
    from flowsint_core.core.services.chat_service import create_chat_service

    class FailedProvider:
        async def stream(self, messages):
            yield "partial response"
            raise SubscriptionError("Reconnect ChatGPT in Profile.")

    service = create_chat_service(MagicMock())
    service.add_bot_message = MagicMock()
    chunks = [
        chunk async for chunk in service.stream_response(uuid4(), [], FailedProvider())
    ]
    assert any(
        '"type": "error"' in chunk and "Reconnect ChatGPT" in chunk for chunk in chunks
    )
    assert not any('"type": "finish"' in chunk for chunk in chunks)
    service.add_bot_message.assert_not_called()
