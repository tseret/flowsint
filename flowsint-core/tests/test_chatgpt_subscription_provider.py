from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from openai import APIStatusError

from flowsint_core.core.llm.protocol import SubscriptionError
from flowsint_core.core.llm.providers.chatgpt_subscription import (
    ChatGPTSubscriptionProvider,
)
from flowsint_core.core.llm.types import ChatMessage, MessageRole


class FakeStream:
    def __init__(self, events):
        self.events = events
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.closed = True

    async def __aiter__(self):
        for event in self.events:
            yield event


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal", ["response.completed", "response.failed", "response.incomplete", None]
)
async def test_subscription_requires_completed_stream_and_correct_wire_contract(
    terminal,
):
    events = [SimpleNamespace(type="response.output_text.delta", delta="Result")]
    if terminal:
        events.append(
            SimpleNamespace(type=terminal, response=SimpleNamespace(status="completed"))
        )
    stream = FakeStream(events)
    create = AsyncMock(return_value=stream)
    with patch(
        "flowsint_core.core.llm.providers.chatgpt_subscription.AsyncOpenAI"
    ) as sdk:
        sdk.return_value.responses.create = create
        provider = ChatGPTSubscriptionProvider("test-token", "gpt-6.1-sol", "medium")
    messages = [
        ChatMessage(MessageRole.SYSTEM, "Trusted instructions"),
        ChatMessage(MessageRole.USER, "Evidence"),
    ]
    if terminal == "response.completed":
        assert await provider.complete(messages) == "Result"
    else:
        with pytest.raises(SubscriptionError):
            await provider.complete(messages)
    assert stream.closed
    create.assert_awaited_once_with(
        model="gpt-6.1-sol",
        instructions="Trusted instructions",
        input=[{"role": "user", "content": "Evidence"}],
        reasoning={"effort": "medium"},
        store=False,
        stream=True,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, message",
    [(401, "Reconnect"), (403, "unavailable"), (429, "plan usage"), (500, "failed")],
)
async def test_subscription_failure_is_redacted_and_never_calls_api_provider(
    status, message
):
    error = APIStatusError(
        "private-response",
        response=httpx.Response(
            status, request=httpx.Request("POST", "https://api.openai.com")
        ),
        body={"code": "other"},
    )
    with patch(
        "flowsint_core.core.llm.providers.chatgpt_subscription.AsyncOpenAI"
    ) as sdk:
        sdk.return_value.responses.create = AsyncMock(side_effect=error)
        provider = ChatGPTSubscriptionProvider("test-token", "gpt-6.1-sol", "medium")
    with pytest.raises(SubscriptionError) as result:
        await provider.complete([ChatMessage(MessageRole.USER, "Evidence")])
    assert message in str(result.value)
    assert "private-response" not in str(result.value)
