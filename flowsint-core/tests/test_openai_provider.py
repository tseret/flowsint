from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from openai import omit

from flowsint_core.core.llm.factory import create_llm_provider
from flowsint_core.core.llm.types import ChatMessage, MessageRole


@pytest.mark.asyncio
@pytest.mark.parametrize("effort", [None, "medium"])
async def test_openai_configuration_reaches_complete_and_stream(monkeypatch, effort):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-6.1-sol")
    monkeypatch.delenv("LLM_REASONING_EFFORT", raising=False)
    if effort:
        monkeypatch.setenv("LLM_REASONING_EFFORT", effort)
    create = AsyncMock()
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )
    with patch(
        "flowsint_core.core.llm.providers.openai.AsyncOpenAI", return_value=client
    ):
        provider = create_llm_provider(api_key="test-only-key")
    messages = [ChatMessage(MessageRole.USER, "Summarize existing evidence")]
    expected = {
        "model": "gpt-6.1-sol",
        "messages": [{"role": "user", "content": messages[0].content}],
        "reasoning_effort": effort or omit,
    }
    create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="Evidence summary"))]
    )
    assert await provider.complete(messages) == "Evidence summary"
    create.assert_awaited_once_with(**expected)

    async def chunks():
        yield SimpleNamespace(choices=[])
        yield SimpleNamespace(
            choices=[SimpleNamespace(delta=SimpleNamespace(content=None))]
        )
        yield SimpleNamespace(
            choices=[SimpleNamespace(delta=SimpleNamespace(content="Summary"))]
        )

    create.reset_mock()
    create.return_value = chunks()
    assert [chunk async for chunk in provider.stream(messages)] == ["Summary"]
    create.assert_awaited_once_with(**expected, stream=True)


def test_invalid_reasoning_effort_fails_before_client_creation(monkeypatch):
    monkeypatch.setenv("LLM_REASONING_EFFORT", "typo")
    with patch("flowsint_core.core.llm.providers.openai.AsyncOpenAI") as client:
        with pytest.raises(ValueError, match="reasoning effort"):
            create_llm_provider(provider="openai", api_key="test-only-key")
        client.assert_not_called()
