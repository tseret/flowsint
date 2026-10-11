from typing import AsyncIterator, List, Optional, cast

from openai import AsyncOpenAI, omit
from openai.types.chat import ChatCompletionMessageParam
from openai.types.shared import ReasoningEffort

from ..types import ChatMessage


class OpenAIProvider:
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        reasoning_effort: Optional[str] = None,
    ) -> None:
        if reasoning_effort is not None and reasoning_effort not in (
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
        ):
            raise ValueError("Unsupported OpenAI reasoning effort")
        self._client = AsyncOpenAI(api_key=api_key)
        self._model = model
        self._reasoning_effort = cast(Optional[ReasoningEffort], reasoning_effort)

    def _build_messages(
        self, messages: List[ChatMessage]
    ) -> list[ChatCompletionMessageParam]:
        return [
            cast(
                ChatCompletionMessageParam, {"role": m.role.value, "content": m.content}
            )
            for m in messages
        ]

    async def stream(self, messages: List[ChatMessage]) -> AsyncIterator[str]:
        sdk_messages = self._build_messages(messages)

        response = await self._client.chat.completions.create(
            model=self._model,
            messages=sdk_messages,
            stream=True,
            reasoning_effort=self._reasoning_effort or omit,
        )

        async for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content is not None:
                yield chunk.choices[0].delta.content

    async def complete(self, messages: List[ChatMessage]) -> str:
        sdk_messages = self._build_messages(messages)

        response = await self._client.chat.completions.create(
            model=self._model,
            messages=sdk_messages,
            reasoning_effort=self._reasoning_effort or omit,
        )

        return response.choices[0].message.content or ""
