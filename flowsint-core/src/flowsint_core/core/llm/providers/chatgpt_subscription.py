from typing import AsyncIterator, cast

from openai import APIConnectionError, APIStatusError, AsyncOpenAI
from openai.types.responses import ResponseInputParam
from openai.types.shared import ReasoningEffort

from ..protocol import SubscriptionError
from ..types import ChatMessage, MessageRole


class ChatGPTSubscriptionProvider:
    def __init__(self, access_token: str, model: str, reasoning_effort: str) -> None:
        self._client = AsyncOpenAI(
            api_key=access_token,
            base_url="https://api.openai.com/v1",
            max_retries=0,
        )
        self._model = model
        self._effort = cast(ReasoningEffort, reasoning_effort)

    async def stream(self, messages: list[ChatMessage]) -> AsyncIterator[str]:
        instructions = "\n\n".join(
            m.content for m in messages if m.role == MessageRole.SYSTEM
        )
        inputs = cast(
            ResponseInputParam,
            [
                {"role": m.role.value, "content": m.content}
                for m in messages
                if m.role != MessageRole.SYSTEM
            ],
        )
        completed = False
        try:
            stream = await self._client.responses.create(
                model=self._model,
                instructions=instructions,
                input=inputs,
                reasoning={"effort": self._effort},
                store=False,
                stream=True,
            )
            async with stream:
                async for event in stream:
                    if event.type == "response.output_text.delta":
                        yield event.delta
                    elif event.type == "response.completed":
                        if event.response.status != "completed":
                            raise SubscriptionError(
                                "The subscription response was incomplete. Try again."
                            )
                        completed = True
                    elif event.type in {
                        "response.failed",
                        "response.incomplete",
                        "error",
                    }:
                        raise SubscriptionError(
                            "The subscription request failed. Check plan limits and model access in Profile."
                        )
            if not completed:
                raise SubscriptionError(
                    "The subscription stream ended before completion. Try again."
                )
        except APIStatusError as error:
            if error.status_code == 429:
                message = "ChatGPT subscription usage is currently limited. Check your plan usage in ChatGPT and try again later."
            elif error.status_code == 401:
                message = "Your ChatGPT subscription connection expired or was revoked. Reconnect in Profile."
            elif error.status_code in {403, 404}:
                message = "This model is unavailable for your ChatGPT account. Refresh models or reconnect in Profile."
            else:
                message = "ChatGPT subscription inference failed. Try again later."
            raise SubscriptionError(message) from None
        except APIConnectionError:
            raise SubscriptionError(
                "Could not reach ChatGPT subscription inference. Try again later."
            ) from None

    async def complete(self, messages: list[ChatMessage]) -> str:
        # The plan-usage route requires streaming even for complete responses.
        return "".join([text async for text in self.stream(messages)])
