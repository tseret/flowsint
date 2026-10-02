from typing import AsyncIterator, List, Protocol

from .types import ChatMessage


class SubscriptionError(RuntimeError):
    """Safe, actionable errors for subscription authentication and inference."""


class LLMProvider(Protocol):
    def stream(self, messages: List[ChatMessage]) -> AsyncIterator[str]: ...
    async def complete(self, messages: List[ChatMessage]) -> str: ...
