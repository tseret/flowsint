from typing import AsyncIterator, List, Protocol

from .types import ChatMessage


class LLMProvider(Protocol):
    def stream(self, messages: List[ChatMessage]) -> AsyncIterator[str]: ...
    async def complete(self, messages: List[ChatMessage]) -> str: ...
