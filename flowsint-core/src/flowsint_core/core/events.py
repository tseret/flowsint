import asyncio
import json
import os
import uuid
from typing import Any, Optional

import redis.asyncio as redis


class EventEmitter:
    def __init__(self) -> None:
        self.id = uuid.uuid4()
        self.redis = redis.from_url(os.environ["REDIS_URL"])

    async def subscribe(self, channel: str) -> redis.client.PubSub:
        """Give each stream its own Redis subscription to this channel."""
        pubsub: redis.client.PubSub = self.redis.pubsub()
        try:
            await pubsub.subscribe(channel)
        except BaseException:
            await pubsub.aclose()
            raise
        return pubsub

    async def unsubscribe(self, pubsub: redis.client.PubSub) -> None:
        """Close only this stream's subscription."""
        await pubsub.aclose()

    async def get_message(self, pubsub: redis.client.PubSub) -> Optional[str]:
        """Get the next message from this stream's subscription."""
        message = await pubsub.get_message(ignore_subscribe_messages=True)
        if message is None:
            await asyncio.sleep(0.1)
            return None

        data = message["data"]
        if isinstance(data, bytes):
            return data.decode("utf-8")
        return str(data)

    async def emit(self, channel: str, data: Any) -> None:
        """Emit an event to a Redis channel"""
        await self.redis.publish(channel, json.dumps(data))


event_emitter = EventEmitter()
