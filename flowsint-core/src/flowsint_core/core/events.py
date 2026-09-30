import asyncio
import json
import os
import uuid
from typing import Any, Dict, Optional

import redis.asyncio as redis


class EventEmitter:
    def __init__(self) -> None:
        self.id = uuid.uuid4()
        self.redis = redis.from_url(os.environ["REDIS_URL"])
        self.pubsubs: Dict[str, redis.client.PubSub] = {}

    async def subscribe(self, channel: str) -> None:
        """Subscribe to Redis channel"""
        if channel not in self.pubsubs:
            pubsub = self.redis.pubsub()
            await pubsub.subscribe(channel)
            self.pubsubs[channel] = pubsub

    async def unsubscribe(self, channel: str) -> None:
        """Unsubscribe from Redis channel"""
        if channel in self.pubsubs:
            await self.pubsubs[channel].unsubscribe(channel)
            await self.pubsubs[channel].close()
            del self.pubsubs[channel]

    async def get_message(self, channel: Optional[str] = None) -> Optional[str]:
        """Get the next message from Redis for a specific channel"""
        if channel not in self.pubsubs:
            return None

        message = await self.pubsubs[channel].get_message(
            ignore_subscribe_messages=True
        )
        if message is None:
            await asyncio.sleep(0.1)
            return None

        if message:
            data = message["data"]
            if isinstance(data, bytes):
                decoded = data.decode("utf-8")
                return decoded
            return str(data)
        return None

    async def emit(self, channel: str, data: Any) -> None:
        """Emit an event to a Redis channel"""
        await self.redis.publish(channel, json.dumps(data))


event_emitter = EventEmitter()
