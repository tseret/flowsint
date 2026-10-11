"""Each case viewer must receive its own live events."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from flowsint_core.core.events import EventEmitter


def test_subscribers_to_same_sketch_are_independent():
    async def run():
        emitter = EventEmitter()
        first = MagicMock()
        second = MagicMock()
        for pubsub in (first, second):
            pubsub.subscribe = AsyncMock()
            pubsub.aclose = AsyncMock()
            pubsub.get_message = AsyncMock(
                return_value={"data": b'{"type":"COMPLETED"}'}
            )
        emitter.redis = MagicMock()
        emitter.redis.pubsub.side_effect = [first, second]

        viewer_a = await emitter.subscribe("sketch_status")
        viewer_b = await emitter.subscribe("sketch_status")
        assert viewer_a is not viewer_b
        assert await emitter.get_message(viewer_a) == '{"type":"COMPLETED"}'
        assert await emitter.get_message(viewer_b) == '{"type":"COMPLETED"}'

        await emitter.unsubscribe(viewer_a)
        first.aclose.assert_awaited_once()
        second.aclose.assert_not_awaited()
        assert await emitter.get_message(viewer_b) == '{"type":"COMPLETED"}'
        await emitter.unsubscribe(viewer_b)

    asyncio.run(run())
