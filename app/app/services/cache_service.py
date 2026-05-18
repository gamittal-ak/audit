"""
Redis-backed rule tree cache.
Key pattern: rt:{switch_key}:{property_id}:{version}
"""
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.asyncio import Redis


async def get_or_fetch_rule_tree(
    redis: "Redis",
    fetch_coro,  # awaitable that returns the rule tree dict
    switch_key: str,
    property_id: str,
    version: str,
    ttl: int = 3600,
) -> dict:
    """
    Return the cached rule tree if available, otherwise call fetch_coro,
    cache the result under the given TTL, and return it.
    """
    key = f"rt:{switch_key}:{property_id}:{version}"
    cached = await redis.get(key)
    if cached:
        return json.loads(cached)

    fresh = await fetch_coro
    await redis.setex(key, ttl, json.dumps(fresh))
    return fresh
