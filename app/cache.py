from __future__ import annotations

import os
import redis
from typing import Optional

REDIS_URL = os.getenv("REDIS_URL", "")

_client: Optional[redis.Redis] = None

def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=5)
    return _client
