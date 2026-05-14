from __future__ import annotations

import os
import redis
from typing import Optional

from .runtime_env import get_runtime_env

_client: Optional[redis.Redis] = None

def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        redis_url = get_runtime_env("REDIS_URL", "") or os.getenv("REDIS_URL", "")
        _client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
            max_connections=20,
        )
    return _client
