from __future__ import annotations

import time
import random
import logging
from typing import Callable, TypeVar, Any, Optional

T = TypeVar("T")
logger = logging.getLogger(__name__)

def retry_with_backoff(fn: Callable[[], T], *, max_attempts: int = 6, base_delay: float = 1.0, max_delay: float = 30.0, jitter: float = 0.2) -> T:
    """Exponential backoff with jitter for transient failures."""
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except Exception as e:
            if attempt >= max_attempts:
                raise
            sleep = min(max_delay, base_delay * (2 ** (attempt - 1)))
            # jitter in range +/- jitter
            delta = sleep * jitter
            sleep = max(0.1, sleep + random.uniform(-delta, delta))
            logger.warning("retry_backoff", extra={"attempt": attempt, "sleep_s": round(sleep,3), "error": str(e)})
            time.sleep(sleep)
