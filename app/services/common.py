from __future__ import annotations

import logging
import os
import random
import threading
import time
from collections import deque
from typing import Callable, TypeVar

T = TypeVar("T")
logger = logging.getLogger(__name__)


class ExternalFeedRateLimiter:
    """Sliding-window limiter for outbound feed/API calls."""

    def __init__(self, per_second: int, per_minute: int) -> None:
        self.per_second = max(0, int(per_second))
        self.per_minute = max(0, int(per_minute))
        self._lock = threading.Lock()
        self._second_window: deque[float] = deque()
        self._minute_window: deque[float] = deque()

    def _trim(self, now: float) -> None:
        while self._second_window and (now - self._second_window[0]) >= 1.0:
            self._second_window.popleft()
        while self._minute_window and (now - self._minute_window[0]) >= 60.0:
            self._minute_window.popleft()

    def acquire(self, *, source: str = "external_feed") -> None:
        while True:
            sleep_s = 0.0
            with self._lock:
                now = time.monotonic()
                self._trim(now)

                waits = []
                if self.per_second > 0 and len(self._second_window) >= self.per_second:
                    waits.append(max(0.0, 1.0 - (now - self._second_window[0])))
                if self.per_minute > 0 and len(self._minute_window) >= self.per_minute:
                    waits.append(max(0.0, 60.0 - (now - self._minute_window[0])))

                if not waits:
                    now = time.monotonic()
                    self._second_window.append(now)
                    self._minute_window.append(now)
                    return

                sleep_s = max(0.001, min(waits))

            logger.debug("feed_rate_limit_wait", extra={"source": source, "sleep_s": round(sleep_s, 3)})
            time.sleep(sleep_s)


_LIMITER_STATE_LOCK = threading.Lock()
_LIMITER_STATE: dict[str, tuple[tuple[bool, int, int], ExternalFeedRateLimiter | None]] = {}


def _source_env_suffix(source: str) -> str:
    raw = (source or "external_feed").strip().upper()
    out = []
    for ch in raw:
        if ch.isalnum():
            out.append(ch)
        else:
            out.append("_")
    return "".join(out)


def _env_feed_limiter_config(*, source: str = "external_feed") -> tuple[bool, int, int]:
    enabled = os.getenv("FEED_RATE_LIMIT_ENABLED", "true").strip().lower() in {"1", "true", "yes", "y", "on"}
    suffix = _source_env_suffix(source)
    per_second = int(os.getenv(f"FEED_REQUESTS_PER_SECOND_{suffix}", os.getenv("FEED_REQUESTS_PER_SECOND", "10")))
    per_minute = int(os.getenv(f"FEED_REQUESTS_PER_MINUTE_{suffix}", os.getenv("FEED_REQUESTS_PER_MINUTE", "55")))
    return enabled, per_second, per_minute


def _get_feed_limiter(*, source: str = "external_feed") -> ExternalFeedRateLimiter | None:
    cfg = _env_feed_limiter_config(source=source)
    with _LIMITER_STATE_LOCK:
        current = _LIMITER_STATE.get(source)
        if current and current[0] == cfg:
            return current[1]
        enabled, per_second, per_minute = cfg
        if not enabled or (per_second <= 0 and per_minute <= 0):
            limiter = None
        else:
            limiter = ExternalFeedRateLimiter(per_second=per_second, per_minute=per_minute)
        _LIMITER_STATE[source] = (cfg, limiter)
        return limiter


def throttle_external_request(*, source: str = "external_feed") -> None:
    limiter = _get_feed_limiter(source=source)
    if limiter is None:
        return
    limiter.acquire(source=source)


class CircuitBreaker:
    """Thread-safe circuit breaker for external service calls.

    Tracks consecutive failures per source. After fail_threshold failures,
    opens the circuit for cooldown_s seconds before allowing new attempts.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, float]] = {}

    def is_open(self, source: str) -> bool:
        with self._lock:
            state = self._state.get(source) or {}
            return float(state.get("open_until", 0.0)) > time.time()

    def record_success(self, source: str) -> None:
        with self._lock:
            self._state[source] = {"fails": 0.0, "open_until": 0.0}

    def record_failure(self, source: str, *, fail_threshold: int, cooldown_s: int) -> None:
        with self._lock:
            now_ts = time.time()
            state = self._state.get(source) or {"fails": 0.0, "open_until": 0.0}
            fails = float(state.get("fails", 0.0)) + 1.0
            open_until = float(state.get("open_until", 0.0))
            if fails >= max(1, fail_threshold):
                open_until = now_ts + max(1, cooldown_s)
                fails = 0.0
            self._state[source] = {"fails": fails, "open_until": open_until}


# Shared instance used across all feed services
_circuit_breaker = CircuitBreaker()


class DepStatusCache:
    """Thread-safe in-memory cache of external dependency health states.

    Updated by feed services after each run and by health check functions.
    Read by the ``/deps`` endpoint.  When Redis is available the caller may
    additionally persist/read entries there; this class is the authoritative
    in-process store.

    Schema per entry::

        {
          "status":          "ok" | "degraded" | "down" | "unknown",
          "last_ok_ts":      float | None,   # epoch seconds
          "last_check_ts":   float | None,
          "last_error":      str | None,
          "last_duration_ms": int | None,
        }
    """

    _VALID_STATUSES = frozenset({"ok", "degraded", "down", "unknown"})

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, dict] = {}

    def update(
        self,
        source: str,
        status: str,
        *,
        error: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        if status not in self._VALID_STATUSES:
            status = "unknown"
        now = time.time()
        with self._lock:
            prev = self._store.get(source) or {}
            self._store[source] = {
                "status": status,
                "last_ok_ts": now if status == "ok" else prev.get("last_ok_ts"),
                "last_check_ts": now,
                "last_error": error if status != "ok" else None,
                "last_duration_ms": duration_ms,
            }

    def get(self, source: str) -> dict:
        with self._lock:
            return dict(self._store.get(source) or {"status": "unknown", "last_ok_ts": None, "last_check_ts": None, "last_error": None, "last_duration_ms": None})

    def get_all(self) -> dict[str, dict]:
        with self._lock:
            return {k: dict(v) for k, v in self._store.items()}


# Shared dep status cache — updated by services, read by /deps endpoint
_dep_status = DepStatusCache()


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
            # Additive jitter only extends wait time (never shortens below base backoff).
            delta = sleep * jitter
            sleep = max(0.1, sleep + random.uniform(0, delta))
            logger.warning("retry_backoff", extra={"attempt": attempt, "sleep_s": round(sleep,3), "error": str(e)})
            time.sleep(sleep)
