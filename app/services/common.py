from __future__ import annotations

import logging
import os
import random
import re
import threading
import time
from collections import deque
from typing import Any, Callable, TypeVar
import warnings
import requests
from urllib3.exceptions import InsecureRequestWarning
from requests import HTTPError
from requests.exceptions import ProxyError, SSLError, ConnectTimeout, ReadTimeout, ConnectionError as RequestsConnectionError
from requests.sessions import merge_setting
from requests.utils import get_environ_proxies

from ..runtime_env import get_proxy_settings, get_runtime_env

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

def configure_requests_tls_verify_from_env() -> None:
    """Compatibility no-op.

    TLS verify and proxy behavior are applied per-session by ``build_feed_session``.
    """
    return


_PROXY_CRED_RE = re.compile(r"(https?://)([^:/@\s]+):([^/@\s]+)@")


def redact_proxy_credentials(text: str) -> str:
    if not text:
        return text
    return _PROXY_CRED_RE.sub(r"\1***:***@", text)


class RuntimeSession(requests.Session):
    def __init__(
        self,
        *,
        runtime_proxies: dict[str, str] | None = None,
        runtime_no_proxy: str | None = None,
        runtime_verify: bool | str | None = None,
    ) -> None:
        super().__init__()
        self.runtime_proxies = dict(runtime_proxies or {})
        self.runtime_no_proxy = runtime_no_proxy or None
        self.runtime_verify = runtime_verify
        self.trust_env = True

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        env_proxies = get_environ_proxies(url, no_proxy=self.runtime_no_proxy) if self.trust_env else {}
        merged_proxies = merge_setting(proxies, env_proxies)
        merged_proxies = merge_setting(merged_proxies, self.runtime_proxies)
        effective_verify = self.runtime_verify if self.runtime_verify is not None else verify
        if effective_verify is False:
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        return {
            "proxies": merged_proxies,
            "stream": stream,
            "verify": effective_verify,
            "cert": cert,
        }


def build_feed_session(*, source: str) -> requests.Session:
    """Build requests Session honoring global env and optional per-feed overrides.

    Optional per-feed env overrides:
    - FEED_PROXY_URL_<SOURCE>
    - FEED_HTTP_PROXY_<SOURCE>
    - FEED_HTTPS_PROXY_<SOURCE>
    where SOURCE is uppercased with non-alnum replaced by underscore.
    """
    proxy_settings = get_proxy_settings()
    suffix = _source_env_suffix(source)
    all_proxy = str(get_runtime_env(f"FEED_PROXY_URL_{suffix}", "") or "").strip()
    http_proxy = str(get_runtime_env(f"FEED_HTTP_PROXY_{suffix}", "") or "").strip() or all_proxy or proxy_settings.http_url
    https_proxy = str(get_runtime_env(f"FEED_HTTPS_PROXY_{suffix}", "") or "").strip() or all_proxy or proxy_settings.https_url
    proxies: dict[str, str] = {}
    if http_proxy:
        proxies["http"] = http_proxy
    if https_proxy:
        proxies["https"] = https_proxy
    verify: bool | str = False if proxy_settings.skip_tls_verify else (proxy_settings.ca_bundle_path or True)
    session = RuntimeSession(
        runtime_proxies=proxies,
        runtime_no_proxy=proxy_settings.no_proxy or None,
        runtime_verify=verify,
    )
    if proxies:
        session.proxies.update(proxies)
    return session


class ExternalFeedConnector:
    """Shared HTTP wrapper for feed connectors.

    Centralizes throttle + retry policy and keeps call sites consistent across
    feed services.
    """

    def __init__(
        self,
        *,
        source: str,
        session: requests.Session | None = None,
        retry_fn: Callable[..., Any] | None = None,
    ) -> None:
        self.source = source
        self._session = session
        self._retry_fn = retry_fn

    def _session_or_new(self) -> tuple[requests.Session, bool]:
        if self._session is not None:
            return self._session, False
        return build_feed_session(source=self.source), True

    def request_json(
        self,
        *,
        method: str,
        url: str,
        timeout_s: int,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        retry_attempts: int = 4,
        retry_base_delay_s: float = 1.0,
        throttle_source: str | None = None,
    ) -> dict[str, Any]:
        session, owns_session = self._session_or_new()
        try:
            def _do() -> dict[str, Any]:
                throttle_external_request(source=(throttle_source or self.source))
                resp = session.request(
                    method.upper(),
                    url,
                    params=params,
                    data=data,
                    json=json_body,
                    headers=headers,
                    timeout=timeout_s,
                )
                resp.raise_for_status()
                payload = resp.json() if resp.content else {}
                if not isinstance(payload, dict):
                    raise RuntimeError("Unexpected non-object JSON response")
                return payload

            retry_fn = self._retry_fn or retry_with_backoff
            return retry_fn(
                _do,
                max_attempts=max(1, retry_attempts),
                base_delay=max(0.1, retry_base_delay_s),
            )
        finally:
            if owns_session:
                session.close()

    def request_text(
        self,
        *,
        method: str,
        url: str,
        timeout_s: int,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        retry_attempts: int = 4,
        retry_base_delay_s: float = 1.0,
        throttle_source: str | None = None,
    ) -> str:
        session, owns_session = self._session_or_new()
        try:
            def _do() -> str:
                throttle_external_request(source=(throttle_source or self.source))
                resp = session.request(
                    method.upper(),
                    url,
                    params=params,
                    data=data,
                    json=json_body,
                    headers=headers,
                    timeout=timeout_s,
                )
                resp.raise_for_status()
                return resp.text

            retry_fn = self._retry_fn or retry_with_backoff
            return retry_fn(
                _do,
                max_attempts=max(1, retry_attempts),
                base_delay=max(0.1, retry_base_delay_s),
            )
        finally:
            if owns_session:
                session.close()

def get_feed_proxies(*, source: str) -> dict[str, str] | None:
    suffix = _source_env_suffix(source)
    proxy_settings = get_proxy_settings()
    all_proxy = str(get_runtime_env(f"FEED_PROXY_URL_{suffix}", "") or "").strip()
    http_proxy = str(get_runtime_env(f"FEED_HTTP_PROXY_{suffix}", "") or "").strip() or all_proxy or proxy_settings.http_url
    https_proxy = str(get_runtime_env(f"FEED_HTTPS_PROXY_{suffix}", "") or "").strip() or all_proxy or proxy_settings.https_url
    proxies: dict[str, str] = {}
    if http_proxy:
        proxies["http"] = http_proxy
    if https_proxy:
        proxies["https"] = https_proxy
    return proxies or None


def retry_with_backoff(fn: Callable[[], T], *, max_attempts: int = 6, base_delay: float = 1.0, max_delay: float = 30.0, jitter: float = 0.2) -> T:
    """Exponential backoff with jitter for transient failures."""
    retriable_4xx = {408, 425, 429}

    def _should_retry(exc: Exception) -> bool:
        if isinstance(exc, HTTPError):
            response = getattr(exc, "response", None)
            status = getattr(response, "status_code", None)
            if isinstance(status, int) and (400 <= status < 500) and status not in retriable_4xx:
                return False
        return True

    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except Exception as e:
            if not _should_retry(e):
                raise
            if attempt >= max_attempts:
                raise
            sleep = min(max_delay, base_delay * (2 ** (attempt - 1)))
            # Additive jitter only extends wait time (never shortens below base backoff).
            delta = sleep * jitter
            sleep = max(0.1, sleep + random.uniform(0, delta))
            extra = {"attempt": attempt, "sleep_s": round(sleep, 3), "error": str(e), "error_type": e.__class__.__name__}
            extra["error"] = redact_proxy_credentials(str(extra.get("error", "")))
            if isinstance(e, ProxyError):
                extra["network_hint"] = "proxy_error"
            elif isinstance(e, SSLError):
                extra["network_hint"] = "tls_error"
            elif isinstance(e, (ConnectTimeout, ReadTimeout)):
                extra["network_hint"] = "timeout"
            elif isinstance(e, RequestsConnectionError):
                extra["network_hint"] = "connection_error"
            logger.warning("retry_backoff", extra=extra)
            time.sleep(sleep)


def standardized_update_result(
    *,
    fetched: int = 0,
    deactivated: int = 0,
    errors: int = 0,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "fetched": max(0, int(fetched or 0)),
        "deactivated": max(0, int(deactivated or 0)),
        "errors": max(0, int(errors or 0)),
        "details": details or {},
    }


def sum_update_result(data: Any) -> dict[str, Any]:
    fetched = 0
    deactivated = 0
    errors = 0

    def _walk(node: Any) -> None:
        nonlocal fetched, deactivated, errors
        if isinstance(node, dict):
            got_any = False
            if "fetched" in node:
                got_any = True
                try:
                    fetched_val = int(node.get("fetched", 0) or 0)
                    if fetched_val > 0:
                        fetched += fetched_val
                except Exception:
                    pass
            if "deactivated" in node:
                got_any = True
                try:
                    deactivated_val = int(node.get("deactivated", 0) or 0)
                    if deactivated_val > 0:
                        deactivated += deactivated_val
                except Exception:
                    pass
            if "errors" in node:
                got_any = True
                try:
                    err_val = int(node.get("errors", 0) or 0)
                    if err_val > 0:
                        errors += err_val
                except Exception:
                    pass
            if got_any:
                return
            for value in node.values():
                _walk(value)
            return
        if isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    return standardized_update_result(fetched=fetched, deactivated=deactivated, errors=errors, details={})
