from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Iterator, Mapping


@dataclass(frozen=True)
class ProxySettings:
    http_url: str = ""
    https_url: str = ""
    no_proxy: str = ""
    ca_bundle_path: str = ""
    skip_tls_verify: bool = False


_RUNTIME_ENV_OVERRIDES: ContextVar[dict[str, str | None]] = ContextVar("runtime_env_overrides", default={})
_PROXY_SETTINGS_LOCK = threading.Lock()
_PROXY_SETTINGS = ProxySettings()


def get_runtime_env(name: str, default: str | None = None) -> str | None:
    overrides = _RUNTIME_ENV_OVERRIDES.get()
    if name in overrides:
        value = overrides[name]
        return default if value is None else str(value)
    return os.getenv(name, default)


@contextmanager
def push_runtime_env_overrides(values: Mapping[str, str | None]) -> Iterator[None]:
    current = dict(_RUNTIME_ENV_OVERRIDES.get())
    merged = dict(current)
    for key, value in values.items():
        merged[str(key)] = None if value is None else str(value)
    token: Token[dict[str, str | None]] = _RUNTIME_ENV_OVERRIDES.set(merged)
    try:
        yield
    finally:
        _RUNTIME_ENV_OVERRIDES.reset(token)


def clear_runtime_env_overrides() -> None:
    _RUNTIME_ENV_OVERRIDES.set({})


def update_proxy_settings_from_mapping(values: Mapping[str, object]) -> ProxySettings:
    proxy_settings = ProxySettings(
        http_url=str(values.get("proxy.http_url") or "").strip(),
        https_url=str(values.get("proxy.https_url") or "").strip(),
        no_proxy=str(values.get("proxy.no_proxy") or "").strip(),
        ca_bundle_path=str(values.get("proxy.ca_bundle_path") or "").strip(),
        skip_tls_verify=str(values.get("proxy.skip_tls_verify") or "").strip().lower() in {"1", "true", "yes", "on"},
    )
    with _PROXY_SETTINGS_LOCK:
        global _PROXY_SETTINGS
        _PROXY_SETTINGS = proxy_settings
    return proxy_settings


def get_proxy_settings() -> ProxySettings:
    with _PROXY_SETTINGS_LOCK:
        return _PROXY_SETTINGS

