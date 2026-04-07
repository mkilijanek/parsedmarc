from __future__ import annotations

from typing import Any

import requests

from .cache import get_redis
from .db import SessionLocal
from .factory import _aggregate_fetched_count
from .services.correlation import query_correlations


def _sync_factory_globals() -> None:
    # Keep compatibility with tests and runtime lookups that patch app.main symbols.
    from . import factory as _factory

    _factory.requests = requests
    _factory.get_redis = get_redis
    _factory.SessionLocal = SessionLocal
    _factory.query_correlations = query_correlations


def create_app(*args: Any, **kwargs: Any):
    from .factory import create_app as _create_app

    _sync_factory_globals()
    return _create_app(*args, **kwargs)


__all__ = [
    "SessionLocal",
    "_aggregate_fetched_count",
    "create_app",
    "get_redis",
    "query_correlations",
    "requests",
]
