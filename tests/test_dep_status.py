from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestDepStatusCacheExtended:

    def test_dep_status_cache_get_unknown_key(self):
        from app.services.common import DepStatusCache
        cache = DepStatusCache()
        result = cache.get("nonexistent_service")
        assert result is None or isinstance(result, dict)

    def test_dep_status_cache_update_then_get(self):
        from app.services.common import DepStatusCache
        cache = DepStatusCache()
        cache.update("test_svc", "ok", duration_ms=10)
        result = cache.get("test_svc")
        assert result is not None
        assert result["status"] == "ok"

    def test_dep_status_cache_all_statuses(self):
        from app.services.common import DepStatusCache
        cache = DepStatusCache()
        cache.update("svc_a", "ok", duration_ms=5)
        cache.update("svc_b", "down", error="conn refused")
        all_statuses = cache.get_all()
        assert "svc_a" in all_statuses
        assert "svc_b" in all_statuses

    def test_dep_status_cache_invalid_status_becomes_unknown(self):
        from app.services.common import DepStatusCache
        cache = DepStatusCache()
        cache.update("svc_x", "completely_invalid_status")
        result = cache.get("svc_x")
        assert result["status"] == "unknown"

    def test_dep_status_cache_error_cleared_on_ok(self):
        from app.services.common import DepStatusCache
        cache = DepStatusCache()
        cache.update("svc_y", "down", error="timeout")
        cache.update("svc_y", "ok")
        result = cache.get("svc_y")
        assert result["last_error"] is None
