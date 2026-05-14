from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestServicesCommonCoverage:

    def test_retry_with_backoff_success_on_first(self):
        from app.services.common import retry_with_backoff
        called = []
        def fn():
            called.append(1)
            return "ok"
        result = retry_with_backoff(fn, max_attempts=3, base_delay=0.01)
        assert result == "ok"
        assert len(called) == 1

    def test_retry_with_backoff_retries_on_failure(self):
        from app.services.common import retry_with_backoff
        attempts = []
        def fn():
            attempts.append(1)
            if len(attempts) < 3:
                raise ConnectionError("retry me")
            return "done"
        result = retry_with_backoff(fn, max_attempts=3, base_delay=0.01)
        assert result == "done"
        assert len(attempts) == 3

    def test_retry_with_backoff_raises_after_max(self):
        from app.services.common import retry_with_backoff
        def fn():
            raise RuntimeError("always fails")
        with pytest.raises(RuntimeError):
            retry_with_backoff(fn, max_attempts=2, base_delay=0.01)

    def test_standardized_update_result_shape(self):
        from app.services.common import standardized_update_result
        result = standardized_update_result(fetched=10, deactivated=2, errors=1, details={"key": "val"})
        assert result["fetched"] == 10
        assert result["deactivated"] == 2
        assert result["errors"] == 1
        assert result["details"]["key"] == "val"

    def test_sum_update_result(self):
        from app.services.common import sum_update_result
        data = [
            {"fetched": 5, "deactivated": 1, "errors": 0},
            {"fetched": 3, "deactivated": 2, "errors": 1},
        ]
        result = sum_update_result(data)
        assert result["fetched"] == 8
        assert result["deactivated"] == 3
        assert result["errors"] == 1

    def test_dep_status_cache_update_and_get(self):
        from app.services.common import DepStatusCache
        cache = DepStatusCache()
        cache.update("misp", "ok", duration_ms=100)
        entry = cache.get_all()
        assert "misp" in entry
        assert entry["misp"]["status"] == "ok"

    def test_dep_status_cache_invalid_status_mapped_to_unknown(self):
        from app.services.common import DepStatusCache
        cache = DepStatusCache()
        cache.update("src", "invalid_status")
        entry = cache.get("src")
        assert entry["status"] == "unknown"

    def test_dep_status_cache_get_missing_returns_unknown(self):
        from app.services.common import DepStatusCache
        cache = DepStatusCache()
        entry = cache.get("nonexistent")
        assert entry["status"] == "unknown"

    def test_external_feed_rate_limiter_allows_within_limit(self):
        from app.services.common import ExternalFeedRateLimiter
        limiter = ExternalFeedRateLimiter(per_second=100, per_minute=6000)
        # Should complete without sleeping too long
        limiter.acquire(source="test")

    def test_external_feed_rate_limiter_zero_limits(self):
        from app.services.common import ExternalFeedRateLimiter
        limiter = ExternalFeedRateLimiter(per_second=0, per_minute=0)
        limiter.acquire(source="test")  # Should immediately return
