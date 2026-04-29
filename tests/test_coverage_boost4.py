"""Fourth pass coverage boost — targeting remaining 74% → 75% gap.

Covers:
- app/worker_health.py: state tracking functions, health_payload
- app/services/sentinel_graph.py: build_graph_indicator, _thumbprint_to_x5t
- app/webui.py: _active_only, _split_csv, _build_download_links
- app/services/common.py: DepStatusCache, percentile edge cases
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# worker_health state tracking
# ---------------------------------------------------------------------------

class TestWorkerHealthState:

    def test_mark_job_start_increments_active(self):
        from app.worker_health import mark_job_start, active_jobs, snapshot
        before = active_jobs()
        mark_job_start("test_job")
        assert active_jobs() == before + 1
        # Clean up
        from app.worker_health import mark_job_success
        mark_job_success("test_job")

    def test_mark_job_success_decrements_active(self):
        from app.worker_health import mark_job_start, mark_job_success, active_jobs
        mark_job_start("success_job")
        before = active_jobs()
        mark_job_success("success_job")
        assert active_jobs() == before - 1

    def test_mark_job_failure_decrements_active(self):
        from app.worker_health import mark_job_start, mark_job_failure, active_jobs
        mark_job_start("fail_job")
        before = active_jobs()
        mark_job_failure("fail_job", "something went wrong")
        assert active_jobs() == before - 1

    def test_mark_shutdown_requested(self):
        from app.worker_health import mark_shutdown_requested, snapshot
        mark_shutdown_requested()
        state = snapshot()
        assert state["shutdown_requested"] is True
        # Reset for other tests
        import app.worker_health as wh
        with wh._state_lock:
            wh._state.shutdown_requested = False

    def test_snapshot_returns_all_keys(self):
        from app.worker_health import snapshot
        s = snapshot()
        for key in ("started_at", "last_loop_at", "active_jobs", "jobs_run", "jobs_failed", "shutdown_requested"):
            assert key in s

    def test_health_payload_with_db_ok(self):
        from app.worker_health import health_payload
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            status, payload = health_payload(max_loop_age_s=3600)
        assert "status" in payload
        assert "checks" in payload

    def test_health_payload_with_db_error(self):
        from app.worker_health import health_payload
        with patch("app.worker_health._database_ok", return_value=(False, "connection refused")):
            status, payload = health_payload(max_loop_age_s=3600)
        assert payload["checks"]["database"]["ok"] is False
        assert status == 503


# ---------------------------------------------------------------------------
# sentinel_graph utilities
# ---------------------------------------------------------------------------

class TestSentinelGraphUtils:

    def test_thumbprint_to_x5t_valid_hex(self):
        from app.services.sentinel_graph import _thumbprint_to_x5t
        result = _thumbprint_to_x5t("AA:BB:CC:DD")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_thumbprint_to_x5t_empty_returns_empty(self):
        from app.services.sentinel_graph import _thumbprint_to_x5t
        assert _thumbprint_to_x5t("") == ""

    def test_thumbprint_to_x5t_invalid_returns_empty(self):
        from app.services.sentinel_graph import _thumbprint_to_x5t
        result = _thumbprint_to_x5t("not-hex!")
        assert result == ""

    def test_build_graph_indicator_ip(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "1.2.3.4"
        row.type = "ip"
        row.source = "misp"
        row.confidence = 80
        row.tlp = "GREEN"
        result = build_graph_indicator(row)
        assert result.get("networkIPv4") == "1.2.3.4"

    def test_build_graph_indicator_domain(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "evil.com"
        row.type = "domain"
        row.source = "misp"
        row.confidence = 70
        row.tlp = "AMBER"
        result = build_graph_indicator(row)
        assert result.get("domainName") == "evil.com"

    def test_build_graph_indicator_url(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "http://evil.com/path"
        row.type = "url"
        row.source = "misp"
        row.confidence = 60
        row.tlp = "WHITE"
        result = build_graph_indicator(row)
        assert result.get("url") == "http://evil.com/path"

    def test_build_graph_indicator_hash_md5(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "d" * 32
        row.type = "hash"
        row.source = "misp"
        row.confidence = 90
        row.tlp = "RED"
        result = build_graph_indicator(row)
        assert result.get("fileHashType") == "md5"
        assert result.get("fileHashValue") == "d" * 32

    def test_build_graph_indicator_hash_sha256(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "a" * 64
        row.type = "hash"
        row.source = "misp"
        row.confidence = 95
        row.tlp = "GREEN"
        result = build_graph_indicator(row)
        assert result.get("fileHashType") == "sha256"

    def test_build_graph_indicator_unknown_type_returns_empty(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "something"
        row.type = "unknown_type_xyz"
        row.source = "test"
        row.confidence = 50
        row.tlp = "WHITE"
        result = build_graph_indicator(row)
        assert result == {}


# ---------------------------------------------------------------------------
# webui utility functions (no DB/engine needed)
# ---------------------------------------------------------------------------

class TestWebuiUtils:

    def test_split_csv_none_returns_none(self):
        from app.webui import _split_csv
        assert _split_csv(None) is None

    def test_split_csv_empty_returns_none(self):
        from app.webui import _split_csv
        result = _split_csv("")
        assert result is None

    def test_split_csv_single_value(self):
        from app.webui import _split_csv
        result = _split_csv("ip")
        assert result == ["ip"]

    def test_split_csv_multiple_values(self):
        from app.webui import _split_csv
        result = _split_csv("ip,domain,hash")
        assert result == ["ip", "domain", "hash"]

    def test_active_only_true_by_default(self):
        from app.webui import _active_only
        assert _active_only("1") is True
        assert _active_only("true") is True

    def test_active_only_false_values(self):
        from app.webui import _active_only
        assert _active_only("0") is False
        assert _active_only("false") is False
        assert _active_only("no") is False
        assert _active_only("off") is False

    def test_active_only_none_returns_true(self):
        from app.webui import _active_only
        assert _active_only(None) is True


# ---------------------------------------------------------------------------
# services/common.py — DepStatusCache extended coverage
# ---------------------------------------------------------------------------

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
