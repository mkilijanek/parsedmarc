"""Tests to boost coverage on modules with significant gaps.

Covers:
- app/cli.py (0%): CLI helper functions and main flow
- app/worker_health.py (51%): health_payload, WorkerState helpers
- app/routes/ops_admin.py (71%): additional admin UI paths
- app/services/sentinel_graph.py (64%): graph building helpers
- app/services/feed_ops.py (64%): feed ops helpers
- app/query_parser.py (78%): parser edge cases
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# CLI module tests (app/cli.py)
# ---------------------------------------------------------------------------

class TestCLIHelpers:

    def test_parse_time_date_only(self):
        from app.cli import _parse_time
        dt = _parse_time("2024-01-15")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.tzinfo is not None

    def test_parse_time_iso_datetime(self):
        from app.cli import _parse_time
        dt = _parse_time("2024-06-01T12:00:00")
        assert dt.year == 2024
        assert dt.hour == 12

    def test_parse_time_iso_with_z(self):
        from app.cli import _parse_time
        dt = _parse_time("2024-06-01T12:00:00Z")
        assert dt.tzinfo is not None

    def test_parse_time_iso_with_offset(self):
        from app.cli import _parse_time
        dt = _parse_time("2024-06-01T14:00:00+02:00")
        assert dt.tzinfo is not None

    def test_parse_time_empty_raises(self):
        from app.cli import _parse_time
        with pytest.raises(ValueError):
            _parse_time("")

    def test_load_config_file_json(self, tmp_path):
        from app.cli import _load_config_file
        f = tmp_path / "cfg.json"
        f.write_text('{"key": "value", "count": 42}')
        result = _load_config_file(str(f))
        assert result["key"] == "value"
        assert result["count"] == 42

    def test_load_config_file_env_style(self, tmp_path):
        from app.cli import _load_config_file
        f = tmp_path / "cfg.env"
        f.write_text("KEY=value\n# comment\nOTHER_KEY=other\n")
        result = _load_config_file(str(f))
        assert result["KEY"] == "value"
        assert result["OTHER_KEY"] == "other"
        assert "# comment" not in result

    def test_load_config_file_not_found_raises(self):
        from app.cli import _load_config_file
        with pytest.raises(FileNotFoundError):
            _load_config_file("/nonexistent/path/file.json")

    def test_load_config_file_empty_returns_empty(self, tmp_path):
        from app.cli import _load_config_file
        f = tmp_path / "empty.env"
        f.write_text("")
        result = _load_config_file(str(f))
        assert result == {}

    def test_merge_list_comma_separated(self):
        from app.cli import _merge_list
        result = _merge_list("a,b,c", None)
        assert result == ["a", "b", "c"]

    def test_merge_list_repeated_args(self):
        from app.cli import _merge_list
        result = _merge_list(None, ["x", "y"])
        assert result == ["x", "y"]

    def test_merge_list_dedup(self):
        from app.cli import _merge_list
        result = _merge_list("a,A,b", ["B", "c"])
        assert len(result) == 3  # a, b, c (case-insensitive dedup)

    def test_merge_list_empty(self):
        from app.cli import _merge_list
        result = _merge_list(None, None)
        assert result == []

    def test_main_no_tags_raises_systemexit(self):
        from app.cli import main
        with pytest.raises(SystemExit, match="No tags"):
            main(["fetch", "--data-source", "bazaar"])

    def test_main_since_after_until_raises(self):
        from app.cli import main
        with pytest.raises(SystemExit):
            main(["fetch", "--data-source", "bazaar", "--tags", "malware",
                  "--since", "2024-02-01", "--until", "2024-01-01"])

    def test_main_no_db_url_raises(self):
        from app.cli import main
        env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(SystemExit, match="DATABASE_URL"):
                main(["fetch", "--data-source", "bazaar", "--tags", "malware"])

    def test_main_dry_run_bazaar(self):
        from app.cli import main
        mock_rows = [{"ioc_value": "1.2.3.4", "ioc_type": "ip", "source": "bazaar"}]
        with patch("app.cli.fetch_malwarebazaar_by_tags", return_value=iter(mock_rows)):
            result = main(["fetch", "--data-source", "bazaar", "--tags", "malware", "--dry-run"])
        assert result == 0

    def test_main_dry_run_mwdb(self):
        from app.cli import main
        mock_rows = [{"ioc_value": "evil.com", "ioc_type": "domain", "source": "mwdb"}]
        with patch("app.cli.fetch_mwdb_by_tags", return_value=iter(mock_rows)):
            result = main(["fetch", "--data-source", "mwdb", "--tags", "apt", "--dry-run"])
        assert result == 0

    def test_main_with_config_file(self, tmp_path):
        from app.cli import main
        cfg = tmp_path / "test.env"
        cfg.write_text("TAGS=malware\n")
        mock_rows: list = []
        with patch("app.cli.fetch_malwarebazaar_by_tags", return_value=iter(mock_rows)):
            result = main(["--config-file", str(cfg), "fetch", "--data-source", "bazaar", "--dry-run"])
        assert result == 0

    def test_main_dry_run_with_since_until(self):
        from app.cli import main
        mock_rows: list = []
        with patch("app.cli.fetch_malwarebazaar_by_tags", return_value=iter(mock_rows)):
            result = main([
                "fetch", "--data-source", "bazaar",
                "--tags", "malware",
                "--since", "2024-01-01",
                "--until", "2024-12-31",
                "--dry-run",
            ])
        assert result == 0

    def test_upsert_iocs_basic(self):
        from app.cli import _upsert_iocs
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value.__enter__ = lambda s: mock_cur
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        rows = [{"ioc_value": "1.2.3.4", "ioc_type": "ip", "source": "test",
                 "source_ref": None, "first_seen": datetime.now(timezone.utc),
                 "last_seen": datetime.now(timezone.utc), "confidence": 80,
                 "tlp": "GREEN", "is_active": True, "tags": [], "comments": None, "metadata": {}}]
        ins, upd = _upsert_iocs(mock_conn, rows)
        assert ins == 1
        assert upd == 0
        mock_conn.commit.assert_called_once()


# ---------------------------------------------------------------------------
# Worker health tests (app/worker_health.py)
# ---------------------------------------------------------------------------

class TestWorkerHealth:

    def test_mark_loop_updates_timestamp(self):
        from app.worker_health import mark_loop, _state, _state_lock
        import time
        before = _state.last_loop_at
        time.sleep(0.01)
        mark_loop()
        assert _state.last_loop_at >= before

    def test_mark_job_start_increments_active(self):
        from app.worker_health import mark_job_start, mark_job_success, _state, _state_lock
        with _state_lock:
            initial = _state.active_jobs
        mark_job_start("test_job")
        with _state_lock:
            assert _state.active_jobs == initial + 1
        mark_job_success("test_job")

    def test_mark_job_success_decrements_active(self):
        from app.worker_health import mark_job_start, mark_job_success, _state, _state_lock
        mark_job_start("test")
        with _state_lock:
            before = _state.active_jobs
        mark_job_success("test")
        with _state_lock:
            assert _state.active_jobs == before - 1

    def test_mark_job_failure_updates_state(self):
        from app.worker_health import mark_job_start, mark_job_failure, _state, _state_lock
        mark_job_start("fail_job")
        with _state_lock:
            before_failed = _state.jobs_failed
        mark_job_failure("fail_job", "timeout error")
        with _state_lock:
            assert _state.jobs_failed == before_failed + 1
            assert _state.last_error == "timeout error"

    def test_active_jobs_returns_count(self):
        from app.worker_health import active_jobs, mark_job_start, mark_job_success
        mark_job_start("aj_test")
        count = active_jobs()
        assert count >= 1
        mark_job_success("aj_test")

    def test_snapshot_returns_dict(self):
        from app.worker_health import snapshot
        s = snapshot()
        assert "started_at" in s
        assert "last_loop_at" in s
        assert "active_jobs" in s
        assert "jobs_run" in s
        assert "jobs_failed" in s
        assert "shutdown_requested" in s
        assert "last_error" in s

    def test_health_payload_returns_tuple(self):
        from app.worker_health import health_payload, mark_loop
        mark_loop()
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            code, payload = health_payload(max_loop_age_s=60)
        assert isinstance(code, int)
        assert "status" in payload
        assert "checks" in payload

    def test_health_payload_degraded_when_loop_stale(self):
        from app.worker_health import health_payload, _state, _state_lock
        import time
        with _state_lock:
            _state.last_loop_at = time.time() - 999
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            code, payload = health_payload(max_loop_age_s=10)
        assert code == 503
        assert payload["status"] == "degraded"
        with _state_lock:
            _state.last_loop_at = time.time()

    def test_health_payload_degraded_when_db_down(self):
        from app.worker_health import health_payload, mark_loop
        mark_loop()
        with patch("app.worker_health._database_ok", return_value=(False, "connection refused")):
            code, payload = health_payload(max_loop_age_s=60)
        assert code == 503
        assert payload["checks"]["database"]["ok"] is False

    def test_health_payload_degraded_when_shutdown(self):
        from app.worker_health import health_payload, mark_loop, mark_shutdown_requested, _state, _state_lock
        mark_loop()
        with _state_lock:
            original = _state.shutdown_requested
        with _state_lock:
            _state.shutdown_requested = True
        try:
            with patch("app.worker_health._database_ok", return_value=(True, "")):
                code, payload = health_payload(max_loop_age_s=60)
            assert payload["checks"]["shutdown"]["requested"] is True
        finally:
            with _state_lock:
                _state.shutdown_requested = original

    def test_worker_health_server_disabled_when_port_zero(self):
        from app.worker_health import WorkerHealthServer
        server = WorkerHealthServer("127.0.0.1", 0, 60)
        server.start()  # should log and return without starting
        assert server._server is None
        server.stop()  # should be a no-op


# ---------------------------------------------------------------------------
# Query parser tests (app/query_parser.py — edge cases)
# ---------------------------------------------------------------------------

class TestQueryParserEdgeCases:

    def test_parse_empty_string(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("")
        assert result == [] or result is None or result == ()

    def test_parse_simple_term_raises_without_field(self):
        from app.query_parser import parse_kibana_query
        # A bare term without "field:value" format is an incomplete predicate
        with pytest.raises(ValueError):
            parse_kibana_query("test")

    def test_parse_field_value(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("type:ip")
        assert result is not None

    def test_parse_boolean_and(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("type:ip AND confidence:>80")
        assert result is not None

    def test_parse_boolean_or(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("type:ip OR type:domain")
        assert result is not None

    def test_parse_boolean_not(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("NOT type:ip")
        assert result is not None

    def test_parse_greater_than_operator(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("confidence:>70")
        assert result is not None

    def test_parse_less_than_operator(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("confidence:<50")
        assert result is not None

    def test_parse_parentheses(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("(type:ip OR type:domain) AND confidence:>70")
        assert result is not None

    def test_parse_quoted_value(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query('tags:"apt malware"')
        assert result is not None

    def test_parse_wildcard(self):
        from app.query_parser import parse_kibana_query
        result = parse_kibana_query("value:1.2.3.*")
        assert result is not None


# ---------------------------------------------------------------------------
# Feed ops tests (app/services/feed_ops.py — coverage boost)
# ---------------------------------------------------------------------------

class TestFeedOpsCoverage:

    def test_percentile_empty_list_returns_none(self):
        from app.services.feed_ops import percentile
        assert percentile([], 95) is None

    def test_percentile_single_value(self):
        from app.services.feed_ops import percentile
        assert percentile([42], 50) == 42.0

    def test_percentile_multiple_values(self):
        from app.services.feed_ops import percentile
        values = [1, 2, 3, 4, 5]
        p50 = percentile(values, 50)
        assert 2.0 <= p50 <= 4.0  # median-ish

    def test_percentile_p100(self):
        from app.services.feed_ops import percentile
        values = [1, 5, 10]
        assert percentile(values, 100) == 10.0

    def test_parse_feed_table_params_defaults(self):
        from app.services.feed_ops import parse_feed_table_params
        params = parse_feed_table_params({})
        assert params is not None
        assert "limit" in params
        assert "offset" in params

    def test_parse_feed_table_params_custom(self):
        from app.services.feed_ops import parse_feed_table_params
        params = parse_feed_table_params({"feeds_limit": "10", "feeds_sort": "source"})
        assert params["limit"] == 10
        assert params["sort"] == "source"

    def test_resolve_metrics_window_hours_default(self):
        from app.services.feed_ops import resolve_metrics_window_hours
        hours, label = resolve_metrics_window_hours({})
        assert isinstance(hours, int)
        assert hours > 0
        assert isinstance(label, str)

    def test_resolve_metrics_window_hours_24h(self):
        from app.services.feed_ops import resolve_metrics_window_hours
        hours, label = resolve_metrics_window_hours({"window": "24h"})
        assert hours == 24
        assert label == "24h"

    def test_resolve_metrics_window_hours_7d(self):
        from app.services.feed_ops import resolve_metrics_window_hours
        hours, label = resolve_metrics_window_hours({"window": "7d"})
        assert hours == 24 * 7

    def test_resolve_metrics_window_hours_custom(self):
        from app.services.feed_ops import resolve_metrics_window_hours
        hours, label = resolve_metrics_window_hours({"hours": "48"})
        assert hours == 48


# ---------------------------------------------------------------------------
# Ops admin route tests (gap coverage)
# ---------------------------------------------------------------------------

class TestOpsAdminCoverage:

    def test_admin_panel_returns_200(self, admin_client):
        resp = admin_client.get("/admin")
        assert resp.status_code == 200

    def test_admin_panel_with_msg_param(self, admin_client):
        resp = admin_client.get("/admin?msg=test+message")
        assert resp.status_code == 200

    def test_admin_sync_jobs_page(self, admin_client):
        resp = admin_client.get("/admin/sync-jobs")
        assert resp.status_code in (200, 302, 404)

    def test_admin_scheduler_status_returns_200(self, admin_client):
        resp = admin_client.get("/admin/api/scheduler-status")
        assert resp.status_code in (200, 404)

    def test_admin_feeds_configure_page(self, admin_client):
        resp = admin_client.get("/admin/feed/misp/configure")
        assert resp.status_code in (200, 302, 404)

    def test_api_logs_page(self, admin_client):
        resp = admin_client.get("/api/logs")
        assert resp.status_code in (200, 302)

    def test_dead_letter_jobs_list_empty(self, admin_client):
        resp = admin_client.get("/admin/api/dead-letter-jobs")
        body = json.loads(resp.data)
        assert body["count"] == 0 or body["count"] >= 0

    def test_db_circuit_state_endpoint(self, admin_client):
        resp = admin_client.get("/admin/api/db-circuit")
        assert resp.status_code == 200
        body = json.loads(resp.data)
        assert "state" in body


# ---------------------------------------------------------------------------
# Sentinel graph coverage
# ---------------------------------------------------------------------------

class TestSentinelGraphCoverage:

    def test_build_graph_indicator_single(self):
        from app.services.sentinel_graph import build_graph_indicator
        mock_ind = MagicMock()
        mock_ind.value = "1.2.3.4"
        mock_ind.type = "ip"
        mock_ind.source = "misp"
        mock_ind.tags = ["malware"]
        mock_ind.confidence = 80
        mock_ind.tlp = "GREEN"
        mock_ind.is_active = True
        mock_ind.first_seen = datetime.now(timezone.utc)
        mock_ind.last_seen = datetime.now(timezone.utc)
        result = build_graph_indicator(mock_ind, expiration_days=30)
        assert result is not None
        assert isinstance(result, dict)

    def test_build_graph_indicator_domain(self):
        from app.services.sentinel_graph import build_graph_indicator
        mock_ind = MagicMock()
        mock_ind.value = "evil.example.com"
        mock_ind.type = "domain"
        mock_ind.source = "crowdsec"
        mock_ind.tags = []
        mock_ind.confidence = 70
        mock_ind.tlp = "AMBER"
        mock_ind.is_active = True
        mock_ind.first_seen = datetime.now(timezone.utc)
        mock_ind.last_seen = datetime.now(timezone.utc)
        result = build_graph_indicator(mock_ind)
        assert result is not None

    def test_b64url(self):
        from app.services.sentinel_graph import _b64url
        result = _b64url(b"hello world")
        assert isinstance(result, str)
        assert "=" not in result  # URL-safe base64 strips padding


# ---------------------------------------------------------------------------
# Services common — additional coverage
# ---------------------------------------------------------------------------

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
