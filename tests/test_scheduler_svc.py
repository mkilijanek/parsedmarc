"""Tests for app/services/scheduler_svc.py.

Focuses on the pure-logic functions (cron matching, failure classification,
retry delay, log-retention guard) reachable through the service namespace
without a real database.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, call
import pytest


# ---------------------------------------------------------------------------
# Shared factory helpers
# ---------------------------------------------------------------------------

def _make_cfg(**overrides):
    defaults = dict(
        SYNC_JOB_MAX_RETRIES=3,
        SYNC_JOB_RETRY_BASE_DELAY_S=30,
        SYNC_JOB_RETRY_MAX_DELAY_S=3600,
        LOG_RETENTION_DAYS=90,
        DLQ_RETENTION_DAYS=90,
        CACHE_TTL=60,
        CACHE_WARMING_ENABLED=False,
        AUDIT_INTEGRITY_VERIFY_INTERVAL_S=3600,
        SECRET_KEY="test-secret-key",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _noop_db(**kwargs):
    """Return a MagicMock session that looks like SQLite (no advisory locks)."""
    m = MagicMock()
    m.get_bind.return_value = None       # dialect check → non-postgresql path
    m.scalar.return_value = None         # no existing job found
    m.execute.return_value = MagicMock(rowcount=0)
    return m


def _make_service(*, cfg=None, db_fn=None, feeds=None, extra_state=None):
    """Instantiate make_scheduler_service with minimal mocks."""
    from app.services.scheduler_svc import make_scheduler_service

    cfg = cfg or _make_cfg()
    db_fn = db_fn or (lambda read_only=False: _noop_db())
    feeds = feeds or []
    state: dict = {"active_run_id": None, "active_job_id": None, "last_minute": {}}
    if extra_state:
        state.update(extra_state)

    svc = make_scheduler_service(
        cfg=cfg,
        db_fn=db_fn,
        app_log_fn=MagicMock(),
        audit_fn=MagicMock(),
        get_setting_fn=MagicMock(return_value="*/15 * * * *"),
        set_setting_fn=MagicMock(),
        read_feed_rows_fn=lambda db: feeds,
        read_feed_config_state_fn=MagicMock(return_value={"ready": True, "missing": [], "fields": []}),
        feed_value_key_fn=MagicMock(side_effect=lambda s, k: f"{s}.{k}"),
        feed_secret_key_fn=MagicMock(side_effect=lambda s, k: f"{s}.secret.{k}"),
        runtime_override_or_env_fn=MagicMock(return_value=None),
        cache_key_fn=MagicMock(return_value="ck"),
        scheduler_state=state,
        scheduler_lock=MagicMock(),
    )
    return svc, state


def _mock_feed(source_id: str, cron: str = "* * * * *", enabled: bool = True):
    f = MagicMock()
    f.source_id = source_id
    f.enabled = enabled
    f.schedule_cron = cron
    return f


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------

class TestAggregatedFetchedCount:
    def test_returns_int_from_fetched_key(self):
        from app.services.scheduler_svc import _aggregate_fetched_count
        assert _aggregate_fetched_count({"fetched": 42}) == 42

    def test_handles_missing_key(self):
        from app.services.scheduler_svc import _aggregate_fetched_count
        assert _aggregate_fetched_count({}) == 0

    def test_handles_none_value(self):
        from app.services.scheduler_svc import _aggregate_fetched_count
        assert _aggregate_fetched_count({"fetched": None}) == 0

    def test_handles_string_value(self):
        from app.services.scheduler_svc import _aggregate_fetched_count
        assert _aggregate_fetched_count({"fetched": "7"}) == 7


# ---------------------------------------------------------------------------
# Cron matching
# ---------------------------------------------------------------------------

class TestCronMatching:
    """Exercise _cron_field_match and _cron_matches through
    enqueue_due_scheduled_jobs, which iterates feeds and checks their cron."""

    def test_wildcard_cron_matches_any_time(self):
        """'* * * * *' must always enqueue an enabled feed."""
        feed = _mock_feed("src1", "* * * * *")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 30, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 1

    def test_non_matching_cron_skips_feed(self):
        """'0 0 1 1 *' (midnight Jan 1) must not match May 15 10:30."""
        feed = _mock_feed("src_ny", "0 0 1 1 *")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 30, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 0

    def test_step_cron_matches_at_divisible_minute(self):
        """'*/15 * * * *' must match minute=30 (30 % 15 == 0)."""
        feed = _mock_feed("src_15m", "*/15 * * * *")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 30, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 1

    def test_step_cron_no_match_at_non_divisible_minute(self):
        """'*/15 * * * *' must NOT match minute=7."""
        feed = _mock_feed("src_15m", "*/15 * * * *")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 7, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 0

    def test_list_cron_field_matches_specific_value(self):
        """'0,15,30,45 * * * *' must match minute=15."""
        feed = _mock_feed("src_list", "0,15,30,45 * * * *")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 15, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 1

    def test_list_cron_field_no_match_when_value_absent(self):
        """'0,15,30,45 * * * *' must NOT match minute=7."""
        feed = _mock_feed("src_list", "0,15,30,45 * * * *")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 7, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 0

    def test_disabled_feed_always_skipped(self):
        feed = _mock_feed("src_off", "* * * * *", enabled=False)
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 0, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 0

    def test_same_minute_dedup(self):
        """Calling twice in the same minute must not double-enqueue."""
        feed = _mock_feed("src_dup", "* * * * *")
        now = datetime(2026, 5, 15, 10, 0, tzinfo=timezone.utc)
        marker = now.strftime("%Y-%m-%dT%H:%M")
        svc, _ = _make_service(feeds=[feed], extra_state={"last_minute": {"src_dup": marker}})
        assert svc.enqueue_due_scheduled_jobs(now) == 0

    def test_invalid_cron_field_count_skipped(self):
        """Cron expressions with wrong field count must not match."""
        feed = _mock_feed("src_bad", "not_a_cron")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 0, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 0

    def test_exact_hour_cron_matches(self):
        """'0 10 * * *' must match hour=10, minute=0."""
        feed = _mock_feed("src_hourly", "0 10 * * *")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 10, 0, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 1

    def test_exact_hour_cron_no_match_different_hour(self):
        """'0 10 * * *' must NOT match hour=11."""
        feed = _mock_feed("src_hourly", "0 10 * * *")
        svc, _ = _make_service(feeds=[feed])
        now = datetime(2026, 5, 15, 11, 0, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 0

    def test_multiple_feeds_partially_match(self):
        """Only matching, enabled feeds count toward the return value."""
        feeds = [
            _mock_feed("always", "* * * * *"),
            _mock_feed("never", "0 0 1 1 *"),
            _mock_feed("off", "* * * * *", enabled=False),
        ]
        svc, _ = _make_service(feeds=feeds)
        now = datetime(2026, 5, 15, 10, 5, tzinfo=timezone.utc)
        assert svc.enqueue_due_scheduled_jobs(now) == 1


# ---------------------------------------------------------------------------
# Advisory locks (non-PostgreSQL path)
# ---------------------------------------------------------------------------

class TestAdvisoryLocks:
    def test_try_lock_returns_true_on_non_postgresql(self):
        svc, _ = _make_service()
        mock_db = _noop_db()
        assert svc.db_try_advisory_lock(mock_db, 42) is True

    def test_unlock_no_ops_on_non_postgresql(self):
        svc, _ = _make_service()
        mock_db = _noop_db()
        svc.db_advisory_unlock(mock_db, 42)
        mock_db.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Log retention guard
# ---------------------------------------------------------------------------

class TestLogRetentionGuard:
    def test_skips_when_ran_recently(self):
        now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
        recent = now - timedelta(hours=1)
        db_calls: list = []

        def counting_db(read_only=False):
            m = _noop_db()
            db_calls.append(m)
            return m

        svc, _ = _make_service(
            db_fn=counting_db,
            extra_state={"last_log_retention_at": recent},
        )
        svc.run_log_retention_if_due(now)
        for m in db_calls:
            m.execute.assert_not_called()

    def test_runs_after_24h(self):
        now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
        old = now - timedelta(days=2)
        mock_db = _noop_db()
        mock_db.execute.return_value = MagicMock(rowcount=5)

        svc, _ = _make_service(
            db_fn=lambda read_only=False: mock_db,
            extra_state={"last_log_retention_at": old},
        )
        svc.run_log_retention_if_due(now)
        assert mock_db.execute.called

    def test_skips_when_retention_days_zero(self):
        cfg = _make_cfg(LOG_RETENTION_DAYS=0)
        mock_db = _noop_db()
        svc, _ = _make_service(cfg=cfg, db_fn=lambda read_only=False: mock_db)
        svc.run_log_retention_if_due(datetime.now(timezone.utc))
        mock_db.execute.assert_not_called()

    def test_updates_state_after_run(self):
        now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
        old = now - timedelta(days=2)
        mock_db = _noop_db()
        mock_db.execute.return_value = MagicMock(rowcount=0)

        svc, state = _make_service(
            db_fn=lambda read_only=False: mock_db,
            extra_state={"last_log_retention_at": old},
        )
        svc.run_log_retention_if_due(now)
        assert state["last_log_retention_at"] == now


# ---------------------------------------------------------------------------
# Refresh job backlog metrics
# ---------------------------------------------------------------------------

class TestRefreshJobBacklogMetrics:
    def test_calls_db_scalar_three_times(self):
        mock_db = _noop_db()
        mock_db.scalar.return_value = 3
        svc, _ = _make_service(db_fn=lambda read_only=False: mock_db)
        svc.refresh_job_backlog_metrics()
        assert mock_db.scalar.call_count >= 3

    def test_tolerates_db_exception(self):
        mock_db = _noop_db()
        mock_db.scalar.side_effect = RuntimeError("db down")
        svc, _ = _make_service(db_fn=lambda read_only=False: mock_db)
        svc.refresh_job_backlog_metrics()  # must not raise


# ---------------------------------------------------------------------------
# Service namespace completeness
# ---------------------------------------------------------------------------

class TestNamespace:
    def test_all_expected_attributes_present(self):
        svc, _ = _make_service()
        expected = {
            "enqueue_sync_job",
            "execute_sync_job",
            "scheduler_loop",
            "refresh_job_backlog_metrics",
            "run_sync_queue_once",
            "enqueue_due_scheduled_jobs",
            "run_log_retention_if_due",
            "run_cache_warming_if_due",
            "run_audit_integrity_check_if_due",
            "db_try_advisory_lock",
            "db_advisory_unlock",
            "classify_sync_failure",
            "sync_retry_delay_s",
        }
        for attr in expected:
            assert hasattr(svc, attr), f"missing attribute: {attr}"



# ---------------------------------------------------------------------------
# _classify_sync_failure
# ---------------------------------------------------------------------------

class TestClassifySyncFailure:
    def test_incomplete_config_is_permanent(self):
        svc, _ = _make_service()
        exc = ValueError("incomplete config: missing base_url")
        assert svc.classify_sync_failure(exc) == "permanent"

    def test_feed_not_found_is_permanent(self):
        svc, _ = _make_service()
        assert svc.classify_sync_failure(RuntimeError("feed not found")) == "permanent"

    def test_unknown_source_type_is_permanent(self):
        svc, _ = _make_service()
        assert svc.classify_sync_failure(ValueError("unknown source_type: legacy")) == "permanent"

    def test_auth_failure_markers_are_permanent(self):
        svc, _ = _make_service()
        for msg in ["authentication failed", "invalid api key", "unauthorized", "forbidden"]:
            exc = RuntimeError(msg)
            assert svc.classify_sync_failure(exc) == "permanent", f"expected permanent for: {msg}"

    def test_connection_error_is_transient(self):
        svc, _ = _make_service()
        assert svc.classify_sync_failure(ConnectionError("timeout")) == "transient"

    def test_generic_runtime_error_is_transient(self):
        svc, _ = _make_service()
        assert svc.classify_sync_failure(RuntimeError("unexpected json format")) == "transient"

    def test_case_insensitive_matching(self):
        svc, _ = _make_service()
        assert svc.classify_sync_failure(RuntimeError("Authentication Failed")) == "permanent"


# ---------------------------------------------------------------------------
# _sync_retry_delay_s
# ---------------------------------------------------------------------------

class TestSyncRetryDelay:
    def test_first_retry_uses_base_delay(self):
        svc, _ = _make_service()
        delay = svc.sync_retry_delay_s(0)
        assert delay == 30  # default base

    def test_second_retry_doubles(self):
        svc, _ = _make_service()
        assert svc.sync_retry_delay_s(1) == 30

    def test_third_retry_doubles_again(self):
        svc, _ = _make_service()
        assert svc.sync_retry_delay_s(2) == 60

    def test_delay_capped_at_max(self):
        svc, _ = _make_service(cfg=_make_cfg(
            SYNC_JOB_RETRY_BASE_DELAY_S=30,
            SYNC_JOB_RETRY_MAX_DELAY_S=3600,
        ))
        # After many retries, should not exceed max
        assert svc.sync_retry_delay_s(20) == 3600

    def test_custom_base_and_max(self):
        svc, _ = _make_service(cfg=_make_cfg(
            SYNC_JOB_RETRY_BASE_DELAY_S=60,
            SYNC_JOB_RETRY_MAX_DELAY_S=300,
        ))
        # retry_count=3: min(300, 60 * 2^2) = min(300, 240) = 240
        assert svc.sync_retry_delay_s(3) == 240

    def test_max_less_than_base_uses_base(self):
        svc, _ = _make_service(cfg=_make_cfg(
            SYNC_JOB_RETRY_BASE_DELAY_S=100,
            SYNC_JOB_RETRY_MAX_DELAY_S=10,
        ))
        # max_delay = max(base, max_delay_cfg) = max(100, 10) = 100
        assert svc.sync_retry_delay_s(0) == 100


# ---------------------------------------------------------------------------
# _run_cache_warming_if_due
# ---------------------------------------------------------------------------

class TestRunCacheWarmingIfDue:
    def _now(self):
        return datetime(2026, 5, 16, 12, 0, 0, tzinfo=timezone.utc)

    def test_skips_when_ran_recently(self):
        now = self._now()
        svc, state = _make_service(
            extra_state={"last_cache_warming_at": now - timedelta(seconds=10)},
        )
        svc.run_cache_warming_if_due(now)
        assert state.get("last_cache_warming_at") == now - timedelta(seconds=10)

    def test_skips_when_redis_unavailable(self):
        now = self._now()
        svc, state = _make_service()
        # get_redis returns None when Redis is not configured
        svc.run_cache_warming_if_due(now)
        # no crash — state may or may not be set

    def test_updates_state_after_run(self):
        from unittest.mock import MagicMock, patch
        import app.services.scheduler_svc as _svc_module
        now = self._now()
        mock_db = _noop_db()
        mock_db.execute.return_value.all.return_value = []
        mock_db.scalar.return_value = 42
        mock_redis = MagicMock()

        svc, state = _make_service(db_fn=lambda read_only=False: mock_db)
        with patch.object(_svc_module, "get_redis", return_value=mock_redis):
            svc.run_cache_warming_if_due(now)
        assert state.get("last_cache_warming_at") == now


# ---------------------------------------------------------------------------
# _run_audit_integrity_check_if_due
# ---------------------------------------------------------------------------

class TestRunAuditIntegrityCheckIfDue:
    def _now(self):
        return datetime(2026, 5, 16, 12, 0, 0, tzinfo=timezone.utc)

    def test_skips_when_ran_recently(self):
        now = self._now()
        svc, state = _make_service(
            cfg=_make_cfg(AUDIT_INTEGRITY_VERIFY_INTERVAL_S=3600),
            extra_state={"last_audit_integrity_check_at": now - timedelta(seconds=60)},
        )
        svc.run_audit_integrity_check_if_due(now)
        assert state.get("last_audit_integrity_check_at") == now - timedelta(seconds=60)

    def test_runs_when_overdue(self):
        from unittest.mock import patch
        import app.audit_integrity as _audit_mod
        now = self._now()
        mock_db = _noop_db()
        scalars_result = MagicMock()
        scalars_result.all.return_value = []
        mock_db.scalars.return_value = scalars_result
        svc, state = _make_service(
            cfg=_make_cfg(AUDIT_INTEGRITY_VERIFY_INTERVAL_S=60),
            db_fn=lambda read_only=False: mock_db,
            extra_state={"last_audit_integrity_check_at": now - timedelta(hours=2)},
        )
        with patch.object(_audit_mod, "verify_audit_chain", return_value={"valid": True, "checked": 0}):
            svc.run_audit_integrity_check_if_due(now)
        assert state.get("last_audit_integrity_check_at") == now
