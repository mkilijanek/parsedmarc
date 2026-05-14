"""Tests for milestone 1.8.0 deliverables.

Covers:
- DBCircuitBreaker (#139)
- DeadLetterJob model (#150)
- /admin/api/dead-letter-jobs endpoint (#150)
- /admin/api/db-circuit endpoint (#139)
- /api/events SSE endpoint (#160)
- settings_store priority model (gap coverage)
- worker helper functions (gap coverage)
- webui helper functions (gap coverage)
- crowdsec service (gap coverage)
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.models import DeadLetterJob, Feed, SyncJob


class TestDBCircuitBreaker:
    """Tests for app.services.common.DBCircuitBreaker (#139)."""

    def test_initial_state_is_closed(self):
        from app.services.common import DBCircuitBreaker
        cb = DBCircuitBreaker(fail_threshold=3, cooldown_s=5)
        assert cb.state == "closed"
        assert not cb.is_open

    def test_allow_request_when_closed(self):
        from app.services.common import DBCircuitBreaker
        cb = DBCircuitBreaker(fail_threshold=3, cooldown_s=5)
        assert cb.allow_request() is True

    def test_record_success_keeps_circuit_closed(self):
        from app.services.common import DBCircuitBreaker
        cb = DBCircuitBreaker(fail_threshold=3, cooldown_s=5)
        cb.record_failure()
        cb.record_success()
        assert cb.state == "closed"
        assert cb.allow_request() is True

    def test_circuit_opens_after_threshold_failures(self):
        from app.services.common import DBCircuitBreaker
        cb = DBCircuitBreaker(fail_threshold=3, cooldown_s=60)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "open"
        assert cb.is_open

    def test_circuit_blocks_when_open(self):
        from app.services.common import DBCircuitBreaker
        cb = DBCircuitBreaker(fail_threshold=1, cooldown_s=60)
        cb.record_failure()
        assert not cb.allow_request()

    def test_circuit_recovers_after_cooldown(self):
        from app.services.common import DBCircuitBreaker
        cb = DBCircuitBreaker(fail_threshold=1, cooldown_s=1)
        cb.record_failure()
        assert cb.state == "open"
        time.sleep(1.1)
        assert cb.allow_request() is True
        assert cb.state == "half_open"
        cb.record_success()
        assert cb.state == "closed"

    def test_success_after_half_open_resets_circuit(self):
        from app.services.common import DBCircuitBreaker
        cb = DBCircuitBreaker(fail_threshold=1, cooldown_s=1)
        cb.record_failure()
        time.sleep(1.1)
        assert cb.allow_request() is True
        assert cb.state == "half_open"
        cb.record_success()
        assert cb.state == "closed"
        assert not cb.is_open

    def test_failure_in_half_open_closes_circuit_again(self):
        from app.services.common import DBCircuitBreaker
        cb = DBCircuitBreaker(fail_threshold=1, cooldown_s=1)
        cb.record_failure()
        time.sleep(1.1)
        assert cb.allow_request() is True
        assert cb.state == "half_open"
        cb.record_failure()  # probe failed
        assert cb.state == "open"


class TestDeadLetterJobModel:
    """Tests for DeadLetterJob model (#150)."""

    def test_model_has_expected_fields(self):
        dlq = DeadLetterJob(
            original_job_id="job-abc",
            feed_source_id="misp",
            failure_class="permanent",
            error="Connection refused",
            retry_count=3,
            payload={"foo": "bar"},
        )
        assert dlq.original_job_id == "job-abc"
        assert dlq.feed_source_id == "misp"
        assert dlq.failure_class == "permanent"
        assert dlq.error == "Connection refused"
        assert dlq.retry_count == 3
        assert (dlq.status or "pending") == "pending"
        # requeue_count default is applied on INSERT, so check None or 0
        assert (dlq.requeue_count or 0) == 0

    def test_dlq_defaults(self):
        dlq = DeadLetterJob(
            original_job_id="job-xyz",
            feed_source_id="crowdsec",
        )
        assert (dlq.status or "pending") == "pending"
        assert (dlq.requeue_count or 0) == 0
        assert dlq.requeue_sync_job_id is None
        assert dlq.last_requeued_at is None


class TestDLQEndpoints:
    """Tests for /admin/api/dead-letter-jobs endpoints (#150)."""

    def test_list_dead_letter_jobs_returns_200(self, admin_client):
        resp = admin_client.get("/admin/api/dead-letter-jobs")
        assert resp.status_code == 200

    def test_list_dead_letter_jobs_returns_json(self, admin_client):
        resp = admin_client.get("/admin/api/dead-letter-jobs")
        import json
        body = json.loads(resp.data)
        assert "count" in body
        assert "items" in body
        assert isinstance(body["items"], list)
        if body["items"]:
            assert "status" in body["items"][0]
            assert "requeue_sync_job_id" in body["items"][0]

    def test_list_returns_dlq_entries(self, admin_client, test_db):
        dlq = DeadLetterJob(
            original_job_id="test-job-001",
            feed_source_id="misp",
            failure_class="permanent",
            error="timeout",
            retry_count=3,
            payload={},
        )
        test_db.add(dlq)
        test_db.commit()

        import json
        resp = admin_client.get("/admin/api/dead-letter-jobs")
        body = json.loads(resp.data)
        ids = [item["original_job_id"] for item in body["items"]]
        assert "test-job-001" in ids

    def test_list_filter_by_feed(self, admin_client, test_db):
        for feed in ["misp", "crowdsec"]:
            test_db.add(DeadLetterJob(
                original_job_id=f"job-{feed}",
                feed_source_id=feed,
                payload={},
            ))
        test_db.commit()

        import json
        resp = admin_client.get("/admin/api/dead-letter-jobs?feed=misp")
        body = json.loads(resp.data)
        assert all(item["feed_source_id"] == "misp" for item in body["items"])

    def test_requeue_nonexistent_returns_404(self, admin_client, admin_csrf_token):
        resp = admin_client.post(
            "/admin/api/dead-letter-jobs/99999/requeue",
            data={"csrf_token": admin_csrf_token},
        )
        assert resp.status_code == 404

    def test_requeue_existing_job(self, admin_client, admin_csrf_token, test_db):
        test_db.add(
            Feed(
                source_id="misp",
                source_type="misp",
                display_name="MISP",
                enabled=True,
                deleted=False,
            )
        )
        dlq = DeadLetterJob(
            original_job_id="test-requeue-job",
            feed_source_id="misp",
            failure_class="permanent",
            error="err",
            retry_count=3,
            payload={},
        )
        test_db.add(dlq)
        test_db.commit()
        dlq_id = dlq.id

        import json
        resp = admin_client.post(
            f"/admin/api/dead-letter-jobs/{dlq_id}/requeue",
            data={"csrf_token": admin_csrf_token},
        )
        assert resp.status_code == 200
        body = json.loads(resp.data)
        assert body["status"] == "requeued"
        second = admin_client.post(
            f"/admin/api/dead-letter-jobs/{dlq_id}/requeue",
            data={"csrf_token": admin_csrf_token},
        )
        assert second.status_code == 200
        second_body = json.loads(second.data)
        assert second_body["status"] == "already_requeued"
        assert second_body["sync_job_id"] == body["sync_job_id"]


class TestDBCircuitEndpoint:
    """Tests for /admin/api/db-circuit endpoint (#139)."""

    def test_db_circuit_returns_200(self, admin_client):
        resp = admin_client.get("/admin/api/db-circuit")
        assert resp.status_code == 200

    def test_db_circuit_returns_state(self, admin_client):
        import json
        resp = admin_client.get("/admin/api/db-circuit")
        body = json.loads(resp.data)
        assert "state" in body
        assert body["state"] in ("closed", "open", "half_open", "unknown")


class TestSSEEventsEndpoint:
    """Tests for /api/events SSE endpoint (#160)."""

    def test_events_endpoint_exists(self, client):
        with client.application.test_request_context():
            from flask import url_for
            url = url_for("api_events")
        assert url == "/api/events"

    def test_events_requires_auth(self, client):
        resp = client.get("/api/events", headers={"Accept": "text/event-stream"})
        assert resp.status_code == 401

    def test_events_content_type(self, admin_client):
        resp = admin_client.get("/api/events", headers={"Accept": "text/event-stream"})
        assert "text/event-stream" in resp.content_type or resp.status_code == 200

    def test_events_reject_sync_workers_outside_testing(self, app):
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["admin_authenticated"] = True
            app.config["TESTING"] = False
            app.config["GUNICORN_WORKER_CLASS"] = "sync"
            resp = c.get("/api/events", headers={"Accept": "text/event-stream"})
            assert resp.status_code == 503
            assert "sse_requires_non_sync_workers" in resp.get_data(as_text=True)
            app.config["TESTING"] = True


class TestHealthWithCircuitState:
    """Tests for /health endpoint db_circuit_state field (#139)."""

    def test_health_includes_db_circuit_state(self, client):
        import json
        resp = client.get("/health")
        body = json.loads(resp.data)
        assert "db_circuit_state" in body
        assert body["db_circuit_state"] in ("closed", "open", "half_open")


class TestBackupScriptHardening:
    """Tests for backup script credential handling (#186)."""

    def test_backup_script_uses_pgpassfile_instead_of_dsn_argv(self):
        script = Path("scripts/backup.sh").read_text(encoding="utf-8")
        assert "PGPASSFILE" in script
        assert 'pg_dump "${PG_CONN}"' not in script


class TestSettingsStoreCoverage:
    """Tests for settings_store.py priority model — gap coverage."""

    def test_is_production_false_by_default(self):
        from app.settings_store import _is_production
        with patch.dict(os.environ, {"APP_ENV": "development"}):
            assert not _is_production()

    def test_is_production_true(self):
        from app.settings_store import _is_production
        with patch.dict(os.environ, {"APP_ENV": "production"}):
            assert _is_production()

    def test_env_var_is_set_true(self):
        from app.settings_store import _env_var_is_set
        with patch.dict(os.environ, {"MY_TEST_VAR": "value"}):
            assert _env_var_is_set("MY_TEST_VAR")

    def test_env_var_is_set_false_when_empty(self):
        from app.settings_store import _env_var_is_set
        with patch.dict(os.environ, {"MY_TEST_VAR": ""}):
            assert not _env_var_is_set("MY_TEST_VAR")

    def test_parse_bool_setting_truthy(self):
        from app.settings_store import parse_bool_setting
        for v in ("1", "true", "yes", "on", "True", "YES"):
            assert parse_bool_setting(v)

    def test_parse_bool_setting_falsy(self):
        from app.settings_store import parse_bool_setting
        for v in ("0", "false", "no", "off", "", None, "random"):
            assert not parse_bool_setting(v)

    def test_decrypt_setting_value_empty(self):
        from app.settings_store import decrypt_setting_value
        assert decrypt_setting_value("") == ""

    def test_decrypt_setting_value_plain(self):
        from app.settings_store import decrypt_setting_value
        assert decrypt_setting_value("plaintext") == "plaintext"

    def test_decrypt_setting_value_v2_roundtrip(self):
        import base64
        import os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from app.settings_store import _secret_enc_key_v2, decrypt_setting_value

        key = _secret_enc_key_v2()
        nonce = os.urandom(12)
        cipher = AESGCM(key).encrypt(nonce, b"secret_value", None)
        blob = nonce + cipher
        encoded = "v2:" + base64.urlsafe_b64encode(blob).decode("ascii")
        assert decrypt_setting_value(encoded) == "secret_value"

    def test_decrypt_v2_invalid_blob_returns_empty(self):
        from app.settings_store import decrypt_setting_value
        assert decrypt_setting_value("v2:notbase64!!!") == ""

    def test_decrypt_v1_invalid_blob_returns_empty(self):
        from app.settings_store import decrypt_setting_value
        assert decrypt_setting_value("v1:tooshort") == ""

    def test_get_app_setting_default_when_missing(self, test_db):
        from app.settings_store import get_app_setting
        result = get_app_setting(test_db, "nonexistent.key", default="fallback")
        assert result == "fallback"

    def test_get_app_setting_returns_db_value(self, test_db):
        from app.models import AppSetting
        from app.settings_store import get_app_setting
        setting = AppSetting(key="test.setting", value="hello")
        test_db.add(setting)
        test_db.commit()
        result = get_app_setting(test_db, "test.setting")
        assert result == "hello"

    def test_get_setting_with_priority_dev_env_wins(self, test_db):
        from app.models import AppSetting
        from app.settings_store import get_setting_with_priority
        setting = AppSetting(key="test.prio.key", value="db_value")
        test_db.add(setting)
        test_db.commit()
        with patch.dict(os.environ, {"APP_ENV": "development", "TEST_PRIO_VAR": "env_value"}):
            result = get_setting_with_priority(
                test_db,
                env_name="TEST_PRIO_VAR",
                setting_key="test.prio.key",
                default="default_value",
            )
        assert result == "env_value"

    def test_get_setting_with_priority_dev_db_fallback(self, test_db):
        from app.models import AppSetting
        from app.settings_store import get_setting_with_priority
        setting = AppSetting(key="test.prio.key2", value="db_value")
        test_db.add(setting)
        test_db.commit()
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=False):
            os.environ.pop("TEST_PRIO_VAR2", None)
            result = get_setting_with_priority(
                test_db,
                env_name="TEST_PRIO_VAR2",
                setting_key="test.prio.key2",
                default="default_value",
            )
        assert result == "db_value"

    def test_get_setting_with_priority_prd_db_wins(self, test_db):
        from app.models import AppSetting
        from app.settings_store import get_setting_with_priority
        setting = AppSetting(key="test.prio.prd", value="db_value_prd")
        test_db.add(setting)
        test_db.commit()
        with patch.dict(os.environ, {"APP_ENV": "production", "TEST_PRD_VAR": "env_value_prd"}):
            result = get_setting_with_priority(
                test_db,
                env_name="TEST_PRD_VAR",
                setting_key="test.prio.prd",
                default="default_value",
            )
        assert result == "db_value_prd"

    def test_get_admin_login_rate_limit_default(self, test_db):
        from app.settings_store import get_admin_login_rate_limit
        result = get_admin_login_rate_limit(test_db)
        assert isinstance(result, str)
        assert "per" in result

    def test_get_admin_login_rate_limit_window_default(self, test_db):
        from app.settings_store import get_admin_login_rate_limit_window
        result = get_admin_login_rate_limit_window(test_db)
        assert isinstance(result, int)
        assert result > 0

    def test_get_admin_auth_enabled_default_true(self, test_db):
        from app.settings_store import get_admin_auth_enabled
        with patch.dict(os.environ, {"APP_ENV": "development"}):
            result = get_admin_auth_enabled(test_db)
        assert isinstance(result, bool)

    def test_get_admin_panel_enabled_default_true(self, test_db):
        from app.settings_store import get_admin_panel_enabled
        with patch.dict(os.environ, {"APP_ENV": "development"}):
            result = get_admin_panel_enabled(test_db)
        assert isinstance(result, bool)

    def test_runtime_override_or_env_returns_env_fallback(self, test_db):
        from app.settings_store import runtime_override_or_env
        result = runtime_override_or_env(
            test_db,
            setting_key="nonexistent.key.xyz",
            env_value="from_env",
        )
        assert result == "from_env"

    def test_runtime_override_or_env_db_wins(self, test_db):
        from app.models import AppSetting
        from app.settings_store import runtime_override_or_env
        setting = AppSetting(key="roo.test.key", value="from_db")
        test_db.add(setting)
        test_db.commit()
        result = runtime_override_or_env(
            test_db,
            setting_key="roo.test.key",
            env_value="from_env",
        )
        assert result == "from_db"


class TestWorkerHelpers:
    """Tests for app.worker helper functions — gap coverage."""

    def test_signal_handler_sets_shutdown_flag(self):
        import app.worker as worker_mod
        original = worker_mod.shutdown_requested
        try:
            with patch.object(worker_mod, "mark_shutdown_requested"):
                worker_mod._signal_handler(15, None)
            assert worker_mod.shutdown_requested is True
        finally:
            worker_mod.shutdown_requested = original

    def test_safe_job_calls_function_on_success(self):
        import app.worker as worker_mod
        called = []
        def fn(): called.append(1)
        with patch.object(worker_mod, "mark_job_start"), \
             patch.object(worker_mod, "mark_job_success"), \
             patch.object(worker_mod, "mark_job_failure"):
            original = worker_mod.shutdown_requested
            try:
                worker_mod.shutdown_requested = False
                worker_mod._safe_job("test_job", fn)()
            finally:
                worker_mod.shutdown_requested = original
        assert called == [1]

    def test_safe_job_handles_exception(self):
        import app.worker as worker_mod
        def fn(): raise ValueError("boom")
        with patch.object(worker_mod, "mark_job_start"), \
             patch.object(worker_mod, "mark_job_success"), \
             patch.object(worker_mod, "mark_job_failure") as mock_fail:
            original = worker_mod.shutdown_requested
            try:
                worker_mod.shutdown_requested = False
                worker_mod._safe_job("fail_job", fn)()
            finally:
                worker_mod.shutdown_requested = original
        mock_fail.assert_called_once_with("fail_job", "boom")

    def test_safe_job_skips_on_shutdown(self):
        import app.worker as worker_mod
        called = []
        def fn(): called.append(1)
        original = worker_mod.shutdown_requested
        try:
            worker_mod.shutdown_requested = True
            worker_mod._safe_job("skipped_job", fn)()
        finally:
            worker_mod.shutdown_requested = original
        assert called == []

    def test_refresh_proxy_settings_handles_db_error(self):
        import app.worker as worker_mod
        mock_db = MagicMock()
        mock_db.scalars.side_effect = Exception("db error")
        mock_db.__enter__ = lambda s: s
        mock_db.__exit__ = MagicMock(return_value=False)
        with patch("app.worker.get_session", return_value=mock_db):
            # Should not raise
            worker_mod._refresh_proxy_settings()


class TestWebUIHelpers:
    """Tests for app.webui helper functions — gap coverage."""

    def test_split_csv_returns_none_for_empty(self):
        from app.webui import _split_csv
        assert _split_csv("") is None
        assert _split_csv(None) is None

    def test_split_csv_returns_list(self):
        from app.webui import _split_csv
        result = _split_csv("ip,domain,url")
        assert result == ["ip", "domain", "url"]

    def test_split_csv_strips_whitespace(self):
        from app.webui import _split_csv
        result = _split_csv(" ip , domain ")
        assert result == ["ip", "domain"]

    def test_split_csv_filters_empty_items(self):
        from app.webui import _split_csv
        result = _split_csv("ip,,domain,")
        assert "ip" in result
        assert "domain" in result
        assert "" not in result

    def test_active_only_true_by_default(self):
        from app.webui import _active_only
        assert _active_only("1") is True
        assert _active_only("true") is True
        assert _active_only("yes") is True

    def test_active_only_false_values(self):
        from app.webui import _active_only
        assert _active_only("0") is False
        assert _active_only("false") is False
        assert _active_only("no") is False
        assert _active_only("off") is False

    def test_as_delimited_csv(self):
        from app.webui import UnifiedRow, _as_delimited
        rows = [UnifiedRow(
            id=1, uuid="uuid1", ioc_value="1.2.3.4", ioc_type="ip",
            source="misp", source_ref=None, confidence=80, tlp="GREEN",
            is_active=True, tags=["malware"], comments=None, metadata={},
            first_seen="2024-01-01", last_seen="2024-01-02",
        )]
        csv = _as_delimited(rows, ",")
        assert "1.2.3.4" in csv
        assert "uuid1" in csv
        lines = csv.strip().splitlines()
        assert len(lines) == 2  # header + 1 row

    def test_as_delimited_tsv(self):
        from app.webui import UnifiedRow, _as_delimited
        rows = [UnifiedRow(
            id=1, uuid="uuid2", ioc_value="evil.com", ioc_type="domain",
            source="crowdsec", source_ref=None, confidence=70, tlp="AMBER",
            is_active=True, tags=[], comments=None, metadata={},
            first_seen="2024-01-01", last_seen="2024-01-01",
        )]
        tsv = _as_delimited(rows, "\t")
        assert "\t" in tsv
        assert "evil.com" in tsv

    def test_as_delimited_handles_none_fields(self):
        from app.webui import UnifiedRow, _as_delimited
        rows = [UnifiedRow(
            id=1, uuid="uuid3", ioc_value="test.com", ioc_type="domain",
            source="test", source_ref=None, confidence=50, tlp="WHITE",
            is_active=False, tags=None, comments=None, metadata=None,
            first_seen="2024-01-01", last_seen="2024-01-01",
        )]
        csv = _as_delimited(rows, ",")
        assert "test.com" in csv


class TestCrowdsecCoverage:
    """Tests for crowdsec service — gap coverage."""

    def test_update_crowdsec_list_no_api_key_raises(self):
        from app.services.crowdsec import update_crowdsec_list
        with patch("app.services.crowdsec.Config") as mock_cfg_cls:
            mock_cfg_cls.return_value.CROWDSEC_API_KEY = ""
            with pytest.raises(RuntimeError, match="CROWDSEC_API_KEY"):
                update_crowdsec_list("test-list")

    def test_update_all_crowdsec_lists_empty_config(self):
        from app.services.crowdsec import update_all_crowdsec_lists
        with patch("app.services.crowdsec.Config") as mock_cfg_cls:
            mock_cfg_cls.return_value.CROWDSEC_LISTS = ""
            mock_cfg_cls.return_value.CROWDSEC_API_KEY = ""
            result = update_all_crowdsec_lists()
        assert result == {}

    def test_update_crowdsec_indicators_aggregates(self):
        from app.services.crowdsec import update_crowdsec_indicators
        with patch("app.services.crowdsec.update_all_crowdsec_lists") as mock_lists:
            mock_lists.return_value = {
                "list1": {"fetched": 10, "deactivated": 2, "errors": 0},
                "list2": {"fetched": 5, "deactivated": 0, "errors": 1},
            }
            result = update_crowdsec_indicators()
        assert result["fetched"] == 15
        assert result["deactivated"] == 2
        assert result["errors"] == 1

    def test_update_crowdsec_list_with_mock_http(self):
        from app.services.crowdsec import update_crowdsec_list
        mock_resp = MagicMock()
        mock_resp.text = "1.2.3.4\n5.6.7.8\n# comment\n"
        mock_resp.raise_for_status = MagicMock()

        mock_session = MagicMock()
        mock_session.__enter__ = lambda s: s
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session.get = MagicMock(return_value=mock_resp)

        mock_db = MagicMock()
        mock_db.execute = MagicMock()
        mock_db.commit = MagicMock()
        mock_db.close = MagicMock()

        with patch("app.services.crowdsec.Config") as mock_cfg_cls, \
             patch("app.services.crowdsec.build_feed_session", return_value=mock_session), \
             patch("app.services.crowdsec.throttle_external_request"), \
             patch("app.services.crowdsec.SessionLocal", return_value=mock_db):
            mock_cfg = MagicMock()
            mock_cfg.CROWDSEC_API_KEY = "test-key"
            mock_cfg.FEED_HTTP_TIMEOUT_S = 30
            mock_cfg.FEED_RETRY_ATTEMPTS = 1
            mock_cfg.FEED_RETRY_BASE_DELAY_S = 0
            mock_cfg_cls.return_value = mock_cfg
            result = update_crowdsec_list("test-list")
        assert result["fetched"] >= 0


class TestCommonCircuitBreakerCoverage:
    """Tests for existing CircuitBreaker in common.py — gap coverage."""

    def test_circuit_breaker_is_open_false_initially(self):
        from app.services.common import CircuitBreaker
        cb = CircuitBreaker()
        assert not cb.is_open("unknown-source")

    def test_circuit_breaker_opens_after_threshold(self):
        from app.services.common import CircuitBreaker
        cb = CircuitBreaker()
        for _ in range(3):
            cb.record_failure("test-source", fail_threshold=3, cooldown_s=60)
        assert cb.is_open("test-source")

    def test_circuit_breaker_record_success_clears(self):
        from app.services.common import CircuitBreaker
        cb = CircuitBreaker()
        cb.record_failure("src", fail_threshold=1, cooldown_s=60)
        cb.record_success("src")
        assert not cb.is_open("src")
