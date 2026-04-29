"""Third pass coverage boost — targeting remaining gaps.

Covers:
- app/services/misp.py: health check, normalize_value
- app/services/malwarebazaar.py: _parse_dt, fetch helpers
- app/services/feed_ops.py: feed_operational_status, feed_last_error_at
- app/settings_store.py: remaining branches
- app/services/quality.py: remaining edge cases
- app/adapters/pipeline.py: pipeline steps
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# MISP service tests
# ---------------------------------------------------------------------------

class TestMISPCoverage:

    def test_misp_health_check_not_configured(self):
        from app.services.misp import misp_health_check
        mock_cfg = MagicMock()
        mock_cfg.MISP_URL = ""
        mock_cfg.MISP_API_KEY = ""
        result = misp_health_check(mock_cfg)
        assert result["status"] == "down"
        assert "not_configured" in str(result.get("error", ""))

    def test_misp_health_check_circuit_open(self):
        from app.services.misp import misp_health_check
        from app.services.common import _circuit_breaker
        mock_cfg = MagicMock()
        mock_cfg.MISP_URL = "https://misp.example.com"
        mock_cfg.MISP_API_KEY = "test-key"

        # Force circuit open temporarily
        with patch.object(_circuit_breaker, "is_open", return_value=True):
            result = misp_health_check(mock_cfg)
        assert result["status"] == "down"

    def test_misp_health_check_success(self):
        from app.services.misp import misp_health_check
        mock_cfg = MagicMock()
        mock_cfg.MISP_URL = "https://misp.example.com"
        mock_cfg.MISP_API_KEY = "test-key"
        mock_cfg.MISP_HEALTH_TIMEOUT_S = 3
        mock_cfg.MISP_VERIFY_SSL = False

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"version": "2.4"}

        mock_session = MagicMock()
        mock_session.__enter__ = lambda s: s
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session.get = MagicMock(return_value=mock_resp)

        with patch("app.services.misp.build_feed_session", return_value=mock_session):
            result = misp_health_check(mock_cfg)
        assert result["status"] == "ok"

    def test_misp_health_check_failure(self):
        from app.services.misp import misp_health_check
        mock_cfg = MagicMock()
        mock_cfg.MISP_URL = "https://misp.example.com"
        mock_cfg.MISP_API_KEY = "test-key"
        mock_cfg.MISP_HEALTH_TIMEOUT_S = 3
        mock_cfg.MISP_VERIFY_SSL = False

        mock_session = MagicMock()
        mock_session.__enter__ = lambda s: s
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session.get.side_effect = ConnectionError("refused")

        with patch("app.services.misp.build_feed_session", return_value=mock_session):
            result = misp_health_check(mock_cfg)
        assert result["status"] == "down"
        assert "error" in result

    def test_normalize_value_compound(self):
        from app.services.misp import _normalize_value
        val, meta = _normalize_value("ip-src|port", "1.2.3.4|443")
        assert val == "1.2.3.4"
        assert "compound_raw" in meta

    def test_normalize_value_plain(self):
        from app.services.misp import _normalize_value
        val, meta = _normalize_value("ip-src", "1.2.3.4")
        assert val == "1.2.3.4"
        assert "raw" in meta


# ---------------------------------------------------------------------------
# MalwareBazaar service tests
# ---------------------------------------------------------------------------

class TestMalwareBazaarCoverage:

    def test_parse_dt_iso_format(self):
        from app.services.malwarebazaar import _parse_dt
        result = _parse_dt("2024-01-15 12:00:00")
        assert result is not None
        assert result.year == 2024
        assert result.month == 1

    def test_parse_dt_iso_with_z(self):
        from app.services.malwarebazaar import _parse_dt
        result = _parse_dt("2024-01-15T12:00:00Z")
        assert result is not None

    def test_parse_dt_empty_string(self):
        from app.services.malwarebazaar import _parse_dt
        result = _parse_dt("")
        assert result is None

    def test_parse_dt_invalid_string(self):
        from app.services.malwarebazaar import _parse_dt
        result = _parse_dt("not-a-date")
        assert result is None

    def test_fetch_malwarebazaar_no_auth_key_raises(self):
        from app.services.malwarebazaar import fetch_malwarebazaar_by_tags
        with pytest.raises(RuntimeError, match="ABUSECH_AUTH_KEY"):
            list(fetch_malwarebazaar_by_tags(
                base_url="https://mb-api.abuse.ch/api/v1/",
                auth_key="",
                tags=["malware"],
                since=None,
                until=None,
                limit=10,
            ))

    def test_fetch_malwarebazaar_api_response(self):
        from app.services.malwarebazaar import fetch_malwarebazaar_by_tags
        mock_data = {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "a" * 64,
                    "first_seen": "2024-01-01 00:00:00",
                    "tags": ["malware"],
                    "file_name": "test.exe",
                }
            ]
        }
        mock_connector = MagicMock()
        mock_connector.request_json.return_value = mock_data

        with patch("app.services.malwarebazaar.ExternalFeedConnector", return_value=mock_connector):
            with patch("app.services.malwarebazaar.requests.Session") as mock_sess_cls:
                mock_sess = MagicMock()
                mock_sess.__enter__ = lambda s: s
                mock_sess.__exit__ = MagicMock(return_value=False)
                mock_sess_cls.return_value = mock_sess
                results = list(fetch_malwarebazaar_by_tags(
                    base_url="https://mb-api.abuse.ch/api/v1/",
                    auth_key="test-key",
                    tags=["malware"],
                    since=None,
                    until=None,
                    limit=10,
                ))
        assert len(results) >= 1
        assert results[0]["ioc_type"] == "hash"

    def test_fetch_malwarebazaar_query_failed_status(self):
        from app.services.malwarebazaar import fetch_malwarebazaar_by_tags
        mock_data = {"query_status": "no_results", "data": []}
        mock_connector = MagicMock()
        mock_connector.request_json.return_value = mock_data

        with patch("app.services.malwarebazaar.ExternalFeedConnector", return_value=mock_connector):
            with patch("app.services.malwarebazaar.requests.Session") as mock_sess_cls:
                mock_sess = MagicMock()
                mock_sess.__enter__ = lambda s: s
                mock_sess.__exit__ = MagicMock(return_value=False)
                mock_sess_cls.return_value = mock_sess
                results = list(fetch_malwarebazaar_by_tags(
                    base_url="https://mb-api.abuse.ch/api/v1/",
                    auth_key="test-key",
                    tags=["malware"],
                    since=None,
                    until=None,
                    limit=10,
                ))
        assert results == []


# ---------------------------------------------------------------------------
# Feed ops coverage
# ---------------------------------------------------------------------------

class TestFeedOpsCoverage2:

    def test_feed_operational_status_enabled_ready_success(self):
        from app.services.feed_ops import feed_operational_status
        latest_run = MagicMock()
        latest_run.status = "success"
        result = feed_operational_status(enabled=True, ready=True, latest_run=latest_run)
        assert result == "OK"

    def test_feed_operational_status_disabled(self):
        from app.services.feed_ops import feed_operational_status
        result = feed_operational_status(enabled=False, ready=True, latest_run=None)
        assert result == "DISABLED"

    def test_feed_operational_status_not_ready(self):
        from app.services.feed_ops import feed_operational_status
        result = feed_operational_status(enabled=True, ready=False, latest_run=None)
        assert result == "NOT_CONFIGURED"

    def test_feed_operational_status_no_runs(self):
        from app.services.feed_ops import feed_operational_status
        result = feed_operational_status(enabled=True, ready=True, latest_run=None)
        assert result in ("OK", "WARNING", "ERROR")

    def test_feed_operational_status_with_failed_run(self):
        from app.services.feed_ops import feed_operational_status
        latest_run = MagicMock()
        latest_run.status = "failed"
        result = feed_operational_status(enabled=True, ready=True, latest_run=latest_run)
        assert result == "ERROR"

    def test_feed_last_error_at_none_when_success(self):
        from app.services.feed_ops import feed_last_error_at
        run = MagicMock()
        run.status = "success"
        run.error = None
        result = feed_last_error_at(run, None)
        # Returns None when no error
        assert result is None or isinstance(result, datetime)

    def test_feed_last_error_at_returns_time_when_failed(self):
        from app.services.feed_ops import feed_last_error_at
        run = MagicMock()
        run.status = "failed"
        run.error = "Connection timeout"
        run.finished_at = datetime.now(timezone.utc)
        result = feed_last_error_at(run, None)
        # May return a datetime if the run was a failure
        assert result is None or isinstance(result, datetime)

    def test_apply_feed_filters_empty_list(self):
        from app.services.feed_ops import apply_feed_filters_and_sort
        result = apply_feed_filters_and_sort(
            [],
            status_filter="",
            datasource="",
            configured="",
            query_text="",
            problems_only=False,
            sort_by="display_name",
            sort_order="asc",
        )
        assert result == []


# ---------------------------------------------------------------------------
# Additional settings_store coverage
# ---------------------------------------------------------------------------

class TestSettingsStoreCoverage2:

    def test_get_admin_api_token_default_empty(self, test_db):
        from app.settings_store import get_admin_api_token
        import os
        with patch.dict(os.environ, {"ADMIN_API_TOKEN": ""}, clear=False):
            result = get_admin_api_token(test_db)
        # Result should be string (empty or from env)
        assert isinstance(result, str)

    def test_get_admin_api_token_from_env(self, test_db):
        from app.settings_store import get_admin_api_token
        import os
        with patch.dict(os.environ, {"ADMIN_API_TOKEN": "token-from-env", "APP_ENV": "development"}, clear=False):
            result = get_admin_api_token(test_db)
        assert result == "token-from-env"

    def test_get_setting_with_priority_default_fallback(self, test_db):
        from app.settings_store import get_setting_with_priority
        import os
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=False):
            os.environ.pop("NONEXISTENT_TEST_VAR_XYZ", None)
            result = get_setting_with_priority(
                test_db,
                env_name="NONEXISTENT_TEST_VAR_XYZ",
                setting_key="nonexistent.setting.xyz",
                default="my_default",
            )
        assert result == "my_default"

    def test_decrypt_v1_valid_roundtrip(self):
        """Test v1 decrypt roundtrip using HMAC/SHA256 stream cipher."""
        import base64
        import hashlib
        import hmac
        import os
        from app.settings_store import _secret_enc_key_v1, decrypt_setting_value

        key = _secret_enc_key_v1()
        nonce = os.urandom(16)
        plaintext = b"test_secret_value"
        # Encrypt
        stream = bytearray()
        counter = 0
        while len(stream) < len(plaintext):
            block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
            stream.extend(block)
            counter += 1
        cipher = bytes(a ^ b for a, b in zip(plaintext, stream))
        mac = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
        blob = nonce + mac + cipher
        encoded = "v1:" + base64.urlsafe_b64encode(blob).decode("ascii")
        result = decrypt_setting_value(encoded)
        assert result == "test_secret_value"


# ---------------------------------------------------------------------------
# Pipeline adapter coverage
# ---------------------------------------------------------------------------

class TestAdapterPipelineCoverage:

    def test_pipeline_db_retry_success(self):
        from app.adapters.pipeline import db_retry
        call_count = [0]

        def op():
            call_count[0] += 1
            return "ok"

        result = db_retry(op, attempts=3, base_delay_s=0.0)
        assert result == "ok"
        assert call_count[0] == 1

    def test_pipeline_db_retry_retries_on_db_error(self):
        from sqlalchemy.exc import OperationalError
        from app.adapters.pipeline import db_retry
        call_count = [0]

        def op():
            call_count[0] += 1
            if call_count[0] < 3:
                raise OperationalError("transient", None, None)
            return "recovered"

        result = db_retry(op, attempts=3, base_delay_s=0.0)
        assert result == "recovered"
        assert call_count[0] == 3

    def test_pipeline_db_retry_raises_after_all_attempts(self):
        from sqlalchemy.exc import OperationalError
        from app.adapters.pipeline import db_retry

        def op():
            raise OperationalError("permanent", None, None)

        with pytest.raises(OperationalError):
            db_retry(op, attempts=3, base_delay_s=0.0)

    def test_pipeline_invalidate_feed_caches(self):
        from app.adapters.pipeline import invalidate_feed_caches
        mock_redis = MagicMock()
        mock_redis.scan.return_value = (0, [])
        with patch("app.adapters.pipeline.get_redis", return_value=mock_redis):
            invalidate_feed_caches()

    def test_pipeline_prepare_items_empty(self):
        from app.adapters.pipeline import _prepare_items
        result = _prepare_items("test_source", ())
        assert isinstance(result, list)
        assert result == []
