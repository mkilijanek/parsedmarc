"""Tests for app/services/feed_config_svc.py.

Focuses on pure-logic helpers: URL validation, cron field validation,
proxy test matching, HTML title extraction, and validate_feed_form.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg(**overrides):
    return SimpleNamespace(**overrides)


def _make_service():
    from app.services.feed_config_svc import make_feed_config_service
    return make_feed_config_service(
        cfg=_make_cfg(),
        get_setting_fn=MagicMock(return_value=""),
        set_setting_fn=MagicMock(),
        secret_decrypt_fn=MagicMock(return_value=""),
    )


def _mock_feed(source_type: str = "misp", source_id: str = "src"):
    f = MagicMock()
    f.source_type = source_type
    f.source_id = source_id
    return f


def _noop_db():
    m = MagicMock()
    m.scalar.return_value = None
    return m


# ---------------------------------------------------------------------------
# _is_valid_http_url
# ---------------------------------------------------------------------------

class TestIsValidHttpUrl:
    def test_valid_http(self):
        svc = _make_service()
        assert svc.is_valid_http_url("http://example.com") is True

    def test_valid_https(self):
        svc = _make_service()
        assert svc.is_valid_http_url("https://misp.internal/api") is True

    def test_rejects_empty(self):
        svc = _make_service()
        assert svc.is_valid_http_url("") is False

    def test_rejects_no_netloc(self):
        svc = _make_service()
        assert svc.is_valid_http_url("https://") is False

    def test_rejects_ftp_scheme(self):
        svc = _make_service()
        assert svc.is_valid_http_url("ftp://example.com") is False

    def test_rejects_bare_hostname(self):
        svc = _make_service()
        assert svc.is_valid_http_url("example.com") is False

    def test_rejects_double_slash_prefix(self):
        svc = _make_service()
        assert svc.is_valid_http_url("//example.com") is False

    def test_strips_whitespace(self):
        svc = _make_service()
        assert svc.is_valid_http_url("  https://example.com  ") is True


# ---------------------------------------------------------------------------
# _proxy_test_expected_match
# ---------------------------------------------------------------------------

class TestProxyTestExpectedMatch:
    def test_mwdb_matches_malware_in_title(self):
        svc = _make_service()
        assert svc.proxy_test_expected_match("mwdb", "Malware Database") is True

    def test_mwdb_matches_mwdb_in_title(self):
        svc = _make_service()
        assert svc.proxy_test_expected_match("mwdb", "MWDB | Login") is True

    def test_mwdb_no_match_returns_false(self):
        svc = _make_service()
        assert svc.proxy_test_expected_match("mwdb", "Some Other Site") is False

    def test_abusech_matches_title(self):
        svc = _make_service()
        assert svc.proxy_test_expected_match("abusech", "abuse.ch portal") is True

    def test_abusech_no_match(self):
        svc = _make_service()
        assert svc.proxy_test_expected_match("abusech", "Google") is False

    def test_certpl_matches(self):
        svc = _make_service()
        assert svc.proxy_test_expected_match("certpl", "cert.pl") is True

    def test_unknown_target_always_true(self):
        svc = _make_service()
        assert svc.proxy_test_expected_match("anything_else", "any title") is True

    def test_empty_title_unknown_target_still_true(self):
        svc = _make_service()
        assert svc.proxy_test_expected_match("other", "") is True


# ---------------------------------------------------------------------------
# _validate_feed_form — cron validation
# ---------------------------------------------------------------------------

class TestValidateFeedFormCron:
    def _state(self, fields=None):
        return {"fields": fields or [], "ready": True, "missing": []}

    def test_valid_cron_no_error(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "*/15 * * * *", "base_url": "https://misp.example.com"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert not any("cron" in e.lower() for e in errors)

    def test_wrong_cron_field_count(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "* * *", "base_url": "https://misp.example.com"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert any("5 fields" in e for e in errors)

    def test_cron_minute_out_of_range(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "99 * * * *", "base_url": "https://misp.example.com"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert any("minute" in e for e in errors)

    def test_cron_hour_out_of_range(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "0 25 * * *", "base_url": "https://misp.example.com"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert any("hour" in e for e in errors)

    def test_cron_step_zero_invalid(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "*/0 * * * *", "base_url": "https://misp.example.com"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert any("minute" in e for e in errors)

    def test_cron_list_values_valid(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "0,15,30,45 * * * *", "base_url": "https://misp.example.com"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert not any("cron" in e.lower() for e in errors)

    def test_cron_list_out_of_range_invalid(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "0,70 * * * *", "base_url": "https://misp.example.com"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert any("minute" in e for e in errors)


# ---------------------------------------------------------------------------
# _validate_feed_form — URL validation
# ---------------------------------------------------------------------------

class TestValidateFeedFormUrl:
    def _state(self):
        return {"fields": [], "ready": True, "missing": []}

    def test_missing_base_url_for_misp(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "*/15 * * * *", "base_url": ""}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert any("Base URL" in e for e in errors)

    def test_invalid_base_url_for_misp(self):
        svc = _make_service()
        feed = _mock_feed("misp")
        form = {"schedule_cron": "*/15 * * * *", "base_url": "not-a-url"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert any("Base URL" in e for e in errors)

    def test_valid_base_url_for_mwdb(self):
        svc = _make_service()
        feed = _mock_feed("mwdb")
        form = {
            "schedule_cron": "*/15 * * * *",
            "base_url": "https://mwdb.example.com",
            "feedcfg__days": "30",
            "feedcfg__tags": "malware",
        }
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert not any("Base URL" in e for e in errors)


# ---------------------------------------------------------------------------
# _validate_feed_form — abusech-specific
# ---------------------------------------------------------------------------

class TestValidateFeedFormAbusech:
    def _state(self):
        return {"fields": [], "ready": True, "missing": []}

    def test_no_service_selected_is_error(self):
        svc = _make_service()
        feed = _mock_feed("abusech")
        form = {"schedule_cron": "*/15 * * * *"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert any("abuse.ch service" in e for e in errors)

    def test_at_least_one_service_no_error(self):
        svc = _make_service()
        feed = _mock_feed("abusech")
        form = {"schedule_cron": "*/15 * * * *", "threatfox_enabled": "1"}
        errors = svc.validate_feed_form(feed, form, self._state(), _noop_db())
        assert not any("abuse.ch service" in e for e in errors)


# ---------------------------------------------------------------------------
# Pure key helpers
# ---------------------------------------------------------------------------

class TestKeyHelpers:
    def test_feed_value_key(self):
        svc = _make_service()
        assert svc.feed_value_key("src1", "api_key") == "feedcfg.src1.api_key"

    def test_feed_secret_key(self):
        svc = _make_service()
        assert svc.feed_secret_key("src1", "api_key") == "feedsecret.src1.api_key"

    def test_field_input_name(self):
        svc = _make_service()
        assert svc.field_input_name("proxy.http_url") == "proxy__http_url"
