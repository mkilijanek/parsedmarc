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


# ---------------------------------------------------------------------------
# _mask_secret_fn (via read_feed_config_state secret field)
# ---------------------------------------------------------------------------

class TestMaskSecretFn:
    def _get_masked(self, value):
        from app.services.feed_config_svc import make_feed_config_service
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        def get_setting(db, key, default="", secret=False):
            return value if secret else default

        svc = make_feed_config_service(
            cfg=SimpleNamespace(ABUSECH_AUTH_KEY=""),
            get_setting_fn=get_setting,
            set_setting_fn=MagicMock(),
            secret_decrypt_fn=MagicMock(return_value=value),
        )
        f = MagicMock()
        f.source_type = "misp"
        f.source_id = "misp"
        f.base_url = "http://misp.example.com"
        f.enabled = True
        f.display_name = "MISP"
        db = MagicMock()
        state = svc.read_feed_config_state(db, f)
        for field in state["fields"]:
            if field["secret"]:
                return field["current_masked"]
        return None

    def test_empty_secret_gives_empty_mask(self):
        assert self._get_masked("") == ""

    def test_long_value_shows_tail(self):
        masked = self._get_masked("supersecretapikey1234")
        assert masked is not None
        assert masked.endswith("1234")
        assert "*" in masked

    def test_short_value_all_masked(self):
        masked = self._get_masked("ab")
        assert masked is not None
        assert "*" in masked


# ---------------------------------------------------------------------------
# _read_feed_enabled
# ---------------------------------------------------------------------------

def _make_feed_config_svc_with_setting(setting_value):
    from app.services.feed_config_svc import make_feed_config_service
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    return make_feed_config_service(
        cfg=SimpleNamespace(ABUSECH_AUTH_KEY=""),
        get_setting_fn=MagicMock(return_value=setting_value),
        set_setting_fn=MagicMock(),
        secret_decrypt_fn=MagicMock(return_value=setting_value),
    )


class TestReadFeedEnabled:
    def _noop_db(self):
        from unittest.mock import MagicMock
        m = MagicMock()
        m.scalar.return_value = None
        return m

    def test_returns_true_for_1(self):
        svc = _make_feed_config_svc_with_setting("1")
        assert svc.read_feed_enabled(self._noop_db(), "misp") is True

    def test_returns_false_for_0(self):
        svc = _make_feed_config_svc_with_setting("0")
        assert svc.read_feed_enabled(self._noop_db(), "misp") is False

    def test_returns_true_for_yes(self):
        svc = _make_feed_config_svc_with_setting("yes")
        assert svc.read_feed_enabled(self._noop_db(), "misp") is True

    def test_returns_false_for_off(self):
        svc = _make_feed_config_svc_with_setting("off")
        assert svc.read_feed_enabled(self._noop_db(), "misp") is False


# ---------------------------------------------------------------------------
# _read_feed_config_state
# ---------------------------------------------------------------------------

class TestReadFeedConfigState:
    def _svc(self, setting_value="", abusech_key=""):
        from app.services.feed_config_svc import make_feed_config_service
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        return make_feed_config_service(
            cfg=SimpleNamespace(ABUSECH_AUTH_KEY=abusech_key),
            get_setting_fn=MagicMock(return_value=setting_value),
            set_setting_fn=MagicMock(),
            secret_decrypt_fn=MagicMock(return_value=setting_value),
        )

    def _mock_feed(self, source_type, source_id, base_url=""):
        from unittest.mock import MagicMock
        f = MagicMock()
        f.source_type = source_type
        f.source_id = source_id
        f.base_url = base_url
        f.enabled = True
        f.display_name = source_type.title()
        return f

    def _noop_db(self):
        from unittest.mock import MagicMock
        m = MagicMock()
        m.scalar.return_value = None
        return m

    def test_unknown_source_type_returns_not_ready(self):
        svc = self._svc()
        f = self._mock_feed("unknown_type", "x")
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert state["ready"] is False
        assert "unknown source type" in state["missing"]

    def test_misp_with_base_url_has_fields(self):
        svc = self._svc(setting_value="token123")
        f = self._mock_feed("misp", "misp", base_url="http://misp.example.com")
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert isinstance(state.get("fields"), list)
        assert state["source_id"] == "misp"

    def test_misp_missing_base_url_not_ready(self):
        svc = self._svc(setting_value="")
        f = self._mock_feed("misp", "misp")
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert state["ready"] is False

    def test_malwarebazaar_missing_key_reported(self):
        svc = self._svc(setting_value="", abusech_key="")
        f = self._mock_feed("malwarebazaar", "malwarebazaar")
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert any("abuse.ch" in m for m in state["missing"])

    def test_malwarebazaar_with_abusech_env_key_not_missing(self):
        svc = self._svc(setting_value="", abusech_key="env-key")
        f = self._mock_feed("malwarebazaar", "malwarebazaar")
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert not any("abuse.ch" in m for m in state["missing"])

    def test_crowdsec_returns_fields_list(self):
        svc = self._svc(setting_value="somekey")
        f = self._mock_feed("crowdsec", "crowdsec")
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert isinstance(state.get("fields"), list)

    def test_abusech_returns_fields_list(self):
        svc = self._svc(setting_value="somekey")
        f = self._mock_feed("abusech", "abusech")
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert isinstance(state.get("fields"), list)

    def test_mwdb_returns_fields_list(self):
        svc = self._svc(setting_value="somekey")
        f = self._mock_feed("mwdb", "mwdb", base_url="http://mwdb.example.com")
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert isinstance(state.get("fields"), list)

    def test_state_includes_enabled_flag(self):
        svc = self._svc(setting_value="k")
        f = self._mock_feed("crowdsec", "crowdsec")
        f.enabled = False
        state = svc.read_feed_config_state(self._noop_db(), f)
        assert state["enabled"] is False

    def test_checkbox_field_checked_value(self):
        def get_setting(db, key, default="", secret=False):
            if "verify_ssl" in key:
                return "1"
            return ""

        from app.services.feed_config_svc import make_feed_config_service
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        svc = make_feed_config_service(
            cfg=SimpleNamespace(ABUSECH_AUTH_KEY=""),
            get_setting_fn=get_setting,
            set_setting_fn=MagicMock(),
            secret_decrypt_fn=MagicMock(return_value="1"),
        )
        f = self._mock_feed("misp", "misp", base_url="http://misp.example.com")
        state = svc.read_feed_config_state(self._noop_db(), f)
        cb_fields = [x for x in state["fields"] if x["type"] == "checkbox"]
        if cb_fields:
            assert cb_fields[0]["checked"] is True


# ---------------------------------------------------------------------------
# _get_feed_field_value
# ---------------------------------------------------------------------------

class TestGetFeedFieldValue:
    def _svc(self, stored="stored-value"):
        from app.services.feed_config_svc import make_feed_config_service
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        return make_feed_config_service(
            cfg=SimpleNamespace(ABUSECH_AUTH_KEY=""),
            get_setting_fn=MagicMock(return_value=stored),
            set_setting_fn=MagicMock(),
            secret_decrypt_fn=MagicMock(return_value=stored),
        )

    def _noop_db(self):
        from unittest.mock import MagicMock
        m = MagicMock()
        m.scalar.return_value = None
        return m

    def _feed(self, source_type="misp", base_url=""):
        from unittest.mock import MagicMock
        f = MagicMock()
        f.source_type = source_type
        f.source_id = source_type
        f.base_url = base_url
        return f

    def test_base_url_from_form(self):
        svc = self._svc()
        f = self._feed(base_url="http://old.example.com")
        field = {"key": "base_url", "input_name": "base_url", "type": "text", "secret": False}
        val = svc.get_feed_field_value(self._noop_db(), f, field, {"base_url": "http://new.example.com"})
        assert val == "http://new.example.com"

    def test_base_url_falls_back_to_feed_attr(self):
        svc = self._svc()
        f = self._feed(base_url="http://feed.example.com")
        field = {"key": "base_url", "input_name": "base_url", "type": "text", "secret": False}
        val = svc.get_feed_field_value(self._noop_db(), f, field, {"base_url": ""})
        assert val == "http://feed.example.com"

    def test_non_secret_returns_form_value(self):
        svc = self._svc()
        f = self._feed()
        field = {"key": "api_key", "input_name": "api_key", "type": "text", "secret": False}
        val = svc.get_feed_field_value(self._noop_db(), f, field, {"api_key": "form-value"})
        assert val == "form-value"

    def test_secret_empty_form_returns_stored(self):
        svc = self._svc(stored="stored-secret")
        f = self._feed()
        field = {"key": "api_key", "input_name": "api_key", "type": "password", "secret": True}
        val = svc.get_feed_field_value(self._noop_db(), f, field, {"api_key": ""})
        assert val == "stored-secret"

    def test_checkbox_on_returns_1(self):
        svc = self._svc()
        f = self._feed()
        field = {"key": "verify_ssl", "input_name": "verify_ssl", "type": "checkbox", "secret": False}
        val = svc.get_feed_field_value(self._noop_db(), f, field, {"verify_ssl": "on"})
        assert val == "1"

    def test_checkbox_empty_returns_0(self):
        svc = self._svc()
        f = self._feed()
        field = {"key": "verify_ssl", "input_name": "verify_ssl", "type": "checkbox", "secret": False}
        val = svc.get_feed_field_value(self._noop_db(), f, field, {"verify_ssl": ""})
        assert val == "0"

    def test_no_form_data_returns_stored(self):
        svc = self._svc(stored="stored-value")
        f = self._feed()
        field = {"key": "api_key", "input_name": "api_key", "type": "text", "secret": False}
        val = svc.get_feed_field_value(self._noop_db(), f, field, None)
        assert val == "stored-value"

    def test_secret_with_form_value_returns_form(self):
        svc = self._svc(stored="old-secret")
        f = self._feed()
        field = {"key": "api_key", "input_name": "api_key", "type": "password", "secret": True}
        val = svc.get_feed_field_value(self._noop_db(), f, field, {"api_key": "new-secret"})
        assert val == "new-secret"


# ---------------------------------------------------------------------------
# _ensure_default_feeds
# ---------------------------------------------------------------------------

class TestEnsureDefaultFeeds:
    def test_creates_defaults_when_no_feeds(self):
        from app.services.feed_config_svc import make_feed_config_service
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        svc = make_feed_config_service(
            cfg=SimpleNamespace(ABUSECH_AUTH_KEY=""),
            get_setting_fn=MagicMock(return_value=""),
            set_setting_fn=MagicMock(),
            secret_decrypt_fn=MagicMock(return_value=""),
        )
        mock_db = MagicMock()
        mock_db.scalars.return_value.all.return_value = []
        svc.ensure_default_feeds(mock_db)
        assert mock_db.add.call_count == 5
        mock_db.commit.assert_called_once()

    def test_skips_when_feeds_exist(self):
        from app.services.feed_config_svc import make_feed_config_service
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        svc = make_feed_config_service(
            cfg=SimpleNamespace(ABUSECH_AUTH_KEY=""),
            get_setting_fn=MagicMock(return_value=""),
            set_setting_fn=MagicMock(),
            secret_decrypt_fn=MagicMock(return_value=""),
        )
        mock_db = MagicMock()
        mock_db.scalars.return_value.all.return_value = [MagicMock()]
        svc.ensure_default_feeds(mock_db)
        mock_db.add.assert_not_called()
