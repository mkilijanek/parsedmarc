"""Tests for app/adapters/feeds.py — adapter unit tests. Closes #234."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.adapters.feeds import (
    AbuseChFeedAdapter,
    BaseFeedAdapter,
    CrowdSecFeedAdapter,
    MalwareBazaarFeedAdapter,
    MispFeedAdapter,
    MwdbFeedAdapter,
    build_feed_registry,
)
from app.adapters.types import AdapterCapabilities, CanonicalIOC, FetchBatch
from app.config import Config
from app.runtime_env import clear_runtime_env_overrides, push_runtime_env_overrides


_BASE_ENV = {
    "SECRET_KEY": "test-secret-key-at-least-32-characters-long",
    "CROWDSEC_API_KEY": "",
    "CROWDSEC_LISTS": "",
    "MISP_URL": "",
    "MISP_API_KEY": "",
    "MALWAREBAZAAR_TAGS": "",
    "MWDB_URL": "",
    "MWDB_AUTH_KEY": "",
    "ABUSECH_AUTH_KEY": "",
    "THREATFOX_ENABLED": "0",
    "URLHAUS_ENABLED": "0",
    "FEODOTRACKER_ENABLED": "0",
    "YARAIFY_ENABLED": "0",
    "HUNTING_FPLIST_ENABLED": "0",
    "FEED_HTTP_TIMEOUT_S": "10",
    "FEED_RETRY_ATTEMPTS": "1",
    "FEED_RETRY_BASE_DELAY_S": "1",
    "ABUSECH_RETRY_ATTEMPTS": "1",
    "ABUSECH_RETRY_BASE_DELAY_S": "1",
    "ABUSECH_TIMEOUT_S": "10",
    "MWDB_DAYS": "7",
    "MWDB_LIMIT": "100",
    "MWDB_NO_TIME_LIMIT": "0",
    "MWDB_ORGANIZATIONS": "",
    "MWDB_MY_GROUP": "",
    "MWDB_TAGS": "",
    "MWDB_CUSTOM_FILTER": "",
    "MWDB_DEFAULT_QUERY": "",
    "MWDB_CIRCUIT_FAIL_THRESHOLD": "3",
    "MWDB_CIRCUIT_COOLDOWN_S": "60",
    "MALWAREBAZAAR_SINCE_DATE": "",
    "MALWAREBAZAAR_LIMIT": "100",
    "MALWAREBAZAAR_API_URL": "https://mb.api",
    "MISP_DAYS": "7",
    "MISP_MAX_TLP": "AMBER",
    "MISP_CIRCUIT_FAIL_THRESHOLD": "3",
    "MISP_CIRCUIT_COOLDOWN_S": "60",
    "THREATFOX_API_URL": "https://threatfox.api",
    "THREATFOX_AUTH_KEY": "",
    "THREATFOX_DAYS": "3",
    "THREATFOX_LIMIT": "100",
    "URLHAUS_FEED_URL": "https://urlhaus.api",
    "URLHAUS_LIMIT": "100",
    "FEODOTRACKER_FEED_URL": "https://feodo.api",
    "FEODOTRACKER_LIMIT": "100",
    "YARAIFY_API_URL": "https://yaraify.api",
    "YARAIFY_AUTH_KEY": "",
    "YARAIFY_IDENTIFIER": "",
    "YARAIFY_TASK_STATUS": "succeeded",
    "YARAIFY_LIMIT": "50",
    "YARAIFY_LOOKUP_HASHES": "",
    "HUNTING_API_URL": "https://hunting.api",
    "HUNTING_AUTH_KEY": "",
    "HUNTING_FPLIST_FORMAT": "json",
    "HUNTING_FPLIST_LIMIT": "100",
    "DATABASE_URL": "sqlite:///:memory:",
}


def _make_cfg(**overrides) -> Config:
    env = {**_BASE_ENV, **{k: str(v) for k, v in overrides.items()}}
    with push_runtime_env_overrides(env):
        return Config()


def _noop_db():
    mock = MagicMock()
    mock.close = MagicMock()
    mock.commit = MagicMock()
    mock.rollback = MagicMock()
    return mock


# ── BaseFeedAdapter ───────────────────────────────────────────────────────────

class TestBaseFeedAdapter:
    def _make(self):
        class ConcreteAdapter(BaseFeedAdapter):
            source_type = "test"
            capabilities = AdapterCapabilities(supported_ioc_types=("ip",))

            def fetch_batches(self):
                return [FetchBatch(source="test", items=(), metadata={})]

        db = _noop_db()
        cfg = _make_cfg()
        return ConcreteAdapter(cfg=cfg, db_factory=lambda: db), db

    def test_execute_calls_fetch_and_persist(self):
        adapter, db = self._make()
        with patch("app.adapters.feeds.persist_batches", return_value={"test": {"fetched": 0, "deactivated": 0, "errors": 0}}):
            result = adapter.execute()
        assert "fetched" in result

    def test_execute_rolls_back_on_exception(self):
        cfg = _make_cfg()

        class FailAdapter(BaseFeedAdapter):
            source_type = "fail"
            capabilities = AdapterCapabilities(supported_ioc_types=("ip",))
            def fetch_batches(self):
                raise RuntimeError("boom")

        db = _noop_db()
        adapter = FailAdapter(cfg=cfg, db_factory=lambda: db)
        with patch("app.adapters.feeds.mark_feed_error"):
            with pytest.raises(RuntimeError, match="boom"):
                adapter.execute()
        db.rollback.assert_called_once()

    def test_execute_closes_db_on_success(self):
        adapter, db = self._make()
        with patch("app.adapters.feeds.persist_batches", return_value={"test": {"fetched": 0, "deactivated": 0, "errors": 0}}):
            adapter.execute()
        db.close.assert_called_once()

    def test_execute_closes_db_on_failure(self):
        cfg = _make_cfg()

        class FailAdapter(BaseFeedAdapter):
            source_type = "fail"
            capabilities = AdapterCapabilities(supported_ioc_types=("ip",))
            def fetch_batches(self):
                raise RuntimeError("fail")

        db = _noop_db()
        adapter = FailAdapter(cfg=cfg, db_factory=lambda: db)
        with patch("app.adapters.feeds.mark_feed_error"):
            with pytest.raises(RuntimeError):
                adapter.execute()
        db.close.assert_called_once()

    def test_format_success_aggregates_counts(self):
        adapter, _ = self._make()
        results = {
            "a": {"fetched": 10, "deactivated": 2, "errors": 1},
            "b": {"fetched": 5, "deactivated": 0, "errors": 0},
        }
        out = adapter._format_success(results)
        assert out["fetched"] == 15
        assert out["deactivated"] == 2
        assert out["errors"] == 1


# ── CrowdSecFeedAdapter ───────────────────────────────────────────────────────

class TestCrowdSecFeedAdapter:
    def test_fetch_batches_raises_if_no_api_key(self):
        cfg = _make_cfg(CROWDSEC_API_KEY="")
        adapter = CrowdSecFeedAdapter(cfg=cfg)
        with pytest.raises(RuntimeError, match="CROWDSEC_API_KEY"):
            adapter.fetch_batches()

    def test_fetch_batches_returns_batch_per_list(self):
        cfg = _make_cfg(CROWDSEC_API_KEY="key123", CROWDSEC_LISTS="list1,list2")
        adapter = CrowdSecFeedAdapter(cfg=cfg)
        with patch("app.adapters.feeds._fetch_list", return_value=["1.2.3.4", "5.6.7.8"]):
            batches = adapter.fetch_batches()
        assert len(batches) == 2
        assert batches[0].source == "crowdsec"
        assert all(ioc.ioc_type == "ip" for ioc in batches[0].items)

    def test_fetch_batches_empty_list_ids_returns_empty(self):
        cfg = _make_cfg(CROWDSEC_API_KEY="key123", CROWDSEC_LISTS="")
        adapter = CrowdSecFeedAdapter(cfg=cfg)
        batches = adapter.fetch_batches()
        assert batches == []

    def test_format_success_uses_lists_key(self):
        cfg = _make_cfg()
        adapter = CrowdSecFeedAdapter(cfg=cfg)
        out = adapter._format_success({"list1": {"fetched": 3, "deactivated": 0, "errors": 0}})
        assert out["fetched"] == 3
        assert "lists" in out["details"]


# ── MispFeedAdapter ───────────────────────────────────────────────────────────

class TestMispFeedAdapter:
    def test_execute_skips_if_not_configured(self):
        cfg = _make_cfg(MISP_URL="", MISP_API_KEY="")
        adapter = MispFeedAdapter(cfg=cfg, db_factory=_noop_db)
        result = adapter.execute()
        assert result.get("skipped") == 1
        assert result.get("reason") == "not_configured"

    def test_execute_skips_if_circuit_open(self):
        cfg = _make_cfg(MISP_URL="https://misp.example", MISP_API_KEY="key")
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = True
            adapter = MispFeedAdapter(cfg=cfg)
            result = adapter.execute()
        assert result.get("skipped") == 1

    def test_fetch_batches_raises_if_not_configured(self):
        cfg = _make_cfg(MISP_URL="", MISP_API_KEY="")
        adapter = MispFeedAdapter(cfg=cfg)
        with patch("app.adapters.feeds._dep_status"):
            with pytest.raises(RuntimeError, match="not_configured"):
                adapter.fetch_batches()

    def test_fetch_batches_raises_if_circuit_open(self):
        cfg = _make_cfg(MISP_URL="https://misp.example", MISP_API_KEY="key")
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = True
            adapter = MispFeedAdapter(cfg=cfg)
            with pytest.raises(RuntimeError, match="circuit_open"):
                adapter.fetch_batches()

    def test_fetch_batches_returns_empty_batch_when_no_attrs(self):
        cfg = _make_cfg(MISP_URL="https://misp.example", MISP_API_KEY="key")
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = False
            with patch("app.adapters.feeds._fetch_misp_attributes", return_value=[]):
                adapter = MispFeedAdapter(cfg=cfg)
                batches = adapter.fetch_batches()
        assert len(batches) == 1
        assert batches[0].items == tuple()

    def test_fetch_batches_groups_by_event(self):
        cfg = _make_cfg(MISP_URL="https://misp.example", MISP_API_KEY="key")
        attrs = [
            {
                "type": "ip-src", "value": "10.0.0.1",
                "event_id": "42",
                "Event": {"id": "42", "distribution": 3, "Tag": []},
                "Tag": [{"name": "tlp:green"}],
                "id": "1", "category": "Network", "comment": "", "timestamp": "1700000000",
            },
            {
                "type": "domain", "value": "evil.example",
                "event_id": "42",
                "Event": {"id": "42", "distribution": 3, "Tag": []},
                "Tag": [{"name": "tlp:green"}],
                "id": "2", "category": "Network", "comment": "", "timestamp": "1700000000",
            },
        ]
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = False
            with patch("app.adapters.feeds._fetch_misp_attributes", return_value=attrs):
                adapter = MispFeedAdapter(cfg=cfg)
                batches = adapter.fetch_batches()
        assert len(batches) == 1
        assert len(batches[0].items) == 2

    def test_execute_records_success(self):
        cfg = _make_cfg(MISP_URL="https://misp.example", MISP_API_KEY="key")
        adapter = MispFeedAdapter(cfg=cfg, db_factory=_noop_db)
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = False
            with patch("app.adapters.feeds._fetch_misp_attributes", return_value=[]):
                with patch("app.adapters.feeds.persist_batches", return_value={"misp": {"fetched": 0, "deactivated": 0, "errors": 0}}):
                    result = adapter.execute()
        cb.record_success.assert_called_once_with("misp")
        assert result["fetched"] == 0

    def test_execute_records_failure_and_reraises(self):
        cfg = _make_cfg(MISP_URL="https://misp.example", MISP_API_KEY="key")
        adapter = MispFeedAdapter(cfg=cfg, db_factory=_noop_db)
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = False
            with patch("app.adapters.feeds._fetch_misp_attributes", side_effect=RuntimeError("network")):
                with patch("app.adapters.feeds.mark_feed_error"):
                    with pytest.raises(RuntimeError, match="network"):
                        adapter.execute()
        cb.record_failure.assert_called_once()


# ── MalwareBazaarFeedAdapter ──────────────────────────────────────────────────

class TestMalwareBazaarFeedAdapter:
    def test_fetch_batches_no_tags_returns_empty(self):
        cfg = _make_cfg(MALWAREBAZAAR_TAGS="")
        adapter = MalwareBazaarFeedAdapter(cfg=cfg)
        batches = adapter.fetch_batches()
        assert len(batches) == 1
        assert batches[0].items == tuple()
        assert batches[0].metadata["reason"] == "no_tags"

    def test_fetch_batches_with_tags_calls_fetch(self):
        cfg = _make_cfg(MALWAREBAZAAR_TAGS="emotet,trickbot", MALWAREBAZAAR_LIMIT="10")
        adapter = MalwareBazaarFeedAdapter(cfg=cfg)
        row = {
            "ioc_value": "abc123", "ioc_type": "hash", "source_ref": "abc123",
            "first_seen": None, "last_seen": None, "confidence": 70,
            "tlp": "GREEN", "tags": ["emotet"], "metadata": {},
        }
        with patch("app.adapters.feeds.fetch_malwarebazaar_by_tags", return_value=[row]):
            batches = adapter.fetch_batches()
        assert len(batches) == 1
        assert len(batches[0].items) == 1
        assert batches[0].items[0].value == "abc123"

    def test_fetch_batches_sets_tlp_and_confidence(self):
        cfg = _make_cfg(MALWAREBAZAAR_TAGS="malware", MALWAREBAZAAR_LIMIT="10")
        adapter = MalwareBazaarFeedAdapter(cfg=cfg)
        row = {
            "ioc_value": "deadbeef", "ioc_type": "hash", "source_ref": "deadbeef",
            "first_seen": None, "last_seen": None, "confidence": 80,
            "tlp": "AMBER", "tags": [], "metadata": {"extra": 1},
        }
        with patch("app.adapters.feeds.fetch_malwarebazaar_by_tags", return_value=[row]):
            batches = adapter.fetch_batches()
        ioc = batches[0].items[0]
        assert ioc.tlp == "AMBER"
        assert ioc.confidence == 80


# ── MwdbFeedAdapter ───────────────────────────────────────────────────────────

class TestMwdbFeedAdapter:
    def _cfg(self):
        return _make_cfg(MWDB_URL="https://mwdb.example", MWDB_AUTH_KEY="key",
                         MWDB_TAGS="apt", MWDB_DAYS="7", MWDB_LIMIT="50")

    def test_execute_skips_if_circuit_open(self):
        cfg = self._cfg()
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = True
            adapter = MwdbFeedAdapter(cfg=cfg)
            result = adapter.execute()
        assert result["fetched"] == 0
        assert result["details"]["skipped"] == 1

    def test_fetch_batches_returns_items(self):
        cfg = self._cfg()
        row = {
            "ioc_value": "bad.example.com", "ioc_type": "domain",
            "source_ref": "obj-1", "first_seen": None, "last_seen": None,
            "confidence": 65, "tlp": "GREEN", "tags": ["apt"], "metadata": {},
        }
        adapter = MwdbFeedAdapter(cfg=cfg)
        with patch("app.adapters.feeds.fetch_mwdb_by_tags", return_value=[row]):
            batches = adapter.fetch_batches()
        assert len(batches) == 1
        assert batches[0].items[0].value == "bad.example.com"

    def test_fetch_batches_no_time_limit(self):
        cfg = _make_cfg(MWDB_URL="https://mwdb.example", MWDB_AUTH_KEY="key",
                        MWDB_NO_TIME_LIMIT="1", MWDB_TAGS="", MWDB_LIMIT="10",
                        MWDB_DAYS="0")
        adapter = MwdbFeedAdapter(cfg=cfg)
        with patch("app.adapters.feeds.fetch_mwdb_by_tags", return_value=[]):
            batches = adapter.fetch_batches()
        assert batches[0].metadata["days"] is None

    def test_execute_records_success(self):
        cfg = self._cfg()
        adapter = MwdbFeedAdapter(cfg=cfg, db_factory=_noop_db)
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = False
            with patch("app.adapters.feeds.fetch_mwdb_by_tags", return_value=[]):
                with patch("app.adapters.feeds.persist_batches", return_value={"mwdb": {"fetched": 0, "deactivated": 0, "errors": 0}}):
                    adapter.execute()
        cb.record_success.assert_called_once_with("mwdb")

    def test_execute_records_failure(self):
        cfg = self._cfg()
        adapter = MwdbFeedAdapter(cfg=cfg, db_factory=_noop_db)
        with patch("app.adapters.feeds._circuit_breaker") as cb:
            cb.is_open.return_value = False
            with patch("app.adapters.feeds.fetch_mwdb_by_tags", side_effect=RuntimeError("timeout")):
                with patch("app.adapters.feeds.mark_feed_error"):
                    with pytest.raises(RuntimeError):
                        adapter.execute()
        cb.record_failure.assert_called_once()


# ── AbuseChFeedAdapter ────────────────────────────────────────────────────────

class TestAbuseChFeedAdapter:
    def _adapter(self, **extra):
        cfg = _make_cfg(ABUSECH_AUTH_KEY="key", **extra)
        db = _noop_db()
        return AbuseChFeedAdapter(cfg=cfg, db_factory=lambda: db), db

    def test_fetch_batches_no_sources_enabled_returns_empty(self):
        adapter, _ = self._adapter()
        runtime_cfg = _make_cfg(
            ABUSECH_AUTH_KEY="key",
            THREATFOX_ENABLED="0", URLHAUS_ENABLED="0",
            FEODOTRACKER_ENABLED="0", YARAIFY_ENABLED="0",
            HUNTING_FPLIST_ENABLED="0",
        )
        with patch.object(adapter, "_load_runtime_config", return_value=runtime_cfg):
            with patch("app.adapters.feeds._validate_abusech_config"):
                batches = adapter.fetch_batches()
        assert batches == []

    def test_fetch_batches_threatfox_enabled(self):
        adapter, _ = self._adapter()
        runtime_cfg = _make_cfg(
            ABUSECH_AUTH_KEY="key",
            THREATFOX_ENABLED="1", URLHAUS_ENABLED="0",
            FEODOTRACKER_ENABLED="0", YARAIFY_ENABLED="0",
            HUNTING_FPLIST_ENABLED="0",
        )
        row = {
            "ioc_value": "1.2.3.4", "ioc_type": "ip", "source_ref": "ref",
            "first_seen": None, "last_seen": None, "confidence": 70,
            "tlp": "GREEN", "tags": [], "metadata": {},
        }
        with patch.object(adapter, "_load_runtime_config", return_value=runtime_cfg):
            with patch("app.adapters.feeds._validate_abusech_config"):
                with patch("app.adapters.feeds.fetch_threatfox_iocs", return_value=iter([row])):
                    batches = adapter.fetch_batches()
        assert len(batches) == 1
        assert batches[0].source == "threatfox"

    def test_fetch_batches_urlhaus_enabled(self):
        adapter, _ = self._adapter()
        runtime_cfg = _make_cfg(
            ABUSECH_AUTH_KEY="key",
            THREATFOX_ENABLED="0", URLHAUS_ENABLED="1",
            FEODOTRACKER_ENABLED="0", YARAIFY_ENABLED="0",
            HUNTING_FPLIST_ENABLED="0",
        )
        row = {"ioc_value": "http://bad.example", "ioc_type": "url", "source_ref": "ref",
               "first_seen": None, "last_seen": None, "confidence": 60,
               "tlp": "GREEN", "tags": [], "metadata": {}}
        with patch.object(adapter, "_load_runtime_config", return_value=runtime_cfg):
            with patch("app.adapters.feeds._validate_abusech_config"):
                with patch("app.adapters.feeds.fetch_urlhaus_urls", return_value=iter([row])):
                    batches = adapter.fetch_batches()
        assert batches[0].source == "urlhaus"

    def test_fetch_batches_feodotracker_enabled(self):
        adapter, _ = self._adapter()
        runtime_cfg = _make_cfg(
            ABUSECH_AUTH_KEY="key",
            THREATFOX_ENABLED="0", URLHAUS_ENABLED="0",
            FEODOTRACKER_ENABLED="1", YARAIFY_ENABLED="0",
            HUNTING_FPLIST_ENABLED="0",
        )
        row = {"ioc_value": "9.9.9.9", "ioc_type": "ip", "source_ref": "ref",
               "first_seen": None, "last_seen": None, "confidence": 75,
               "tlp": "GREEN", "tags": [], "metadata": {}}
        with patch.object(adapter, "_load_runtime_config", return_value=runtime_cfg):
            with patch("app.adapters.feeds._validate_abusech_config"):
                with patch("app.adapters.feeds.fetch_feodotracker_ips", return_value=iter([row])):
                    batches = adapter.fetch_batches()
        assert batches[0].source == "feodotracker"

    def test_format_success_includes_source_keys(self):
        adapter, _ = self._adapter()
        results = {"threatfox": {"fetched": 5, "deactivated": 0, "errors": 0}}
        out = adapter._format_success(results)
        assert out["fetched"] == 5
        assert "threatfox" in out


# ── build_feed_registry ───────────────────────────────────────────────────────

class TestBuildFeedRegistry:
    def test_contains_all_sources(self):
        registry = build_feed_registry()
        assert set(registry.keys()) == {"crowdsec", "misp", "malwarebazaar", "mwdb", "abusech"}

    def test_adapters_have_correct_source_type(self):
        registry = build_feed_registry()
        for name in ("crowdsec", "misp", "malwarebazaar", "mwdb", "abusech"):
            assert registry.get(name).source_type == name

    def test_custom_cfg_passed_through(self):
        cfg = _make_cfg(MISP_URL="https://custom.misp", MISP_API_KEY="k")
        registry = build_feed_registry(cfg=cfg)
        assert registry.get("misp").cfg.MISP_URL == "https://custom.misp"
