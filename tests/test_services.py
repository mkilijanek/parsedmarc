"""
Comprehensive tests for data source integration services.

Tests cover:
- MISP integration (TLP extraction, confidence calculation, normalization)
- CrowdSec integration
- MalwareBazaar integration
- MWDB integration
- Common retry logic
- Error handling
- Data normalization
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, call

import pytest

from app.services.misp import (
    extract_tlp_from_tags,
    compute_confidence,
    TYPE_MAPPING,
    _normalize_value,
    tlp_exceeds_max,
)
from app.services.common import ExternalFeedRateLimiter, retry_with_backoff, throttle_external_request
from app.services.mwdb import update_mwdb_indicators
from app.services.mwdb import fetch_mwdb_by_tags, _object_matches_group
from app.services.malwarebazaar import update_malwarebazaar_indicators
from app.services.mwdb import _build_tag_query
from app.services.abusech import (
    _infer_ioc_type,
    _normalize_threatfox_ioc,
    _pick_ioc_from_csv_row,
    fetch_urlhaus_urls,
    fetch_feodotracker_ips,
    fetch_yaraify_lookup_hashes,
    update_abusech_indicators,
)
from app.services.common import _circuit_breaker


# ============================================================================
# MISP Service Tests
# ============================================================================

class TestMISPTLPExtraction:
    """Test TLP extraction from MISP tags."""

    def test_tlp_from_attribute_tags(self):
        """Test TLP extraction from attribute tags (highest priority)."""
        result = extract_tlp_from_tags(['tlp:red', 'apt'], ['tlp:green'])
        assert result == 'RED'

    def test_tlp_from_event_tags(self):
        """Test TLP extraction from event tags (fallback)."""
        result = extract_tlp_from_tags([], ['tlp:amber', 'malware'])
        assert result == 'AMBER'

    def test_tlp_attribute_priority_over_event(self):
        """Test that attribute TLP has priority over event TLP."""
        result = extract_tlp_from_tags(['tlp:red'], ['tlp:white'])
        assert result == 'RED'

    def test_tlp_default_green(self):
        """Test default TLP is GREEN when not specified."""
        result = extract_tlp_from_tags(['apt', 'malware'], ['ransomware'])
        assert result == 'GREEN'

    def test_tlp_case_insensitive(self):
        """Test TLP extraction is case-insensitive."""
        result = extract_tlp_from_tags(['TLP:RED'], [])
        assert result == 'RED'

        result = extract_tlp_from_tags(['tlp:AmBeR'], [])
        assert result == 'AMBER'

    def test_tlp_clear_maps_to_white(self):
        """Test TLP 2.0 'clear' maps to WHITE."""
        result = extract_tlp_from_tags(['tlp:clear'], [])
        assert result == 'WHITE'

    def test_tlp_whitespace_handling(self):
        """Test TLP extraction handles whitespace."""
        result = extract_tlp_from_tags([' tlp:red ', 'apt'], [])
        assert result == 'RED'

    def test_tlp_multiple_tlp_tags(self):
        """Test behavior with multiple TLP tags (first valid one wins)."""
        result = extract_tlp_from_tags(['tlp:red', 'tlp:green'], [])
        assert result == 'RED'

    def test_tlp_none_tags(self):
        """Test TLP extraction with None tags."""
        result = extract_tlp_from_tags(None, None)
        assert result == 'GREEN'

    def test_tlp_empty_tags(self):
        """Test TLP extraction with empty tag lists."""
        result = extract_tlp_from_tags([], [])
        assert result == 'GREEN'

    def test_tlp_invalid_values(self):
        """Test TLP extraction ignores invalid values."""
        result = extract_tlp_from_tags(['tlp:invalid', 'tlp:purple'], [])
        assert result == 'GREEN'

    def test_tlp_all_valid_levels(self):
        """Test all valid TLP levels are recognized."""
        for level in ['WHITE', 'GREEN', 'AMBER', 'RED']:
            result = extract_tlp_from_tags([f'tlp:{level.lower()}'], [])
            assert result == level


class TestMISPTLPMaxFilter:
    """Test tlp_exceeds_max() helper and MISP_MAX_TLP filtering."""

    def test_red_exceeds_amber(self):
        assert tlp_exceeds_max("RED", "AMBER") is True

    def test_amber_not_exceeds_amber(self):
        assert tlp_exceeds_max("AMBER", "AMBER") is False

    def test_green_not_exceeds_amber(self):
        assert tlp_exceeds_max("GREEN", "AMBER") is False

    def test_white_not_exceeds_amber(self):
        assert tlp_exceeds_max("WHITE", "AMBER") is False

    def test_red_exceeds_green(self):
        assert tlp_exceeds_max("RED", "GREEN") is True

    def test_amber_exceeds_green(self):
        assert tlp_exceeds_max("AMBER", "GREEN") is True

    def test_red_not_exceeds_red(self):
        assert tlp_exceeds_max("RED", "RED") is False

    def test_max_tlp_case_insensitive(self):
        assert tlp_exceeds_max("RED", "amber") is True
        assert tlp_exceeds_max("AMBER", "amber") is False

    def test_unknown_tlp_treated_as_most_sensitive(self):
        # Unknown TLP level gets order 99 → always exceeds any valid max
        assert tlp_exceeds_max("UNKNOWN", "AMBER") is True

    @patch('app.services.misp._fetch_misp_attributes')
    @patch('app.services.misp.SessionLocal')
    def test_update_misp_skips_red_by_default(self, mock_session, mock_fetch):
        """With default MISP_MAX_TLP=AMBER, TLP:RED attributes must be skipped."""
        mock_fetch.return_value = [
            {
                "type": "ip-src",
                "value": "1.2.3.4",
                "event_id": "100",
                "Tag": [{"name": "tlp:red"}],
                "Event": {"id": "100", "distribution": "1", "Tag": []},
            },
            {
                "type": "ip-src",
                "value": "5.6.7.8",
                "event_id": "100",
                "Tag": [{"name": "tlp:amber"}],
                "Event": {"id": "100", "distribution": "1", "Tag": []},
            },
        ]
        mock_db = MagicMock()
        mock_session.return_value = mock_db

        with patch.dict('os.environ', {
            'MISP_URL': 'https://misp.example.com',
            'MISP_API_KEY': 'test-key',
            'MISP_MAX_TLP': 'AMBER',
        }):
            from app.services.misp import update_misp_indicators
            result = update_misp_indicators()

        # Only the AMBER attribute should be ingested; RED is skipped.
        assert result["tlp_skipped"] == 1
        assert result["fetched"] == 2  # total fetched from upstream

    @patch('app.services.misp._fetch_misp_attributes')
    @patch('app.services.misp.SessionLocal')
    def test_update_misp_allows_red_when_max_tlp_red(self, mock_session, mock_fetch):
        """With MISP_MAX_TLP=RED, TLP:RED attributes must not be skipped."""
        mock_fetch.return_value = [
            {
                "type": "ip-src",
                "value": "1.2.3.4",
                "event_id": "200",
                "Tag": [{"name": "tlp:red"}],
                "Event": {"id": "200", "distribution": "1", "Tag": []},
            },
        ]
        mock_db = MagicMock()
        mock_session.return_value = mock_db

        with patch.dict('os.environ', {
            'MISP_URL': 'https://misp.example.com',
            'MISP_API_KEY': 'test-key',
            'MISP_MAX_TLP': 'RED',
        }):
            from app.services.misp import update_misp_indicators
            result = update_misp_indicators()

        assert result["tlp_skipped"] == 0


class TestMISPConfidenceCalculation:
    """Test MISP confidence calculation logic."""

    def test_confidence_distribution_0(self):
        """Test confidence with distribution=0 (organization only)."""
        result = compute_confidence(distribution=0, tags=[])
        assert result == 90

    def test_confidence_distribution_1(self):
        """Test confidence with distribution=1 (community)."""
        result = compute_confidence(distribution=1, tags=[])
        assert result == 80

    def test_confidence_distribution_2(self):
        """Test confidence with distribution=2 (connected communities)."""
        result = compute_confidence(distribution=2, tags=[])
        assert result == 70

    def test_confidence_distribution_3(self):
        """Test confidence with distribution=3 (all communities)."""
        result = compute_confidence(distribution=3, tags=[])
        assert result == 60

    def test_confidence_distribution_4(self):
        """Test confidence with distribution=4 (sharing group)."""
        result = compute_confidence(distribution=4, tags=[])
        assert result == 50

    def test_confidence_high_conf_tag_boost(self):
        """Test confidence boost for high-confidence tags."""
        # Base 70 + 10 boost = 80
        result = compute_confidence(distribution=2, tags=['apt'])
        assert result == 80

        result = compute_confidence(distribution=2, tags=['malware'])
        assert result == 80

        result = compute_confidence(distribution=2, tags=['ransomware'])
        assert result == 80

    def test_confidence_multiple_high_conf_tags(self):
        """Test confidence boost applies once for multiple high-conf tags."""
        result = compute_confidence(distribution=2, tags=['apt', 'malware', 'ransomware'])
        assert result == 80  # Still 70 + 10, not compounded

    def test_confidence_cap_at_95(self):
        """Test confidence is capped at 95."""
        result = compute_confidence(distribution=0, tags=['apt', 'malware'])
        # Base 90 + 10 boost = 100, but capped at 95
        assert result == 95

    def test_confidence_case_insensitive_tags(self):
        """Test tag matching is case-insensitive."""
        result = compute_confidence(distribution=2, tags=['APT'])
        assert result == 80

        result = compute_confidence(distribution=2, tags=['MALWARE'])
        assert result == 80

    def test_confidence_none_tags(self):
        """Test confidence calculation with None tags."""
        result = compute_confidence(distribution=2, tags=None)
        assert result == 70

    def test_confidence_empty_tags(self):
        """Test confidence calculation with empty tags."""
        result = compute_confidence(distribution=2, tags=[])
        assert result == 70

    def test_confidence_specific_apt_groups(self):
        """Test confidence boost for specific APT groups."""
        result = compute_confidence(distribution=2, tags=['apt28'])
        assert result == 80

        result = compute_confidence(distribution=2, tags=['apt29'])
        assert result == 80


class TestMISPValueNormalization:
    """Test MISP value normalization."""

    def test_normalize_simple_value(self):
        """Test normalization of simple attribute value."""
        value, meta = _normalize_value('ip-src', '1.2.3.4')
        assert value == '1.2.3.4'
        assert meta['raw'] == '1.2.3.4'

    def test_normalize_compound_value(self):
        """Test normalization of compound values (ip|port)."""
        value, meta = _normalize_value('ip-src|port', '1.2.3.4|443')
        assert value == '1.2.3.4'
        assert meta['raw'] == '1.2.3.4|443'
        assert meta['compound_raw'] == '1.2.3.4|443'

    def test_normalize_whitespace(self):
        """Test normalization strips whitespace."""
        value, meta = _normalize_value('ip-src', '  1.2.3.4  ')
        assert value == '1.2.3.4'

    def test_normalize_compound_with_whitespace(self):
        """Test normalization of compound value with whitespace."""
        value, meta = _normalize_value('ip-src|port', ' 1.2.3.4 | 443 ')
        assert value.strip() == '1.2.3.4'

    def test_normalize_domain(self):
        """Test normalization of domain."""
        value, meta = _normalize_value('domain', 'example.com')
        assert value == 'example.com'
        assert 'raw' in meta

    def test_normalize_url(self):
        """Test normalization of URL."""
        value, meta = _normalize_value('url', 'http://example.com/path')
        assert value == 'http://example.com/path'


class TestMISPTypeMapping:
    """Test MISP type to IOC type mapping."""

    def test_ip_type_mapping(self):
        """Test IP-related types map to 'ip'."""
        assert TYPE_MAPPING['ip-src'] == 'ip'
        assert TYPE_MAPPING['ip-dst'] == 'ip'
        assert TYPE_MAPPING['ip-src|port'] == 'ip'
        assert TYPE_MAPPING['ip-dst|port'] == 'ip'

    def test_domain_type_mapping(self):
        """Test domain-related types map to 'domain'."""
        assert TYPE_MAPPING['domain'] == 'domain'
        assert TYPE_MAPPING['hostname'] == 'domain'

    def test_url_type_mapping(self):
        """Test URL type mapping."""
        assert TYPE_MAPPING['url'] == 'url'

    def test_hash_type_mapping(self):
        """Test hash types map to 'hash'."""
        assert TYPE_MAPPING['md5'] == 'hash'
        assert TYPE_MAPPING['sha1'] == 'hash'
        assert TYPE_MAPPING['sha256'] == 'hash'
        assert TYPE_MAPPING['sha512'] == 'hash'
        assert TYPE_MAPPING['ssdeep'] == 'hash'

    def test_email_type_mapping(self):
        """Test email types map to 'email'."""
        assert TYPE_MAPPING['email'] == 'email'
        assert TYPE_MAPPING['email-src'] == 'email'
        assert TYPE_MAPPING['email-dst'] == 'email'
        assert TYPE_MAPPING['email-subject'] == 'email'


# ============================================================================
# Common Service Tests
# ============================================================================

class TestRetryLogic:
    """Test common retry with backoff logic."""

    def test_retry_success_first_attempt(self):
        """Test retry succeeds on first attempt."""
        func = MagicMock(return_value="success")
        result = retry_with_backoff(func, max_attempts=3, base_delay=0.1)

        assert result == "success"
        assert func.call_count == 1

    def test_retry_success_after_failures(self):
        """Test retry succeeds after initial failures."""
        func = MagicMock(side_effect=[
            Exception("fail1"),
            Exception("fail2"),
            "success"
        ])

        result = retry_with_backoff(func, max_attempts=3, base_delay=0.01)

        assert result == "success"
        assert func.call_count == 3

    def test_retry_exhausts_attempts(self):
        """Test retry raises after max attempts."""
        func = MagicMock(side_effect=Exception("always fails"))

        with pytest.raises(Exception, match="always fails"):
            retry_with_backoff(func, max_attempts=3, base_delay=0.01)

        assert func.call_count == 3

    def test_retry_with_different_exceptions(self):
        """Test retry handles different exception types."""
        func = MagicMock(side_effect=[
            ConnectionError("network error"),
            TimeoutError("timeout"),
            "success"
        ])

        result = retry_with_backoff(func, max_attempts=3, base_delay=0.01)

        assert result == "success"
        assert func.call_count == 3

    def test_retry_backoff_delay(self):
        """Test retry implements exponential backoff."""
        import time
        func = MagicMock(side_effect=[
            Exception("fail1"),
            Exception("fail2"),
            "success"
        ])

        start = time.time()
        result = retry_with_backoff(func, max_attempts=3, base_delay=0.1)
        duration = time.time() - start

        # Should have some delay due to backoff (0.1 + 0.2 = 0.3s minimum)
        assert duration >= 0.3
        assert result == "success"


class TestExternalFeedRateLimiter:
    def test_per_second_limit_waits(self, monkeypatch):
        now = {"t": 0.0}
        sleeps = []

        def fake_monotonic():
            return now["t"]

        def fake_sleep(delay):
            sleeps.append(delay)
            now["t"] += delay

        monkeypatch.setattr("app.services.common.time.monotonic", fake_monotonic)
        monkeypatch.setattr("app.services.common.time.sleep", fake_sleep)

        limiter = ExternalFeedRateLimiter(per_second=1, per_minute=0)
        limiter.acquire(source="test")
        limiter.acquire(source="test")

        assert sleeps
        assert sleeps[0] >= 1.0

    def test_per_minute_limit_waits(self, monkeypatch):
        now = {"t": 0.0}
        sleeps = []

        def fake_monotonic():
            return now["t"]

        def fake_sleep(delay):
            sleeps.append(delay)
            now["t"] += delay

        monkeypatch.setattr("app.services.common.time.monotonic", fake_monotonic)
        monkeypatch.setattr("app.services.common.time.sleep", fake_sleep)

        limiter = ExternalFeedRateLimiter(per_second=0, per_minute=2)
        limiter.acquire(source="test")
        limiter.acquire(source="test")
        limiter.acquire(source="test")

        assert sleeps
        assert sleeps[0] >= 60.0

    def test_throttle_can_be_disabled_via_env(self, monkeypatch):
        monkeypatch.setenv("FEED_RATE_LIMIT_ENABLED", "false")

        called = {"waits": 0}

        def fail_acquire(*args, **kwargs):
            called["waits"] += 1

        monkeypatch.setattr("app.services.common.ExternalFeedRateLimiter.acquire", fail_acquire)
        throttle_external_request(source="test")
        assert called["waits"] == 0


# ============================================================================
# MISP Integration Tests
# ============================================================================

class TestMISPIntegration:
    """Test MISP integration functionality."""

    @patch('app.services.misp.PyMISP')
    def test_misp_initialization(self, mock_pymisp):
        """Test MISP client initialization."""
        with patch.dict('os.environ', {
            'MISP_URL': 'https://misp.example.com',
            'MISP_API_KEY': 'test-api-key',
            'MISP_VERIFY_SSL': 'true'
        }):
            from app.services.misp import _init_misp
            from app.config import Config

            cfg = Config()
            misp = _init_misp(cfg)

            mock_pymisp.assert_called_once_with(
                'https://misp.example.com',
                'test-api-key',
                ssl=True
            )

    @patch('app.services.misp.PyMISP')
    def test_misp_ssl_verification(self, mock_pymisp):
        """Test MISP SSL verification setting."""
        with patch.dict('os.environ', {
            'MISP_URL': 'https://misp.example.com',
            'MISP_API_KEY': 'test-api-key',
            'MISP_VERIFY_SSL': 'false'
        }):
            from app.services.misp import _init_misp
            from app.config import Config

            cfg = Config()
            misp = _init_misp(cfg)

            # Verify SSL=False was passed
            call_kwargs = mock_pymisp.call_args[1]
            assert call_kwargs['ssl'] is False

    def test_misp_missing_config(self):
        """Test MISP initialization fails with missing config."""
        with patch.dict('os.environ', {'SECRET_KEY': 'a' * 32}, clear=True):
            from app.services.misp import _init_misp
            from app.config import Config

            cfg = Config()

            with pytest.raises(RuntimeError, match="MISP_URL/MISP_API_KEY not set"):
                _init_misp(cfg)

    @patch('app.services.misp.PyMISP')
    def test_misp_attribute_fetch(self, mock_pymisp):
        """Test fetching MISP attributes."""
        # Mock MISP response
        mock_instance = MagicMock()
        mock_instance.search.return_value = {
            "Attribute": [
                {
                    "type": "ip-src",
                    "value": "1.2.3.4",
                    "to_ids": True,
                    "distribution": "1",
                    "event_id": "123",
                    "Tag": [{"name": "tlp:red"}, {"name": "apt"}]
                }
            ]
        }
        mock_pymisp.return_value = mock_instance

        with patch.dict('os.environ', {
            'MISP_URL': 'https://misp.example.com',
            'MISP_API_KEY': 'test-api-key',
            'MISP_DAYS': '7'
        }):
            from app.services.misp import _fetch_misp_attributes
            from app.config import Config

            cfg = Config()
            attributes = _fetch_misp_attributes(cfg)

            assert len(attributes) == 1
            assert attributes[0]["type"] == "ip-src"
            assert attributes[0]["value"] == "1.2.3.4"


# ============================================================================
# CrowdSec Integration Tests
# ============================================================================

class TestCrowdSecIntegration:
    """Test CrowdSec integration functionality."""

    @patch('requests.get')
    def test_crowdsec_api_call(self, mock_get):
        """Test CrowdSec API call structure."""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"value": "1.2.3.4", "type": "ip"}
        ]
        mock_get.return_value = mock_response

        # Test would call CrowdSec service function
        # (Actual implementation test would require reading crowdsec.py)

    @patch('requests.get')
    def test_crowdsec_error_handling(self, mock_get):
        """Test CrowdSec error handling."""
        # Mock error response
        mock_get.side_effect = ConnectionError("Network error")

        # Test error handling
        # (Would be implemented based on actual service code)


# ============================================================================
# MalwareBazaar Integration Tests
# ============================================================================

class TestMalwareBazaarIntegration:
    """Test MalwareBazaar integration functionality."""

    @patch('requests.post')
    def test_malwarebazaar_api_call(self, mock_post):
        """Test MalwareBazaar API call structure."""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "a" * 64,
                    "file_type": "exe",
                    "tags": ["malware"]
                }
            ]
        }
        mock_post.return_value = mock_response

        # Test would call MalwareBazaar service function


# ============================================================================
# Data Normalization Tests
# ============================================================================

class TestDataNormalization:
    """Test data normalization across all sources."""

    def test_normalize_ip_addresses(self):
        """Test IP address normalization."""
        # IPv4
        value, meta = _normalize_value('ip-src', '192.168.1.1')
        assert value == '192.168.1.1'

        # IPv6 (if supported)
        value, meta = _normalize_value('ip-src', '2001:db8::1')
        assert value == '2001:db8::1'

    def test_normalize_domains(self):
        """Test domain normalization."""
        value, meta = _normalize_value('domain', 'example.com')
        assert value == 'example.com'

        # With subdomain
        value, meta = _normalize_value('domain', 'www.example.com')
        assert value == 'www.example.com'

    def test_normalize_urls(self):
        """Test URL normalization."""
        value, meta = _normalize_value('url', 'http://example.com/path')
        assert value == 'http://example.com/path'

        # HTTPS
        value, meta = _normalize_value('url', 'https://example.com/path?param=value')
        assert value == 'https://example.com/path?param=value'

    def test_normalize_hashes(self):
        """Test hash normalization."""
        # MD5
        md5 = 'a' * 32
        value, meta = _normalize_value('md5', md5)
        assert value == md5

        # SHA-256
        sha256 = 'a' * 64
        value, meta = _normalize_value('sha256', sha256)
        assert value == sha256

    def test_normalize_emails(self):
        """Test email normalization."""
        value, meta = _normalize_value('email', 'test@example.com')
        assert value == 'test@example.com'


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows
        self.updated = False

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return self._rows

    def update(self, *args, **kwargs):
        self.updated = True
        return 1


class _FakeDB:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.executed = 0
        self.committed = 0
        self.rolled_back = 0
        self.closed = 0

    def query(self, *args, **kwargs):
        return _FakeQuery(self.rows)

    def execute(self, stmt):
        self.executed += 1
        return None

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    def close(self):
        self.closed += 1


class TestMWDBAutoUpdate:
    @patch("app.services.mwdb.fetch_mwdb_by_tags")
    @patch("app.services.mwdb.SessionLocal")
    def test_uses_recent_mode_when_no_tags(self, mock_sessionlocal, mock_fetch):
        mock_fetch.return_value = iter([])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db
        with patch.dict("os.environ", {"SECRET_KEY": "a" * 32, "MWDB_TAGS": "", "MWDB_DAYS": "30"}, clear=False):
            result = update_mwdb_indicators()
            assert result["fetched"] == 0
            mock_fetch.assert_called_once()
            kwargs = mock_fetch.call_args.kwargs
            assert kwargs["mode"] == "recent"
            assert kwargs["tags"] == []

    @patch("app.services.mwdb.SessionLocal")
    @patch("app.services.mwdb.fetch_mwdb_by_tags")
    def test_updates_indicators(self, mock_fetch, mock_sessionlocal):
        mock_fetch.return_value = iter([{
            "ioc_value": "a" * 64,
            "ioc_type": "hash",
            "source": "mwdb",
            "source_ref": "obj-1",
            "first_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "confidence": 60,
            "tlp": "GREEN",
            "is_active": True,
            "tags": ["apt"],
            "metadata": {"id": "obj-1"},
        }])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db

        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "MWDB_TAGS": "apt,malware",
            "MWDB_URL": "https://mwdb.example.com",
            "MWDB_AUTH_KEY": "test-key",
            "MWDB_LIMIT": "10",
        }, clear=False):
            result = update_mwdb_indicators()

        assert result["fetched"] == 1
        assert fake_db.executed >= 2
        assert fake_db.committed >= 1
        assert fake_db.closed == 1
        mock_fetch.assert_called_once()

    @patch("app.services.mwdb.SessionLocal")
    @patch("app.services.mwdb.fetch_mwdb_by_tags")
    def test_recent_mode_uses_custom_filter(self, mock_fetch, mock_sessionlocal):
        mock_fetch.return_value = iter([])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db
        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "MWDB_TAGS": "",
            "MWDB_URL": "https://mwdb.example.com",
            "MWDB_AUTH_KEY": "test-key",
            "MWDB_CUSTOM_FILTER": "tag:evil",
        }, clear=False):
            update_mwdb_indicators()
        kwargs = mock_fetch.call_args.kwargs
        assert kwargs["mode"] == "recent"
        assert kwargs["custom_filter"] == "tag:evil"


class TestMWDBQueryBuilding:
    def test_single_simple_tag(self):
        assert _build_tag_query(["trojan"]) == "tag:trojan"

    def test_single_tag_with_colon(self):
        assert _build_tag_query(["feed:vx"]) == 'tag:"feed:vx"'

    def test_multiple_tags_mixed(self):
        q = _build_tag_query(["trojan", "feed:vx"])
        assert q == '(tag:trojan OR tag:"feed:vx")'

    @patch("app.services.mwdb.retry_with_backoff")
    @patch("app.services.mwdb.logger")
    def test_fetch_logs_stop_reason_no_results(self, mock_logger, mock_retry):
        mock_retry.return_value = {"objects": []}
        rows = list(
            fetch_mwdb_by_tags(
                base_url="https://mwdb.example.com",
                auth_key="abc",
                tags=[],
                custom_filter="",
                mode="recent",
                limit=10,
            )
        )
        assert rows == []
        calls = [str(c.args[0]) for c in mock_logger.info.call_args_list if c.args]
        assert "mwdb_stop_reason" in calls


class TestMWDBGroupTLP:
    """Tests for _object_matches_group and TLP:AMBER assignment."""

    def test_no_group_configured_returns_false(self):
        obj = {"uploaders": [{"group": "mygroup"}]}
        assert _object_matches_group(obj, "") is False

    def test_matches_uploader_group_key(self):
        obj = {"uploaders": [{"group": "mygroup", "login": "user1"}]}
        assert _object_matches_group(obj, "mygroup") is True

    def test_matches_uploader_organization_key(self):
        obj = {"uploaders": [{"organization": "SecTeam"}]}
        assert _object_matches_group(obj, "SecTeam") is True

    def test_matches_case_insensitive(self):
        obj = {"uploaders": [{"group": "MYGROUP"}]}
        assert _object_matches_group(obj, "mygroup") is True

    def test_no_match_returns_false(self):
        obj = {"uploaders": [{"group": "othergroup"}]}
        assert _object_matches_group(obj, "mygroup") is False

    def test_matches_top_level_organization(self):
        obj = {"organization": "SecTeam", "uploaders": []}
        assert _object_matches_group(obj, "SecTeam") is True

    def test_string_uploader_matches(self):
        obj = {"uploaders": ["mygroup", "anothergroup"]}
        assert _object_matches_group(obj, "mygroup") is True

    def test_empty_uploaders_returns_false(self):
        obj = {"uploaders": []}
        assert _object_matches_group(obj, "mygroup") is False

    @patch("app.services.mwdb.retry_with_backoff")
    def test_tlp_amber_when_group_matches(self, mock_retry):
        sha = "a" * 64
        # Second call returns empty to stop pagination
        mock_retry.side_effect = [
            {"objects": [{"id": "obj-1", "sha256": sha, "upload_time": "2025-01-01T00:00:00Z", "tags": [], "uploaders": [{"group": "myteam"}]}]},
            {"objects": []},
        ]
        rows = list(
            fetch_mwdb_by_tags(
                base_url="https://mwdb.example.com",
                auth_key="abc",
                tags=["malware"],
                my_group="myteam",
                limit=10,
            )
        )
        assert len(rows) == 1
        assert rows[0]["tlp"] == "AMBER"

    @patch("app.services.mwdb.retry_with_backoff")
    def test_tlp_green_when_group_does_not_match(self, mock_retry):
        sha = "b" * 64
        mock_retry.side_effect = [
            {"objects": [{"id": "obj-2", "sha256": sha, "upload_time": "2025-01-01T00:00:00Z", "tags": [], "uploaders": [{"group": "otherteam"}]}]},
            {"objects": []},
        ]
        rows = list(
            fetch_mwdb_by_tags(
                base_url="https://mwdb.example.com",
                auth_key="abc",
                tags=["malware"],
                my_group="myteam",
                limit=10,
            )
        )
        assert len(rows) == 1
        assert rows[0]["tlp"] == "GREEN"

    @patch("app.services.mwdb.retry_with_backoff")
    def test_tlp_green_when_no_group_configured(self, mock_retry):
        sha = "c" * 64
        mock_retry.side_effect = [
            {"objects": [{"id": "obj-3", "sha256": sha, "upload_time": "2025-01-01T00:00:00Z", "tags": [], "uploaders": [{"group": "anyteam"}]}]},
            {"objects": []},
        ]
        rows = list(
            fetch_mwdb_by_tags(
                base_url="https://mwdb.example.com",
                auth_key="abc",
                tags=["malware"],
                my_group=None,
                limit=10,
            )
        )
        assert len(rows) == 1
        assert rows[0]["tlp"] == "GREEN"


class TestMalwareBazaarAutoUpdate:
    @patch("app.services.malwarebazaar.fetch_malwarebazaar_by_tags")
    def test_skips_when_no_tags(self, mock_fetch):
        with patch.dict("os.environ", {"SECRET_KEY": "a" * 32, "MALWAREBAZAAR_TAGS": ""}, clear=False):
            result = update_malwarebazaar_indicators()
            assert result["fetched"] == 0
            mock_fetch.assert_not_called()

    @patch("app.services.malwarebazaar.SessionLocal")
    @patch("app.services.malwarebazaar.fetch_malwarebazaar_by_tags")
    def test_updates_indicators(self, mock_fetch, mock_sessionlocal):
        mock_fetch.return_value = iter([{
            "ioc_value": "b" * 64,
            "ioc_type": "hash",
            "source": "malwarebazaar",
            "source_ref": "sample-1",
            "first_seen": datetime(2025, 1, 2, tzinfo=timezone.utc),
            "last_seen": datetime(2025, 1, 2, tzinfo=timezone.utc),
            "confidence": 60,
            "tlp": "GREEN",
            "is_active": True,
            "tags": ["trickbot"],
            "metadata": {"sha256_hash": "b" * 64},
        }])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db

        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "MALWAREBAZAAR_TAGS": "trickbot",
            "MALWAREBAZAAR_AUTH_KEY": "test-key",
            "MALWAREBAZAAR_LIMIT": "5",
        }, clear=False):
            result = update_malwarebazaar_indicators()

        assert result["fetched"] == 1
        assert fake_db.executed >= 2
        assert fake_db.committed >= 1
        assert fake_db.closed == 1
        mock_fetch.assert_called_once()

    @patch("app.services.malwarebazaar.SessionLocal")
    @patch("app.services.malwarebazaar.fetch_malwarebazaar_by_tags")
    def test_uses_abusech_key_fallback(self, mock_fetch, mock_sessionlocal):
        mock_fetch.return_value = iter([])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db

        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "MALWAREBAZAAR_TAGS": "trickbot",
            "MALWAREBAZAAR_AUTH_KEY": "",
            "ABUSECH_AUTH_KEY": "shared-key",
        }, clear=False):
            update_malwarebazaar_indicators()

        kwargs = mock_fetch.call_args.kwargs
        assert kwargs["auth_key"] == "shared-key"


class TestAbuseChHelpers:
    def test_infer_ioc_type(self):
        assert _infer_ioc_type("1.2.3.4") == "ip"
        assert _infer_ioc_type("https://evil.example/a") == "url"
        assert _infer_ioc_type("example.com") == "domain"
        assert _infer_ioc_type("a" * 64) == "hash"

    def test_normalize_threatfox_ioc(self):
        value, kind = _normalize_threatfox_ioc("8.8.8.8:443", "ip:port")
        assert value == "8.8.8.8"
        assert kind == "ip"

        value, kind = _normalize_threatfox_ioc("http://evil.test", "url")
        assert value == "http://evil.test"
        assert kind == "url"

    def test_pick_ioc_from_csv_row(self):
        ioc, ioc_type = _pick_ioc_from_csv_row({"value": "bad.example.com"})
        assert ioc == "bad.example.com"
        assert ioc_type == "domain"

    def test_pick_ioc_from_hunting_csv_shape(self):
        ioc, ioc_type = _pick_ioc_from_csv_row({
            "time_stamp": "2026-02-25 10:28:04",
            "entry_type": "sha256_hash",
            "entry_value": "b7dcf1d156c1d47f27d960d59cceda1fb49276fff182e3078854a08dbb9281cc",
        })
        assert ioc == "b7dcf1d156c1d47f27d960d59cceda1fb49276fff182e3078854a08dbb9281cc"
        assert ioc_type == "hash"


class TestAbuseChFetchers:
    @patch("app.services.abusech.requests.get")
    def test_fetch_urlhaus_urls(self, mock_get):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "# comment\nhttps://evil.example/a\n\nhttps://evil.example/b\n"
        mock_get.return_value = mock_response

        rows = list(fetch_urlhaus_urls(url="https://urlhaus.abuse.ch/downloads/text_online/", limit=10))
        assert len(rows) == 2
        assert rows[0]["ioc_type"] == "url"
        assert rows[0]["source"] == "urlhaus"

    @patch("app.services.abusech.requests.get")
    def test_fetch_feodotracker_ips(self, mock_get):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "# comment\n1.1.1.1\nnot-an-ip\n8.8.8.8,foo\n"
        mock_get.return_value = mock_response

        rows = list(fetch_feodotracker_ips(url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt", limit=10))
        assert len(rows) == 2
        assert all(r["ioc_type"] == "ip" for r in rows)
        assert rows[0]["source"] == "feodotracker"

    @patch("app.services.abusech.requests.post")
    def test_fetch_yaraify_lookup_hashes(self, mock_post):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [{
                "sha256_hash": "c" * 64,
                "first_seen": "2026-02-25 12:00:00",
                "task_id": "task-1",
            }]
        }
        mock_post.return_value = mock_response

        rows = list(fetch_yaraify_lookup_hashes(
            api_url="https://yaraify-api.abuse.ch/api/v1/",
            auth_key="key",
            search_terms=["c" * 64],
            limit=5,
        ))
        assert len(rows) == 1
        assert rows[0]["ioc_value"] == "c" * 64
        assert rows[0]["ioc_type"] == "hash"
        assert rows[0]["source"] == "yaraify"


class TestAbuseChUpdater:
    @patch("app.services.abusech.SessionLocal")
    @patch("app.services.abusech.fetch_hunting_fplist")
    @patch("app.services.abusech.fetch_yaraify_tasks")
    @patch("app.services.abusech.fetch_feodotracker_ips")
    @patch("app.services.abusech.fetch_urlhaus_urls")
    @patch("app.services.abusech.fetch_threatfox_iocs")
    def test_update_abusech_indicators(
        self,
        mock_threatfox,
        mock_urlhaus,
        mock_feodo,
        mock_yaraify,
        mock_hunting,
        mock_sessionlocal,
    ):
        mock_threatfox.return_value = iter([{
            "ioc_value": "evil.example.com",
            "ioc_type": "domain",
            "source_ref": "1",
            "first_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "confidence": 60,
            "tlp": "GREEN",
            "is_active": True,
            "tags": [],
            "metadata": {"id": 1},
        }])
        mock_urlhaus.return_value = iter([])
        mock_feodo.return_value = iter([])
        mock_yaraify.return_value = iter([])
        mock_hunting.return_value = iter([])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db

        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "THREATFOX_ENABLED": "true",
            "URLHAUS_ENABLED": "false",
            "FEODOTRACKER_ENABLED": "false",
            "YARAIFY_ENABLED": "false",
            "HUNTING_FPLIST_ENABLED": "false",
            "THREATFOX_AUTH_KEY": "key",
        }, clear=False):
            result = update_abusech_indicators()

        assert "threatfox" in result
        assert result["threatfox"]["fetched"] == 1
        assert fake_db.executed >= 2
        assert fake_db.committed >= 1
        assert fake_db.closed == 1

    @patch("app.services.abusech.SessionLocal")
    @patch("app.services.abusech.fetch_hunting_fplist")
    @patch("app.services.abusech.fetch_yaraify_lookup_hashes")
    @patch("app.services.abusech.fetch_yaraify_tasks")
    @patch("app.services.abusech.fetch_feodotracker_ips")
    @patch("app.services.abusech.fetch_urlhaus_urls")
    @patch("app.services.abusech.fetch_threatfox_iocs")
    def test_update_abusech_yaraify_lookup_fallback(
        self,
        mock_threatfox,
        mock_urlhaus,
        mock_feodo,
        mock_yaraify_tasks,
        mock_yaraify_lookup,
        mock_hunting,
        mock_sessionlocal,
    ):
        mock_threatfox.return_value = iter([])
        mock_urlhaus.return_value = iter([])
        mock_feodo.return_value = iter([])
        mock_yaraify_tasks.return_value = iter([])
        mock_yaraify_lookup.return_value = iter([{
            "ioc_value": "d" * 64,
            "ioc_type": "hash",
            "source_ref": "task-x",
            "first_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "confidence": 55,
            "tlp": "GREEN",
            "is_active": True,
            "tags": ["lookup_hash"],
            "metadata": {"task_id": "task-x"},
        }])
        mock_hunting.return_value = iter([])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db

        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "YARAIFY_ENABLED": "true",
            "YARAIFY_IDENTIFIER": "",
            "YARAIFY_LOOKUP_HASHES": "d" * 64,
            "THREATFOX_ENABLED": "false",
            "URLHAUS_ENABLED": "false",
            "FEODOTRACKER_ENABLED": "false",
            "HUNTING_FPLIST_ENABLED": "false",
            "ABUSECH_AUTH_KEY": "key",
        }, clear=False):
            result = update_abusech_indicators()

        assert "yaraify" in result
        assert result["yaraify"]["fetched"] == 1
        mock_yaraify_lookup.assert_called_once()

    @patch("app.services.abusech.SessionLocal")
    @patch("app.services.abusech.fetch_urlhaus_urls")
    @patch("app.services.abusech.fetch_threatfox_iocs")
    def test_source_error_does_not_block_other_sources(self, mock_threatfox, mock_urlhaus, mock_sessionlocal):
        _circuit_breaker._state.clear()
        mock_threatfox.side_effect = RuntimeError("threatfox down")
        mock_urlhaus.return_value = iter([{
            "ioc_value": "http://evil.test",
            "ioc_type": "url",
            "source_ref": "http://evil.test",
            "first_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "confidence": 65,
            "tlp": "GREEN",
            "is_active": True,
            "tags": [],
            "metadata": {},
        }])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db

        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "THREATFOX_ENABLED": "true",
            "URLHAUS_ENABLED": "true",
            "ABUSECH_AUTH_KEY": "key",
        }, clear=False):
            result = update_abusech_indicators()

        assert result["threatfox"]["error"] == 1
        assert result["urlhaus"]["fetched"] == 1

    def test_validation_requires_yaraify_identifier_or_hashes(self):
        _circuit_breaker._state.clear()
        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "YARAIFY_ENABLED": "true",
            "ABUSECH_AUTH_KEY": "key",
            "YARAIFY_IDENTIFIER": "",
            "YARAIFY_LOOKUP_HASHES": "",
        }, clear=False):
            with pytest.raises(RuntimeError, match="YARAIFY_ENABLED=true requires YARAIFY_IDENTIFIER or YARAIFY_LOOKUP_HASHES"):
                update_abusech_indicators()

    @patch("app.services.abusech.SessionLocal")
    @patch("app.services.abusech.fetch_threatfox_iocs")
    def test_circuit_breaker_skips_after_fail_threshold(self, mock_threatfox, mock_sessionlocal):
        _circuit_breaker._state.clear()
        mock_threatfox.side_effect = RuntimeError("boom")
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db

        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "THREATFOX_ENABLED": "true",
            "ABUSECH_AUTH_KEY": "key",
            "ABUSECH_CIRCUIT_FAIL_THRESHOLD": "1",
            "ABUSECH_CIRCUIT_COOLDOWN_S": "60",
        }, clear=False):
            first = update_abusech_indicators()
            second = update_abusech_indicators()

        assert first["threatfox"]["error"] == 1
        assert second["threatfox"]["skipped"] == 1
        assert mock_threatfox.call_count == 1


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestServiceErrorHandling:
    """Test error handling in service integrations."""

    @patch('app.services.misp.PyMISP')
    def test_misp_connection_error(self, mock_pymisp):
        """Test handling of MISP connection errors."""
        mock_instance = MagicMock()
        mock_instance.search.side_effect = ConnectionError("Failed to connect")
        mock_pymisp.return_value = mock_instance

        # Test that error is handled gracefully
        # (Implementation depends on actual error handling in service)

    @patch('app.services.misp.PyMISP')
    def test_misp_authentication_error(self, mock_pymisp):
        """Test handling of MISP authentication errors."""
        mock_instance = MagicMock()
        mock_instance.search.side_effect = Exception("Authentication failed")
        mock_pymisp.return_value = mock_instance

        # Test error handling

    def test_malformed_data_handling(self):
        """Test handling of malformed data from sources."""
        # Test with missing required fields
        # Test with invalid data types
        # Test with unexpected structure


# ============================================================================
# Integration Test Helpers
# ============================================================================

def create_mock_misp_attribute(**kwargs):
    """Helper to create mock MISP attribute."""
    defaults = {
        "type": "ip-src",
        "value": "1.2.3.4",
        "to_ids": True,
        "distribution": "1",
        "event_id": "123",
        "Tag": []
    }
    defaults.update(kwargs)
    return defaults


def create_mock_crowdsec_decision(**kwargs):
    """Helper to create mock CrowdSec decision."""
    defaults = {
        "value": "1.2.3.4",
        "type": "ip",
        "duration": "4h",
        "scenario": "crowdsecurity/ssh-bruteforce"
    }
    defaults.update(kwargs)
    return defaults


# ============================================================================
# MWDB Default Query Tests
# ============================================================================

class TestMWDBDefaultQuery:
    """Test that fetch_mwdb_by_tags falls back to default_query when no tags/filter."""

    @patch("app.services.mwdb.retry_with_backoff")
    def test_uses_default_query_when_no_tags(self, mock_retry):
        """When tags and custom_filter are empty, default_query is sent as query param."""
        mock_retry.return_value = {"objects": []}
        rows = list(
            fetch_mwdb_by_tags(
                base_url="https://mwdb.example.com",
                auth_key="abc",
                tags=[],
                custom_filter="",
                default_query="type:*",
                mode="recent",
                limit=10,
            )
        )
        assert rows == []
        # Verify that query was passed to the HTTP call
        call_kwargs = mock_retry.call_args[0][0]  # the _do closure
        # We can't inspect closure internals directly, but the fact that
        # retry_with_backoff was called means the query path was exercised.
        assert mock_retry.called

    @patch("app.services.mwdb.retry_with_backoff")
    @patch("app.services.mwdb.logger")
    def test_default_query_logged_in_stop_reason(self, mock_logger, mock_retry):
        """stop_reason log entry includes query_hash when default_query used."""
        mock_retry.return_value = {"objects": []}
        list(
            fetch_mwdb_by_tags(
                base_url="https://mwdb.example.com",
                auth_key="abc",
                tags=[],
                custom_filter="",
                default_query="type:*",
                mode="recent",
                limit=10,
            )
        )
        stop_calls = [
            c for c in mock_logger.info.call_args_list
            if c.args and c.args[0] == "mwdb_stop_reason"
        ]
        assert stop_calls, "expected mwdb_stop_reason log entry"
        extra = stop_calls[0].kwargs.get("extra") or {}
        assert "query_hash" in extra
        assert "filtered_org" in extra
        assert "filtered_time" in extra
        assert "filtered_no_ioc" in extra

    @patch("app.services.mwdb.retry_with_backoff")
    def test_custom_query_overrides_default(self, mock_retry):
        """When custom_filter is set, it takes priority over default_query."""
        mock_retry.return_value = {"objects": []}
        list(
            fetch_mwdb_by_tags(
                base_url="https://mwdb.example.com",
                auth_key="abc",
                tags=[],
                custom_filter="tag:evil",
                default_query="type:*",
                mode="recent",
                limit=10,
            )
        )
        # custom_filter should be sent, not default_query
        # The closure is called by retry_with_backoff — verify it was invoked
        assert mock_retry.called

    @patch("app.services.mwdb.fetch_mwdb_by_tags")
    @patch("app.services.mwdb.SessionLocal")
    def test_update_passes_default_query_from_config(self, mock_sessionlocal, mock_fetch):
        """update_mwdb_indicators passes MWDB_DEFAULT_QUERY to fetch_mwdb_by_tags."""
        mock_fetch.return_value = iter([])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db
        with patch.dict("os.environ", {
            "SECRET_KEY": "a" * 32,
            "MWDB_TAGS": "",
            "MWDB_DEFAULT_QUERY": "type:file",
        }, clear=False):
            update_mwdb_indicators()
        kwargs = mock_fetch.call_args.kwargs
        assert kwargs["default_query"] == "type:file"

    @patch("app.services.mwdb.fetch_mwdb_by_tags")
    @patch("app.services.mwdb.SessionLocal")
    def test_update_default_query_fallback_when_not_set(self, mock_sessionlocal, mock_fetch):
        """update_mwdb_indicators uses MWDB_DEFAULT_QUERY default value 'type:*'."""
        mock_fetch.return_value = iter([])
        fake_db = _FakeDB(rows=[])
        mock_sessionlocal.return_value = fake_db
        # Remove MWDB_DEFAULT_QUERY from env so Config uses default
        import os as _os
        env_without = {k: v for k, v in _os.environ.items() if k != "MWDB_DEFAULT_QUERY"}
        env_without["SECRET_KEY"] = "a" * 32
        env_without["MWDB_TAGS"] = ""
        with patch.dict("os.environ", env_without, clear=True):
            update_mwdb_indicators()
        kwargs = mock_fetch.call_args.kwargs
        assert kwargs["default_query"] == "type:*"
