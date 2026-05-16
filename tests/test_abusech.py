"""Tests for app/services/abusech.py — pure-logic functions."""
from __future__ import annotations


# ---------------------------------------------------------------------------
# _parse_dt
# ---------------------------------------------------------------------------

class TestParseDt:
    def _parse(self, s):
        from app.services.abusech import _parse_dt
        return _parse_dt(s)

    def test_none_returns_none(self):
        assert self._parse(None) is None

    def test_empty_returns_none(self):
        assert self._parse("") is None

    def test_standard_datetime_format(self):
        from datetime import timezone
        result = self._parse("2026-01-15 10:30:00")
        assert result is not None
        assert result.year == 2026
        assert result.month == 1
        assert result.tzinfo == timezone.utc

    def test_date_only_format(self):
        result = self._parse("2026-05-16")
        assert result is not None
        assert result.year == 2026
        assert result.month == 5
        assert result.day == 16

    def test_iso_format_with_Z(self):
        result = self._parse("2026-03-01T12:00:00Z")
        assert result is not None
        assert result.year == 2026

    def test_invalid_returns_none(self):
        assert self._parse("not-a-date") is None

    def test_whitespace_stripped(self):
        result = self._parse("  2026-01-01 00:00:00  ")
        assert result is not None


# ---------------------------------------------------------------------------
# _is_hash
# ---------------------------------------------------------------------------

class TestIsHash:
    def _is_hash(self, value):
        from app.services.abusech import _is_hash
        return _is_hash(value)

    def test_md5_is_hash(self):
        assert self._is_hash("d41d8cd98f00b204e9800998ecf8427e") is True

    def test_sha1_is_hash(self):
        assert self._is_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True

    def test_sha256_is_hash(self):
        assert self._is_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True

    def test_ip_not_hash(self):
        assert self._is_hash("1.2.3.4") is False

    def test_domain_not_hash(self):
        assert self._is_hash("example.com") is False

    def test_uppercase_hash_is_hash(self):
        assert self._is_hash("D41D8CD98F00B204E9800998ECF8427E") is True

    def test_empty_not_hash(self):
        assert self._is_hash("") is False

    def test_non_hex_wrong_length_not_hash(self):
        assert self._is_hash("gggggggggggggggggggggggggggggggg") is False


# ---------------------------------------------------------------------------
# _infer_ioc_type
# ---------------------------------------------------------------------------

class TestInferIocType:
    def _infer(self, value):
        from app.services.abusech import _infer_ioc_type
        return _infer_ioc_type(value)

    def test_ip_address(self):
        assert self._infer("1.2.3.4") == "ip"

    def test_ipv6_address(self):
        assert self._infer("2001:db8::1") == "ip"

    def test_domain(self):
        assert self._infer("malware.example.com") == "domain"

    def test_url_with_scheme(self):
        assert self._infer("http://evil.com/payload") == "url"

    def test_hash_md5(self):
        assert self._infer("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_empty_value(self):
        assert self._infer("") == "object_id"

    def test_path_like_object_id(self):
        assert self._infer("/usr/bin/evil cmd arg") == "object_id"


# ---------------------------------------------------------------------------
# _normalize_threatfox_ioc
# ---------------------------------------------------------------------------

class TestNormalizeThreatfoxIoc:
    def _norm(self, ioc, ioc_type):
        from app.services.abusech import _normalize_threatfox_ioc
        return _normalize_threatfox_ioc(ioc, ioc_type)

    def test_ip_port_extracts_ip(self):
        value, typ = self._norm("1.2.3.4:8080", "ip:port")
        assert value == "1.2.3.4"
        assert typ == "ip"

    def test_ip_type_returns_ip(self):
        value, typ = self._norm("5.6.7.8", "ip")
        assert value == "5.6.7.8"
        assert typ == "ip"

    def test_domain_type(self):
        value, typ = self._norm("evil.com", "domain")
        assert value == "evil.com"
        assert typ == "domain"

    def test_url_type(self):
        value, typ = self._norm("http://evil.com/bad", "url")
        assert value == "http://evil.com/bad"
        assert typ == "url"

    def test_md5_hash_type(self):
        value, typ = self._norm("d41d8cd98f00b204e9800998ecf8427e", "md5_hash")
        assert typ == "hash"

    def test_sha256_hash_type(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        value, typ = self._norm(h, "sha256_hash")
        assert typ == "hash"

    def test_unknown_type_inferred(self):
        value, typ = self._norm("1.2.3.4", "unknown")
        assert typ == "ip"


# ---------------------------------------------------------------------------
# _abusech_headers
# ---------------------------------------------------------------------------

class TestAbusechHeaders:
    def test_returns_auth_key_header(self):
        from app.services.abusech import _abusech_headers
        headers = _abusech_headers("my-key-123")
        assert headers["Auth-Key"] == "my-key-123"

    def test_returns_user_agent(self):
        from app.services.abusech import _abusech_headers
        headers = _abusech_headers("k")
        assert "User-Agent" in headers

    def test_raises_on_empty_key(self):
        from app.services.abusech import _abusech_headers
        import pytest
        with pytest.raises(RuntimeError, match="Auth-Key"):
            _abusech_headers("")

    def test_raises_on_none_key(self):
        from app.services.abusech import _abusech_headers
        import pytest
        with pytest.raises(RuntimeError):
            _abusech_headers(None)


# ---------------------------------------------------------------------------
# _pick_ioc_from_csv_row
# ---------------------------------------------------------------------------

class TestPickIocFromCsvRow:
    def _pick(self, row):
        from app.services.abusech import _pick_ioc_from_csv_row
        return _pick_ioc_from_csv_row(row)

    def test_entry_value_ip(self):
        val, typ = self._pick({"entry_value": "1.2.3.4", "entry_type": "ip"})
        assert val == "1.2.3.4"
        assert typ == "ip"

    def test_entry_value_domain(self):
        val, typ = self._pick({"entry_value": "evil.com", "entry_type": "domain"})
        assert val == "evil.com"
        assert typ == "domain"

    def test_entry_value_url(self):
        val, typ = self._pick({"entry_value": "http://evil.com", "entry_type": "url"})
        assert val == "http://evil.com"
        assert typ == "url"

    def test_entry_value_hash(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        val, typ = self._pick({"entry_value": h, "entry_type": "md5_hash"})
        assert val == h
        assert typ == "hash"

    def test_fallback_to_ioc_key(self):
        val, typ = self._pick({"ioc": "1.2.3.4"})
        assert val == "1.2.3.4"
        assert typ == "ip"

    def test_fallback_to_ip_key(self):
        val, typ = self._pick({"ip": "10.0.0.1"})
        assert val == "10.0.0.1"
        assert typ == "ip"

    def test_empty_row_returns_none(self):
        val, typ = self._pick({})
        assert val is None
        assert typ is None

    def test_fallback_skips_null_none_values(self):
        val, typ = self._pick({"other_key": "null", "another": "none", "third": "1.1.1.1"})
        assert val == "1.1.1.1"

    def test_inferred_type_for_unknown_entry_type(self):
        val, typ = self._pick({"entry_value": "malware.example.com", "entry_type": "unknown"})
        assert val == "malware.example.com"
        assert typ == "domain"
