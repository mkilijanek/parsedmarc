from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.services.quality import canonicalize_row, dedup_rows, infer_type_from_value, normalize_value


def test_infer_type_from_value():
    assert infer_type_from_value("1.2.3.4") == "ip"
    assert infer_type_from_value("example.org") == "domain"
    assert infer_type_from_value("https://a.b/c") == "url"
    assert infer_type_from_value("a" * 64) == "hash"


def test_normalize_value_domain_and_hash():
    assert normalize_value("Example.ORG.", "domain") == "example.org"
    assert normalize_value("AA" * 32, "hash") == ("aa" * 32)


def test_canonicalize_row_invalid_ip():
    row = {
        "ioc_value": "999.999.999.999",
        "ioc_type": "ip",
        "confidence": 60,
        "tlp": "green",
    }
    normalized, reason = canonicalize_row(row, source="threatfox")
    assert normalized is None
    assert reason == "invalid_value"


def test_canonicalize_row_applies_normalization_and_confidence():
    old = datetime.now(timezone.utc) - timedelta(days=120)
    row = {
        "ioc_value": "Example.ORG.",
        "ioc_type": "domain",
        "source_ref": "",
        "first_seen": old,
        "last_seen": old,
        "confidence": 70,
        "tlp": "green",
        "tags": ["APT", "apt", "Malware"],
        "metadata": {"k": "v"},
    }
    normalized, reason = canonicalize_row(row, source="threatfox")
    assert reason is None
    assert normalized is not None
    assert normalized["ioc_value"] == "example.org"
    assert normalized["source_ref"] == "example.org"
    assert normalized["tags"] == ["apt", "malware"]
    assert 0 <= int(normalized["confidence"]) <= 100
    assert normalized["metadata"]["enrichment"]["domain_root"] == "example.org"


def test_dedup_rows_merges_metadata_tags_and_confidence():
    rows = [
        {
            "source": "mwdb",
            "ioc_value": "a" * 64,
            "ioc_type": "hash",
            "source_ref": "x",
            "confidence": 60,
            "is_active": True,
            "tags": ["malware"],
            "metadata": {"a": 1},
            "first_seen": datetime(2025, 1, 2, tzinfo=timezone.utc),
            "last_seen": datetime(2025, 1, 2, tzinfo=timezone.utc),
        },
        {
            "source": "mwdb",
            "ioc_value": "a" * 64,
            "ioc_type": "hash",
            "source_ref": "x",
            "confidence": 80,
            "is_active": True,
            "tags": ["apt"],
            "metadata": {"b": 2},
            "first_seen": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2025, 1, 3, tzinfo=timezone.utc),
        },
    ]
    deduped, merged = dedup_rows(rows)
    assert len(deduped) == 1
    assert merged == 1
    one = deduped[0]
    assert one["confidence"] == 80
    assert one["tags"] == ["malware", "apt"]
    assert one["metadata"] == {"a": 1, "b": 2}
    assert one["first_seen"] == datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert one["last_seen"] == datetime(2025, 1, 3, tzinfo=timezone.utc)


def test_canonicalize_row_url_enrichment():
    row = {
        "ioc_value": "https://sub.example.org/path",
        "ioc_type": "url",
        "source_ref": "",
        "confidence": 60,
        "metadata": {},
    }
    normalized, reason = canonicalize_row(row, source="urlhaus")
    assert reason is None
    assert normalized is not None
    enr = normalized["metadata"]["enrichment"]
    assert enr["url_host"] == "sub.example.org"
    assert enr["url_host_type"] == "domain"
    assert enr["url_host_root"] == "example.org"


def test_canonicalize_row_ip_enrichment():
    row = {
        "ioc_value": "10.0.0.1",
        "ioc_type": "ip",
        "source_ref": "",
        "confidence": 60,
        "metadata": {},
    }
    normalized, reason = canonicalize_row(row, source="threatfox")
    assert reason is None
    assert normalized is not None
    enr = normalized["metadata"]["enrichment"]
    assert enr["ip_version"] == 4
    assert enr["ip_is_private"] is True


# ---------------------------------------------------------------------------
# TestQualityEdgeCases — migrated from test_coverage_boost2.py
# ---------------------------------------------------------------------------

class TestQualityEdgeCases:

    def test_infer_type_ip_v4(self):
        assert infer_type_from_value("192.168.1.1") == "ip"

    def test_infer_type_ip_v6(self):
        assert infer_type_from_value("::1") == "ip"

    def test_infer_type_domain(self):
        assert infer_type_from_value("evil.example.com") == "domain"

    def test_infer_type_url(self):
        assert infer_type_from_value("http://evil.com/path") == "url"

    def test_infer_type_email(self):
        assert infer_type_from_value("user@evil.com") == "email"

    def test_infer_type_hash_md5(self):
        assert infer_type_from_value("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_infer_type_hash_sha256(self):
        sha = "a" * 64
        assert infer_type_from_value(sha) == "hash"

    def test_infer_type_empty_returns_object_id(self):
        assert infer_type_from_value("") == "object_id"

    def test_normalize_type_known_types(self):
        from app.services.quality import _normalize_type
        assert _normalize_type("ip", "1.2.3.4") == "ip"
        assert _normalize_type("domain", "evil.com") == "domain"
        assert _normalize_type("url", "http://x.com") == "url"
        assert _normalize_type("hash", "abc123") == "hash"

    def test_normalize_type_alias_sha256(self):
        from app.services.quality import _normalize_type
        assert _normalize_type("sha256_hash", "abc") == "hash"

    def test_normalize_type_alias_ip_src(self):
        from app.services.quality import _normalize_type
        assert _normalize_type("ip-src", "1.2.3.4") == "ip"

    def test_normalize_type_hostname_becomes_domain(self):
        from app.services.quality import _normalize_type
        assert _normalize_type("hostname", "evil.com") == "domain"

    def test_normalize_type_uri_becomes_url(self):
        from app.services.quality import _normalize_type
        assert _normalize_type("uri", "https://x.com") == "url"

    def test_normalize_value_strips_whitespace(self):
        result = normalize_value("  1.2.3.4  ", "ip")
        assert result == "1.2.3.4"

    def test_normalize_value_domain_lowercase(self):
        result = normalize_value("EVIL.COM", "domain")
        assert result == "evil.com"

    def test_normalize_value_ip_valid(self):
        result = normalize_value("10.0.0.1", "ip")
        assert result == "10.0.0.1"

    def test_normalize_value_invalid_ip_returns_none(self):
        result = normalize_value("not-an-ip", "ip")
        assert result is None

    def test_normalize_tags_dedups(self):
        from app.services.quality import normalize_tags
        result = normalize_tags(["malware", "MALWARE", "apt"])
        assert len(result) == 2  # dedup by lowercase

    def test_normalize_tags_empty(self):
        from app.services.quality import normalize_tags
        result = normalize_tags(None)
        assert result == []

    def test_normalize_tags_strips(self):
        from app.services.quality import normalize_tags
        result = normalize_tags(["  tag1 ", " tag2"])
        assert "tag1" in result
        assert "tag2" in result

    def test_confidence_v2_recent_is_higher(self):
        from app.services.quality import confidence_v2
        now = datetime.now(timezone.utc)
        conf = confidence_v2(source="misp", base_confidence=80, first_seen=now)
        assert 0 <= conf <= 100

    def test_confidence_v2_no_first_seen(self):
        from app.services.quality import confidence_v2
        conf = confidence_v2(source="misp", base_confidence=80, first_seen=None)
        assert 0 <= conf <= 100

    def test_dedup_rows_removes_duplicates(self):
        rows = [
            {"ioc_value": "1.2.3.4", "ioc_type": "ip", "source": "s1", "source_ref": "r1"},
            {"ioc_value": "1.2.3.4", "ioc_type": "ip", "source": "s1", "source_ref": "r1"},
            {"ioc_value": "5.6.7.8", "ioc_type": "ip", "source": "s1", "source_ref": "r2"},
        ]
        unique, merged_count = dedup_rows(rows)
        assert len(unique) == 2
        assert merged_count >= 1

    def test_normalize_source_ref_string(self):
        from app.services.quality import normalize_source_ref
        result = normalize_source_ref("ref-123", "fallback")
        assert result == "ref-123"

    def test_normalize_source_ref_none_uses_fallback(self):
        from app.services.quality import normalize_source_ref
        result = normalize_source_ref(None, "fallback_val")
        assert result == "fallback_val"
