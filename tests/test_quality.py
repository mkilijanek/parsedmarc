from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
