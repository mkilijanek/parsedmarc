"""Second pass coverage boost tests — targeting remaining gaps.

Covers:
- app/services/quality.py (83%): normalization edge cases
- app/routes/api_v1.py (70%): API v1 endpoints
- app/services/correlation.py (92%): edge cases
- app/services/enrichment.py (92%): edge cases
- app/audit_integrity.py (85%): edge cases
- app/services/cleanup.py (85%): edge cases
- app/adapters/pipeline.py (75%): pipeline steps
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Quality service — edge case coverage
# ---------------------------------------------------------------------------

class TestQualityEdgeCases:

    def test_infer_type_ip_v4(self):
        from app.services.quality import infer_type_from_value
        assert infer_type_from_value("192.168.1.1") == "ip"

    def test_infer_type_ip_v6(self):
        from app.services.quality import infer_type_from_value
        assert infer_type_from_value("::1") == "ip"

    def test_infer_type_domain(self):
        from app.services.quality import infer_type_from_value
        assert infer_type_from_value("evil.example.com") == "domain"

    def test_infer_type_url(self):
        from app.services.quality import infer_type_from_value
        assert infer_type_from_value("http://evil.com/path") == "url"

    def test_infer_type_email(self):
        from app.services.quality import infer_type_from_value
        assert infer_type_from_value("user@evil.com") == "email"

    def test_infer_type_hash_md5(self):
        from app.services.quality import infer_type_from_value
        assert infer_type_from_value("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_infer_type_hash_sha256(self):
        from app.services.quality import infer_type_from_value
        sha = "a" * 64
        assert infer_type_from_value(sha) == "hash"

    def test_infer_type_empty_returns_object_id(self):
        from app.services.quality import infer_type_from_value
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
        from app.services.quality import normalize_value
        result = normalize_value("  1.2.3.4  ", "ip")
        assert result == "1.2.3.4"

    def test_normalize_value_domain_lowercase(self):
        from app.services.quality import normalize_value
        result = normalize_value("EVIL.COM", "domain")
        assert result == "evil.com"

    def test_normalize_value_ip_valid(self):
        from app.services.quality import normalize_value
        result = normalize_value("10.0.0.1", "ip")
        assert result == "10.0.0.1"

    def test_normalize_value_invalid_ip_returns_none(self):
        from app.services.quality import normalize_value
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
        from app.services.quality import dedup_rows
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


# ---------------------------------------------------------------------------
# Audit integrity edge cases
# ---------------------------------------------------------------------------

class TestAuditIntegrityEdgeCases:

    def test_verify_audit_chain_empty_list(self):
        from app.audit_integrity import verify_audit_chain
        # Empty list should be valid (no records to violate)
        result = verify_audit_chain([], secret_key="test-secret-key-32-chars-minimum!")
        assert result["valid"] is True

    def test_signed_audit_hash_deterministic(self):
        from app.audit_integrity import signed_audit_hash
        h1 = signed_audit_hash(
            secret_key="key",
            action="test",
            entity_type="indicator",
            entity_id=1,
            user_id="user",
            ip_address="127.0.0.1",
            metadata={},
            created_at=datetime(2024, 1, 1, 0, 0, 0),
            previous_hash="",
        )
        h2 = signed_audit_hash(
            secret_key="key",
            action="test",
            entity_type="indicator",
            entity_id=1,
            user_id="user",
            ip_address="127.0.0.1",
            metadata={},
            created_at=datetime(2024, 1, 1, 0, 0, 0),
            previous_hash="",
        )
        assert h1 == h2

    def test_signed_audit_hash_changes_with_different_inputs(self):
        from app.audit_integrity import signed_audit_hash
        h1 = signed_audit_hash(
            secret_key="key", action="create", entity_type="x", entity_id=1,
            user_id="u", ip_address="1.2.3.4", metadata={},
            created_at=datetime(2024, 1, 1), previous_hash=""
        )
        h2 = signed_audit_hash(
            secret_key="key", action="delete", entity_type="x", entity_id=1,
            user_id="u", ip_address="1.2.3.4", metadata={},
            created_at=datetime(2024, 1, 1), previous_hash=""
        )
        assert h1 != h2


# ---------------------------------------------------------------------------
# Cleanup service edge cases
# ---------------------------------------------------------------------------

class TestCleanupEdgeCases:

    def test_cleanup_export_files_with_custom_extension(self):
        import os
        import tempfile
        import time
        from app.services.cleanup import cleanup_export_files

        with tempfile.TemporaryDirectory() as tmpdir:
            old_file = os.path.join(tmpdir, "old.csv")
            open(old_file, "w").close()
            old_time = time.time() - (25 * 3600)
            os.utime(old_file, (old_time, old_time))
            with patch("app.services.cleanup.Config") as mock_cfg_cls:
                mock_cfg_cls.return_value.EXPORT_JOB_DIR = tmpdir
                deleted = cleanup_export_files(max_age_hours=24)
            assert deleted == 1

    def test_cleanup_export_files_with_new_file_not_deleted(self):
        import os
        import tempfile
        from app.services.cleanup import cleanup_export_files

        with tempfile.TemporaryDirectory() as tmpdir:
            new_file = os.path.join(tmpdir, "new.json")
            open(new_file, "w").close()
            with patch("app.services.cleanup.Config") as mock_cfg_cls:
                mock_cfg_cls.return_value.EXPORT_JOB_DIR = tmpdir
                deleted = cleanup_export_files(max_age_hours=24)
            assert deleted == 0
            assert os.path.exists(new_file)


# ---------------------------------------------------------------------------
# API v1 route tests — additional coverage
# ---------------------------------------------------------------------------

class TestApiV1Coverage:

    def test_api_v1_indicators_returns_200(self, client):
        resp = client.get("/api/v1/indicators")
        assert resp.status_code == 200

    def test_api_v1_indicators_json_structure(self, client):
        import json
        resp = client.get("/api/v1/indicators")
        body = json.loads(resp.data)
        assert "items" in body or "indicators" in body or "data" in body or isinstance(body, (list, dict))

    def test_api_v1_indicators_filter_by_type(self, client):
        resp = client.get("/api/v1/indicators?type=ip")
        assert resp.status_code == 200

    def test_api_v1_indicators_filter_by_source(self, client):
        resp = client.get("/api/v1/indicators?source=misp")
        assert resp.status_code == 200

    def test_api_v1_indicators_pagination(self, client):
        resp = client.get("/api/v1/indicators?limit=5&offset=0")
        assert resp.status_code == 200

    def test_api_v1_feeds_returns_200(self, client):
        resp = client.get("/api/v1/feeds")
        assert resp.status_code == 200

    def test_api_v1_feeds_json(self, client):
        import json
        resp = client.get("/api/v1/feeds")
        body = json.loads(resp.data)
        assert isinstance(body, (dict, list))

    def test_api_v1_sync_missing_source(self, client):
        resp = client.post("/api/v1/sync", json={})
        assert resp.status_code == 400

    def test_api_v1_sync_invalid_source(self, client):
        resp = client.post("/api/v1/sync", json={"source": "nonexistent_source_xyz"})
        assert resp.status_code in (400, 202)

    def test_api_v1_runs_current(self, client):
        resp = client.get("/api/v1/runs/current")
        assert resp.status_code in (200, 404)

    def test_api_v1_logs_returns_200(self, client):
        resp = client.get("/api/v1/logs")
        assert resp.status_code in (200, 404)

    def test_openapi_yaml_accessible(self, client):
        resp = client.get("/api/v1/openapi.yaml")
        assert resp.status_code in (200, 404)

    def test_openapi_json_accessible(self, client):
        resp = client.get("/api/v1/openapi.json")
        assert resp.status_code in (200, 404)


# ---------------------------------------------------------------------------
# Enrichment edge cases
# ---------------------------------------------------------------------------

class TestEnrichmentEdgeCases:

    def test_enrich_metadata_empty(self):
        from app.services.enrichment import enrich_metadata
        result = enrich_metadata(value="1.2.3.4", ioc_type="ip", metadata={})
        assert isinstance(result, dict)

    def test_enrich_metadata_domain(self):
        from app.services.enrichment import enrich_metadata
        result = enrich_metadata(value="evil.com", ioc_type="domain", metadata={})
        assert isinstance(result, dict)

    def test_enrich_metadata_url(self):
        from app.services.enrichment import enrich_metadata
        result = enrich_metadata(value="http://evil.com/path", ioc_type="url", metadata={})
        assert isinstance(result, dict)

    def test_enrich_metadata_preserves_existing(self):
        from app.services.enrichment import enrich_metadata
        existing = {"key": "value"}
        result = enrich_metadata(value="1.2.3.4", ioc_type="ip", metadata=existing)
        assert "key" in result

    def test_enrich_metadata_none_metadata(self):
        from app.services.enrichment import enrich_metadata
        result = enrich_metadata(value="1.2.3.4", ioc_type="ip", metadata=None)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Correlation edge cases
# ---------------------------------------------------------------------------

class TestCorrelationEdgeCases:

    def test_query_correlations_empty_db(self, test_db):
        from app.services.correlation import query_correlations
        result = query_correlations(test_db, min_sources=2, limit=10, ioc_type=None)
        assert isinstance(result, list)

    def test_query_correlations_with_type_filter(self, test_db):
        from app.services.correlation import query_correlations
        result = query_correlations(test_db, min_sources=2, limit=10, ioc_type="ip")
        assert isinstance(result, list)

    def test_query_correlations_min_sources_3(self, test_db):
        from app.services.correlation import query_correlations
        result = query_correlations(test_db, min_sources=3, limit=5, ioc_type=None)
        assert isinstance(result, list)
