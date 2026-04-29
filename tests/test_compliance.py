"""Tests for compliance-1.0 deliverables: log export, CEF format, retention, cleanup."""
from __future__ import annotations

import hashlib
import json
import os
import time
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.models import AppLog


class TestLogsExportEndpoint:
    """Tests for GET /api/logs/export (checksummed JSON export)."""

    def test_export_returns_200(self, admin_client):
        resp = admin_client.get("/api/logs/export")
        assert resp.status_code == 200

    def test_export_content_type_is_json(self, admin_client):
        resp = admin_client.get("/api/logs/export")
        assert "application/json" in resp.content_type

    def test_export_has_checksum_header(self, admin_client):
        resp = admin_client.get("/api/logs/export")
        assert "X-Export-Checksum" in resp.headers
        assert resp.headers["X-Export-Checksum"].startswith("sha256:")

    def test_export_checksum_matches_payload(self, admin_client):
        resp = admin_client.get("/api/logs/export")
        header_checksum = resp.headers["X-Export-Checksum"]
        body = json.loads(resp.data)

        # The checksum was computed over items/count/exported_at (before the checksum field was added).
        # Reconstruct that intermediate payload and verify.
        intermediate = {
            "count": body["count"],
            "exported_at": body["exported_at"],
            "items": body["items"],
        }
        expected = "sha256:" + hashlib.sha256(
            json.dumps(intermediate, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        assert header_checksum == expected

    def test_export_body_contains_checksum_field(self, admin_client):
        resp = admin_client.get("/api/logs/export")
        body = json.loads(resp.data)
        assert "export_checksum" in body
        assert body["export_checksum"].startswith("sha256:")

    def test_export_header_and_body_checksum_agree(self, admin_client):
        resp = admin_client.get("/api/logs/export")
        body = json.loads(resp.data)
        assert resp.headers["X-Export-Checksum"] == body["export_checksum"]

    def test_export_has_count_and_items(self, admin_client):
        resp = admin_client.get("/api/logs/export")
        body = json.loads(resp.data)
        assert "count" in body
        assert "items" in body
        assert isinstance(body["items"], list)

    def test_export_has_exported_at_field(self, admin_client):
        resp = admin_client.get("/api/logs/export")
        body = json.loads(resp.data)
        assert "exported_at" in body
        assert "T" in body["exported_at"]  # ISO format contains date and time

    def test_export_level_filter(self, admin_client, test_db):
        test_db.add(AppLog(level="ERROR", component="test", message="err-for-export",
                           created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        test_db.add(AppLog(level="INFO", component="test", message="info-for-export",
                           created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        test_db.commit()

        resp = admin_client.get("/api/logs/export?level=ERROR")
        body = json.loads(resp.data)
        assert all(item["level"] == "ERROR" for item in body["items"])

    def test_export_limit_respected(self, admin_client):
        resp = admin_client.get("/api/logs/export?limit=1")
        body = json.loads(resp.data)
        assert len(body["items"]) <= 1

    def test_export_unauthenticated_still_works(self, client):
        # /api/logs/export is rate-limited but does not require admin auth
        resp = client.get("/api/logs/export")
        assert resp.status_code == 200


class TestLogsCefFormat:
    """Tests for GET /api/logs?format=cef (ArcSight CEF output)."""

    def test_cef_returns_200(self, admin_client):
        resp = admin_client.get("/api/logs?format=cef")
        assert resp.status_code == 200

    def test_cef_content_type_is_text_plain(self, admin_client):
        resp = admin_client.get("/api/logs?format=cef")
        assert "text/plain" in resp.content_type

    def test_cef_with_log_rows(self, admin_client, test_db):
        test_db.add(AppLog(level="WARNING", component="scheduler", message="cef-test",
                           feed_source_id="misp", created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        test_db.commit()

        resp = admin_client.get("/api/logs?format=cef&level=WARNING")
        lines = resp.data.decode("utf-8").strip().splitlines()
        assert len(lines) >= 1
        assert lines[0].startswith("CEF:0|ioc-service|app|")
        assert "cs1Label=component" in lines[0]
        assert "scheduler" in lines[0]

    def test_cef_severity_mapping_warning(self, admin_client, test_db):
        test_db.add(AppLog(level="WARNING", component="test", message="sev-test",
                           created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        test_db.commit()

        resp = admin_client.get("/api/logs?format=cef&level=WARNING&component=test")
        text = resp.data.decode("utf-8")
        # CEF severity 5 for WARNING
        assert "|WARNING|WARNING|5|" in text

    def test_cef_severity_mapping_error(self, admin_client, test_db):
        test_db.add(AppLog(level="ERROR", component="test-cef-err", message="err-sev",
                           created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        test_db.commit()

        resp = admin_client.get("/api/logs?format=cef&level=ERROR&component=test-cef-err")
        text = resp.data.decode("utf-8")
        assert "|ERROR|ERROR|8|" in text

    def test_cef_empty_result_returns_empty_body(self, admin_client):
        resp = admin_client.get("/api/logs?format=cef&feed=nonexistent-feed-xyz")
        assert resp.status_code == 200
        assert resp.data == b"\n" or resp.data == b""

    def test_cef_pipe_level_filter(self, admin_client, test_db):
        test_db.add(AppLog(level="WARNING", component="pipe-test", message="warn-pipe",
                           created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        test_db.add(AppLog(level="ERROR", component="pipe-test", message="err-pipe",
                           created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        test_db.add(AppLog(level="INFO", component="pipe-test", message="info-pipe",
                           created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        test_db.commit()

        resp = admin_client.get("/api/logs?format=cef&level=WARNING|ERROR&component=pipe-test")
        lines = [l for l in resp.data.decode().splitlines() if l]
        levels_in_output = [l.split("|")[5] for l in lines]
        assert set(levels_in_output) <= {"WARNING", "ERROR"}
        assert "INFO" not in resp.data.decode()


class TestLogRetention:
    """Tests for log retention policy and config."""

    def test_log_retention_days_config_default(self):
        from app.config import RuntimeConfig
        cfg = RuntimeConfig()
        assert cfg.LOG_RETENTION_DAYS == 90

    def test_log_retention_days_env_override(self):
        import os
        from app.config import RuntimeConfig
        with patch.dict(os.environ, {"LOG_RETENTION_DAYS": "30"}):
            cfg = RuntimeConfig()
            assert cfg.LOG_RETENTION_DAYS == 30


class TestCleanupService:
    """Tests for app/services/cleanup.py — export file and indicator cleanup."""

    def test_cleanup_export_files_removes_old_files(self):
        from app.services.cleanup import cleanup_export_files

        with tempfile.TemporaryDirectory() as tmpdir:
            old_file = os.path.join(tmpdir, "old-export.json")
            new_file = os.path.join(tmpdir, "new-export.json")

            open(old_file, "w").close()
            open(new_file, "w").close()

            # backdate the old file
            old_time = time.time() - (25 * 3600)
            os.utime(old_file, (old_time, old_time))

            with patch("app.services.cleanup.Config") as mock_cfg_cls:
                mock_cfg_cls.return_value.EXPORT_JOB_DIR = tmpdir
                deleted = cleanup_export_files(max_age_hours=24)

            assert deleted == 1
            assert not os.path.exists(old_file)
            assert os.path.exists(new_file)

    def test_cleanup_export_files_noop_when_dir_missing(self):
        from app.services.cleanup import cleanup_export_files

        with patch("app.services.cleanup.Config") as mock_cfg_cls:
            mock_cfg_cls.return_value.EXPORT_JOB_DIR = "/nonexistent/path/xyz"
            deleted = cleanup_export_files()

        assert deleted == 0

    def test_cleanup_old_indicators_removes_inactive(self, test_db):
        from app.services.cleanup import cleanup_old_indicators
        from app.models import Indicator

        old_cutoff = datetime.now(timezone.utc) - timedelta(days=100)
        ind = Indicator(
            value="1.2.3.4",
            type="ip",
            source="test-cleanup",
            source_id="cleanup-test-1",
            is_active=False,
            last_seen=old_cutoff,
            first_seen=old_cutoff,
        )
        test_db.add(ind)
        test_db.commit()

        with patch("app.services.cleanup.SessionLocal", return_value=test_db):
            deleted = cleanup_old_indicators(days_inactive=90)

        assert deleted >= 1
