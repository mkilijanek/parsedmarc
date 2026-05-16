"""Tests for async export job access token and expiry model (issue #238)."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


class TestExportJobTokenAndExpiry:
    """Tests for ExportJob access_token and expires_at fields."""

    def test_async_export_returns_access_token(self, client):
        """Async export response includes access_token."""
        response = client.get("/indicators/json?limit=100000&async=1")
        assert response.status_code == 202
        data = response.get_json()
        assert "access_token" in data
        assert data["access_token"]

    def test_async_export_status_url_includes_token(self, client):
        """status_url returned from async export includes token query param."""
        response = client.get("/indicators/json?limit=100000&async=1")
        data = response.get_json()
        assert "token=" in data["status_url"]

    def test_async_export_download_url_includes_token(self, client):
        """download_url returned from async export includes token query param."""
        response = client.get("/indicators/json?limit=100000&async=1")
        data = response.get_json()
        assert "token=" in data["download_url"]

    def test_export_status_wrong_token_returns_403(self, client):
        """Status endpoint returns 403 for wrong token."""
        response = client.get("/indicators/json?limit=100000&async=1")
        data = response.get_json()
        job_id = data["job_id"]
        st = client.get(f"/export-jobs/{job_id}?token=wrongtoken")
        assert st.status_code == 403
        assert "invalid token" in st.get_json()["error"]

    def test_export_download_wrong_token_returns_403(self, client):
        """Download endpoint returns 403 for wrong token."""
        response = client.get("/indicators/json?limit=100000&async=1")
        data = response.get_json()
        job_id = data["job_id"]
        dl = client.get(f"/export-jobs/{job_id}/download?token=wrongtoken")
        assert dl.status_code == 403

    def test_export_status_correct_token_succeeds(self, client):
        """Status endpoint returns 200 for correct token."""
        response = client.get("/indicators/json?limit=100000&async=1")
        data = response.get_json()
        status_url = data["status_url"]
        st = client.get(status_url)
        assert st.status_code == 200
        assert "expires_at" in st.get_json()

    def test_export_status_expired_job_returns_410(self, client, test_db):
        """Status endpoint returns 410 for expired job."""
        from app.models import ExportJob
        import secrets
        token = secrets.token_hex(32)
        job = ExportJob(
            job_id="expired-test-job-001",
            fmt="json",
            status="completed",
            query_json={},
            access_token=token,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        test_db.add(job)
        test_db.commit()
        st = client.get(f"/export-jobs/expired-test-job-001?token={token}")
        assert st.status_code == 410
        assert "expired" in st.get_json()["error"]

    def test_export_download_expired_job_returns_410(self, client, test_db):
        """Download endpoint returns 410 for expired job."""
        from app.models import ExportJob
        import secrets
        token = secrets.token_hex(32)
        job = ExportJob(
            job_id="expired-test-job-002",
            fmt="json",
            status="completed",
            result_path="/tmp/notexist.json",
            query_json={},
            access_token=token,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        test_db.add(job)
        test_db.commit()
        dl = client.get(f"/export-jobs/expired-test-job-002/download?token={token}")
        assert dl.status_code == 410

    def test_export_job_missing_returns_404(self, client):
        """Status endpoint returns 404 for unknown job_id."""
        st = client.get("/export-jobs/nonexistent-job-xyz?token=anytoken")
        assert st.status_code == 404

    def test_cleanup_export_files_removes_expired_artifacts(self, tmp_path):
        """cleanup_export_files removes files for expired ExportJob rows."""
        from app.services.cleanup import cleanup_export_files
        from app.models import ExportJob
        import secrets

        artifact = tmp_path / "test_artifact.json"
        artifact.write_text('{"test": true}')

        token = secrets.token_hex(32)
        expired_job = MagicMock()
        expired_job.result_path = str(artifact)

        mock_session = MagicMock()
        mock_session.scalars.return_value.all.return_value = [expired_job]

        with patch("app.services.cleanup.Config") as mock_cfg, \
             patch("app.services.cleanup.SessionLocal", return_value=mock_session):
            mock_cfg.return_value.EXPORT_JOB_DIR = str(tmp_path)
            mock_cfg.return_value.EXPORT_JOB_TTL_HOURS = 24
            deleted = cleanup_export_files()

        assert deleted >= 1
        assert not artifact.exists()

    def test_cleanup_export_files_skips_already_deleted(self, tmp_path):
        """cleanup_export_files handles already-deleted artifacts gracefully."""
        from app.services.cleanup import cleanup_export_files

        missing_job = MagicMock()
        missing_job.result_path = str(tmp_path / "nonexistent.json")

        mock_session = MagicMock()
        mock_session.scalars.return_value.all.return_value = [missing_job]

        with patch("app.services.cleanup.Config") as mock_cfg, \
             patch("app.services.cleanup.SessionLocal", return_value=mock_session):
            mock_cfg.return_value.EXPORT_JOB_DIR = str(tmp_path)
            mock_cfg.return_value.EXPORT_JOB_TTL_HOURS = 24
            deleted = cleanup_export_files()

        assert deleted == 0
