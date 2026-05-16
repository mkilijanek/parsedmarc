"""Tests for app/services/export_svc — _run_export_job and _spawn_export_job (issue #240)."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _make_export_svc(tmp_path, cfg_overrides=None):
    """Build a minimal make_export_service instance for unit testing."""
    from app.services.export_svc import make_export_service

    cfg = MagicMock()
    cfg.EXPORT_JOB_DIR = str(tmp_path)
    cfg.EXPORT_JOB_TTL_HOURS = 24
    cfg.AZURE_SENTINEL_AUTH_MODE = "client_secret"
    cfg.AZURE_SENTINEL_TENANT_ID = ""
    cfg.AZURE_SENTINEL_CLIENT_ID = ""
    cfg.AZURE_SENTINEL_CLIENT_SECRET = ""
    cfg.AZURE_SENTINEL_CERT_PRIVATE_KEY_PEM = ""
    cfg.AZURE_SENTINEL_CERT_THUMBPRINT = ""
    cfg.AZURE_SENTINEL_SCOPE = ""
    cfg.AZURE_SENTINEL_ENDPOINT_URL = ""
    cfg.AZURE_SENTINEL_CHUNK_SIZE = 100
    cfg.FEED_HTTP_TIMEOUT_S = 30
    if cfg_overrides:
        for k, v in cfg_overrides.items():
            setattr(cfg, k, v)

    mock_db = MagicMock()
    mock_db.scalar.return_value = None  # default: no job found

    def db_fn():
        return MagicMock()

    def app_log_fn(*a, **kw):
        pass

    def count_fn(*a, **kw):
        return 0

    def query_fn(*a, **kw):
        return []

    def get_setting_fn(db, key, default="", secret=False):
        return default

    svc = make_export_service(
        cfg=cfg,
        db_fn=db_fn,
        app_log_fn=app_log_fn,
        count_indicators_fn=count_fn,
        query_indicators_fn=query_fn,
        get_setting_fn=get_setting_fn,
    )
    return svc, cfg


class TestRunExportJob:

    def test_run_export_job_no_job_found(self, tmp_path):
        """_run_export_job exits early if job not in DB."""
        svc, cfg = _make_export_svc(tmp_path)
        # Call should not raise even if DB returns nothing
        svc.run_export_job("nonexistent-job")

    def test_run_export_job_completes_successfully(self, tmp_path):
        """_run_export_job writes output file and sets status=completed."""
        from app.services.export_svc import make_export_service

        cfg = MagicMock()
        cfg.EXPORT_JOB_DIR = str(tmp_path)
        cfg.EXPORT_JOB_TTL_HOURS = 24
        cfg.FEED_HTTP_TIMEOUT_S = 30

        mock_job = MagicMock()
        mock_job.job_id = "test-job-abc"
        mock_job.fmt = "json"
        mock_job.status = "queued"
        mock_job.query_json = {"limit": "10", "offset": "0"}

        mock_db = MagicMock()
        mock_db.scalar.return_value = mock_job

        def db_fn():
            return mock_db

        svc = make_export_service(
            cfg=cfg,
            db_fn=db_fn,
            app_log_fn=MagicMock(),
            count_indicators_fn=MagicMock(return_value=0),
            query_indicators_fn=MagicMock(return_value=[]),
            get_setting_fn=MagicMock(return_value=""),
        )

        svc.run_export_job("test-job-abc")

        # job status should be set to completed
        assert mock_job.status == "completed"
        assert mock_job.result_path is not None

    def test_run_export_job_sets_failed_on_exception(self, tmp_path):
        """_run_export_job sets status=failed if an exception occurs."""
        from app.services.export_svc import make_export_service

        cfg = MagicMock()
        cfg.EXPORT_JOB_DIR = str(tmp_path)
        cfg.EXPORT_JOB_TTL_HOURS = 24
        cfg.FEED_HTTP_TIMEOUT_S = 30

        mock_job = MagicMock()
        mock_job.job_id = "error-job"
        mock_job.fmt = "json"
        mock_job.status = "queued"
        mock_job.query_json = {}

        call_n = [0]

        def bad_query(*args, **kwargs):
            raise RuntimeError("db exploded")

        mock_db = MagicMock()
        mock_db.scalar.return_value = mock_job

        svc = make_export_service(
            cfg=cfg,
            db_fn=lambda: mock_db,
            app_log_fn=MagicMock(),
            count_indicators_fn=MagicMock(return_value=0),
            query_indicators_fn=bad_query,
            get_setting_fn=MagicMock(return_value=""),
        )

        svc.run_export_job("error-job")
        assert mock_job.status == "failed"
        assert "db exploded" in (mock_job.error or "")

    def test_persist_export_job_sets_token_and_expiry(self, tmp_path):
        """_persist_export_job stores access_token and expires_at."""
        from app.services.export_svc import make_export_service

        cfg = MagicMock()
        cfg.EXPORT_JOB_DIR = str(tmp_path)
        cfg.EXPORT_JOB_TTL_HOURS = 24

        added_jobs = []
        mock_db = MagicMock()
        mock_db.add.side_effect = added_jobs.append

        svc = make_export_service(
            cfg=cfg,
            db_fn=lambda: mock_db,
            app_log_fn=MagicMock(),
            count_indicators_fn=MagicMock(return_value=0),
            query_indicators_fn=MagicMock(return_value=[]),
            get_setting_fn=MagicMock(return_value=""),
        )

        svc.persist_export_job("job-token-test", "json", {})

        assert len(added_jobs) == 1
        job_obj = added_jobs[0]
        assert job_obj.access_token is not None
        assert len(job_obj.access_token) == 64
        assert job_obj.expires_at is not None

    def test_persist_export_job_custom_ttl(self, tmp_path):
        """_persist_export_job respects ttl_hours_fn override."""
        from app.services.export_svc import make_export_service

        cfg = MagicMock()
        cfg.EXPORT_JOB_DIR = str(tmp_path)
        cfg.EXPORT_JOB_TTL_HOURS = 24

        added_jobs = []
        mock_db = MagicMock()
        mock_db.add.side_effect = added_jobs.append

        svc = make_export_service(
            cfg=cfg,
            db_fn=lambda: mock_db,
            app_log_fn=MagicMock(),
            count_indicators_fn=MagicMock(return_value=0),
            query_indicators_fn=MagicMock(return_value=[]),
            get_setting_fn=MagicMock(return_value=""),
            ttl_hours_fn=lambda: 48,
        )

        svc.persist_export_job("job-48h", "json", {})

        job_obj = added_jobs[0]
        expected_expiry = datetime.now(timezone.utc) + timedelta(hours=48)
        diff = abs((job_obj.expires_at - expected_expiry).total_seconds())
        assert diff < 5

    def test_spawn_export_job_starts_thread(self, tmp_path):
        """_spawn_export_job starts a daemon thread."""
        svc, cfg = _make_export_svc(tmp_path)

        with patch("app.services.export_svc.Thread") as mock_thread_cls:
            mock_thread = MagicMock()
            mock_thread_cls.return_value = mock_thread
            svc.spawn_export_job("some-job-id")
            mock_thread_cls.assert_called_once()
            mock_thread.start.assert_called_once()

    def test_render_export_body_json(self, tmp_path):
        """_render_export_body returns body and mime for json format."""
        svc, cfg = _make_export_svc(tmp_path)
        body, mime = svc.render_export_body("json", [])
        assert mime is not None
        assert isinstance(body, str)
