"""Tests for app/worker_health.py — health_payload, WorkerHealthServer. Closes #235."""
from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection
from unittest.mock import MagicMock, patch

import pytest

import app.worker_health as _wh_mod
from app.worker_health import WorkerHealthServer, health_payload, snapshot


class TestSnapshot:
    def test_snapshot_returns_dict(self):
        s = snapshot()
        assert isinstance(s, dict)
        assert "last_loop_at" in s
        assert "shutdown_requested" in s

    def test_mark_loop_updates_timestamp(self):
        before = _wh_mod._state.last_loop_at
        _wh_mod.mark_loop()
        assert _wh_mod._state.last_loop_at >= before

    def test_mark_shutdown_requested(self):
        original = _wh_mod._state.shutdown_requested
        _wh_mod.mark_shutdown_requested()
        assert _wh_mod._state.shutdown_requested is True
        _wh_mod._state.shutdown_requested = original

    def test_mark_job_start_increments_active(self):
        original = _wh_mod._state.active_jobs
        _wh_mod.mark_job_start("test_job")
        assert _wh_mod._state.active_jobs == original + 1
        _wh_mod._state.active_jobs = original

    def test_mark_job_success_decrements_active(self):
        _wh_mod._state.active_jobs = 1
        _wh_mod.mark_job_success("test_job")
        assert _wh_mod._state.active_jobs == 0

    def test_mark_job_failure_records_error(self):
        original_failed = _wh_mod._state.jobs_failed
        _wh_mod.mark_job_failure("test_job", "err_msg")
        assert _wh_mod._state.jobs_failed == original_failed + 1
        assert _wh_mod._state.last_error == "err_msg"


class TestHealthPayload:
    def test_healthy_when_loop_recent_and_db_ok(self):
        _wh_mod.mark_loop()
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            _wh_mod._state.shutdown_requested = False
            status, payload = health_payload(max_loop_age_s=60)
        assert status == 200
        assert payload["status"] == "ok"
        assert payload["checks"]["database"]["ok"] is True

    def test_degraded_when_loop_old(self):
        _wh_mod._state.last_loop_at = time.time() - 9999
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            _wh_mod._state.shutdown_requested = False
            status, payload = health_payload(max_loop_age_s=10)
        assert status == 503
        assert payload["status"] == "degraded"
        _wh_mod.mark_loop()

    def test_degraded_when_db_down(self):
        _wh_mod.mark_loop()
        with patch("app.worker_health._database_ok", return_value=(False, "connection refused")):
            _wh_mod._state.shutdown_requested = False
            status, payload = health_payload(max_loop_age_s=60)
        assert status == 503
        assert payload["checks"]["database"]["ok"] is False
        assert "connection refused" in payload["checks"]["database"]["error"]

    def test_degraded_when_shutdown_requested(self):
        _wh_mod.mark_loop()
        _wh_mod._state.shutdown_requested = True
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            status, payload = health_payload(max_loop_age_s=60)
        assert status == 503
        assert payload["checks"]["shutdown"]["requested"] is True
        _wh_mod._state.shutdown_requested = False

    def test_payload_contains_state(self):
        _wh_mod.mark_loop()
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            _wh_mod._state.shutdown_requested = False
            _, payload = health_payload(max_loop_age_s=60)
        assert "state" in payload
        assert "checks" in payload


class TestDatabaseOk:
    def test_returns_true_when_db_responds(self):
        mock_db = MagicMock()
        mock_db.execute = MagicMock(return_value=MagicMock())
        with patch("app.worker_health.get_session", return_value=mock_db):
            ok, err = _wh_mod._database_ok()
        assert ok is True
        assert err == ""
        mock_db.close.assert_called_once()

    def test_returns_false_when_db_raises(self):
        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("connection lost")
        with patch("app.worker_health.get_session", return_value=mock_db):
            ok, err = _wh_mod._database_ok()
        assert ok is False
        assert "connection lost" in err
        mock_db.close.assert_called_once()


class TestWorkerHealthServer:
    def test_start_disabled_when_port_zero(self):
        server = WorkerHealthServer("127.0.0.1", 0, 60)
        server.start()
        assert server._server is None

    def test_stop_noop_when_not_started(self):
        server = WorkerHealthServer("127.0.0.1", 0, 60)
        server.stop()  # should not raise

    def test_healthz_endpoint_returns_json(self):
        import socket
        # Find a free port
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        server = WorkerHealthServer("127.0.0.1", port, 60)
        _wh_mod.mark_loop()
        _wh_mod._state.shutdown_requested = False
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            server.start()
            time.sleep(0.1)
            try:
                conn = HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", "/healthz")
                resp = conn.getresponse()
                body = resp.read()
                conn.close()
            finally:
                server.stop()

        assert resp.status in (200, 503)
        data = json.loads(body)
        assert "status" in data
        assert "checks" in data

    def test_metrics_endpoint_returns_prometheus(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        server = WorkerHealthServer("127.0.0.1", port, 60)
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            server.start()
            time.sleep(0.1)
            try:
                conn = HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", "/metrics")
                resp = conn.getresponse()
                body = resp.read()
                conn.close()
            finally:
                server.stop()

        assert resp.status == 200

    def test_unknown_path_returns_404(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        server = WorkerHealthServer("127.0.0.1", port, 60)
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            server.start()
            time.sleep(0.1)
            try:
                conn = HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", "/nonexistent")
                resp = conn.getresponse()
                resp.read()
                conn.close()
            finally:
                server.stop()

        assert resp.status == 404
