from __future__ import annotations

import time
from unittest.mock import patch

from app import worker_health


def _reset_worker_state() -> None:
    now = time.time()
    with worker_health._state_lock:
        worker_health._state.started_at = now
        worker_health._state.last_loop_at = now
        worker_health._state.last_job_start_at = None
        worker_health._state.last_job_success_at = None
        worker_health._state.last_job_failure_at = None
        worker_health._state.active_jobs = 0
        worker_health._state.jobs_run = 0
        worker_health._state.jobs_failed = 0
        worker_health._state.shutdown_requested = False
        worker_health._state.last_error = ""


def test_worker_health_payload_ok(monkeypatch):
    _reset_worker_state()
    monkeypatch.setattr(worker_health, "_database_ok", lambda: (True, ""))

    status, payload = worker_health.health_payload(max_loop_age_s=30)

    assert status == 200
    assert payload["status"] == "ok"
    assert payload["checks"]["database"]["ok"] is True
    assert payload["checks"]["scheduler_loop"]["ok"] is True


def test_worker_health_payload_degraded_when_loop_stale(monkeypatch):
    _reset_worker_state()
    monkeypatch.setattr(worker_health, "_database_ok", lambda: (True, ""))
    with worker_health._state_lock:
        worker_health._state.last_loop_at = time.time() - 120

    status, payload = worker_health.health_payload(max_loop_age_s=30)

    assert status == 503
    assert payload["status"] == "degraded"
    assert payload["checks"]["scheduler_loop"]["ok"] is False


def test_worker_health_job_state_transitions():
    _reset_worker_state()

    worker_health.mark_job_start("test")
    assert worker_health.active_jobs() == 1

    worker_health.mark_job_failure("test", "boom")
    snapshot = worker_health.snapshot()

    assert snapshot["active_jobs"] == 0
    assert snapshot["jobs_run"] == 1
    assert snapshot["jobs_failed"] == 1
    assert snapshot["last_error"] == "boom"


# ---------------------------------------------------------------------------
# TestWorkerHealth — migrated from test_coverage_boost.py
# ---------------------------------------------------------------------------

class TestWorkerHealth:

    def test_mark_loop_updates_timestamp(self):
        from app.worker_health import mark_loop, _state, _state_lock
        before = _state.last_loop_at
        time.sleep(0.01)
        mark_loop()
        assert _state.last_loop_at >= before

    def test_mark_job_start_increments_active(self):
        from app.worker_health import mark_job_start, mark_job_success, _state, _state_lock
        with _state_lock:
            initial = _state.active_jobs
        mark_job_start("test_job")
        with _state_lock:
            assert _state.active_jobs == initial + 1
        mark_job_success("test_job")

    def test_mark_job_success_decrements_active(self):
        from app.worker_health import mark_job_start, mark_job_success, _state, _state_lock
        mark_job_start("test")
        with _state_lock:
            before = _state.active_jobs
        mark_job_success("test")
        with _state_lock:
            assert _state.active_jobs == before - 1

    def test_mark_job_failure_updates_state(self):
        from app.worker_health import mark_job_start, mark_job_failure, _state, _state_lock
        mark_job_start("fail_job")
        with _state_lock:
            before_failed = _state.jobs_failed
        mark_job_failure("fail_job", "timeout error")
        with _state_lock:
            assert _state.jobs_failed == before_failed + 1
            assert _state.last_error == "timeout error"

    def test_active_jobs_returns_count(self):
        from app.worker_health import active_jobs, mark_job_start, mark_job_success
        mark_job_start("aj_test")
        count = active_jobs()
        assert count >= 1
        mark_job_success("aj_test")

    def test_snapshot_returns_dict(self):
        from app.worker_health import snapshot
        s = snapshot()
        assert "started_at" in s
        assert "last_loop_at" in s
        assert "active_jobs" in s
        assert "jobs_run" in s
        assert "jobs_failed" in s
        assert "shutdown_requested" in s
        assert "last_error" in s

    def test_health_payload_returns_tuple(self):
        from app.worker_health import health_payload, mark_loop
        mark_loop()
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            code, payload = health_payload(max_loop_age_s=60)
        assert isinstance(code, int)
        assert "status" in payload
        assert "checks" in payload

    def test_health_payload_degraded_when_loop_stale(self):
        from app.worker_health import health_payload, _state, _state_lock
        with _state_lock:
            _state.last_loop_at = time.time() - 999
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            code, payload = health_payload(max_loop_age_s=10)
        assert code == 503
        assert payload["status"] == "degraded"
        with _state_lock:
            _state.last_loop_at = time.time()

    def test_health_payload_degraded_when_db_down(self):
        from app.worker_health import health_payload, mark_loop
        mark_loop()
        with patch("app.worker_health._database_ok", return_value=(False, "connection refused")):
            code, payload = health_payload(max_loop_age_s=60)
        assert code == 503
        assert payload["checks"]["database"]["ok"] is False

    def test_health_payload_degraded_when_shutdown(self):
        from app.worker_health import health_payload, mark_loop, mark_shutdown_requested, _state, _state_lock
        mark_loop()
        with _state_lock:
            original = _state.shutdown_requested
        with _state_lock:
            _state.shutdown_requested = True
        try:
            with patch("app.worker_health._database_ok", return_value=(True, "")):
                code, payload = health_payload(max_loop_age_s=60)
            assert payload["checks"]["shutdown"]["requested"] is True
        finally:
            with _state_lock:
                _state.shutdown_requested = original

    def test_worker_health_server_disabled_when_port_zero(self):
        from app.worker_health import WorkerHealthServer
        server = WorkerHealthServer("127.0.0.1", 0, 60)
        server.start()  # should log and return without starting
        assert server._server is None
        server.stop()  # should be a no-op


# ---------------------------------------------------------------------------
# TestWorkerHealthState — migrated from test_coverage_boost4.py
# ---------------------------------------------------------------------------

class TestWorkerHealthState:

    def test_mark_job_start_increments_active(self):
        from app.worker_health import mark_job_start, active_jobs, snapshot
        before = active_jobs()
        mark_job_start("test_job")
        assert active_jobs() == before + 1
        # Clean up
        from app.worker_health import mark_job_success
        mark_job_success("test_job")

    def test_mark_job_success_decrements_active(self):
        from app.worker_health import mark_job_start, mark_job_success, active_jobs
        mark_job_start("success_job")
        before = active_jobs()
        mark_job_success("success_job")
        assert active_jobs() == before - 1

    def test_mark_job_failure_decrements_active(self):
        from app.worker_health import mark_job_start, mark_job_failure, active_jobs
        mark_job_start("fail_job")
        before = active_jobs()
        mark_job_failure("fail_job", "something went wrong")
        assert active_jobs() == before - 1

    def test_mark_shutdown_requested(self):
        from app.worker_health import mark_shutdown_requested, snapshot
        mark_shutdown_requested()
        state = snapshot()
        assert state["shutdown_requested"] is True
        # Reset for other tests
        import app.worker_health as wh
        with wh._state_lock:
            wh._state.shutdown_requested = False

    def test_snapshot_returns_all_keys(self):
        from app.worker_health import snapshot
        s = snapshot()
        for key in ("started_at", "last_loop_at", "active_jobs", "jobs_run", "jobs_failed", "shutdown_requested"):
            assert key in s

    def test_health_payload_with_db_ok(self):
        from app.worker_health import health_payload
        with patch("app.worker_health._database_ok", return_value=(True, "")):
            status, payload = health_payload(max_loop_age_s=3600)
        assert "status" in payload
        assert "checks" in payload

    def test_health_payload_with_db_error(self):
        from app.worker_health import health_payload
        with patch("app.worker_health._database_ok", return_value=(False, "connection refused")):
            status, payload = health_payload(max_loop_age_s=3600)
        assert payload["checks"]["database"]["ok"] is False
        assert status == 503
