from __future__ import annotations

import time

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
