from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import select

from .db import get_session

logger = logging.getLogger(__name__)


@dataclass
class WorkerState:
    started_at: float = field(default_factory=time.time)
    last_loop_at: float = field(default_factory=time.time)
    last_job_start_at: float | None = None
    last_job_success_at: float | None = None
    last_job_failure_at: float | None = None
    active_jobs: int = 0
    jobs_run: int = 0
    jobs_failed: int = 0
    shutdown_requested: bool = False
    last_error: str = ""


_state = WorkerState()
_state_lock = threading.Lock()


def mark_loop() -> None:
    with _state_lock:
        _state.last_loop_at = time.time()


def mark_shutdown_requested() -> None:
    with _state_lock:
        _state.shutdown_requested = True


def mark_job_start(name: str) -> None:
    with _state_lock:
        _state.active_jobs += 1
        _state.last_job_start_at = time.time()
        _state.last_error = ""


def mark_job_success(name: str) -> None:
    with _state_lock:
        _state.active_jobs = max(0, _state.active_jobs - 1)
        _state.jobs_run += 1
        _state.last_job_success_at = time.time()


def mark_job_failure(name: str, error: str) -> None:
    with _state_lock:
        _state.active_jobs = max(0, _state.active_jobs - 1)
        _state.jobs_run += 1
        _state.jobs_failed += 1
        _state.last_job_failure_at = time.time()
        _state.last_error = error


def active_jobs() -> int:
    with _state_lock:
        return _state.active_jobs


def snapshot() -> dict[str, Any]:
    with _state_lock:
        return {
            "started_at": _state.started_at,
            "last_loop_at": _state.last_loop_at,
            "last_job_start_at": _state.last_job_start_at,
            "last_job_success_at": _state.last_job_success_at,
            "last_job_failure_at": _state.last_job_failure_at,
            "active_jobs": _state.active_jobs,
            "jobs_run": _state.jobs_run,
            "jobs_failed": _state.jobs_failed,
            "shutdown_requested": _state.shutdown_requested,
            "last_error": _state.last_error,
        }


def _database_ok() -> tuple[bool, str]:
    db = get_session(read_only=False)
    try:
        db.execute(select(1))
        return True, ""
    except Exception as exc:
        return False, str(exc)
    finally:
        db.close()


def health_payload(max_loop_age_s: int) -> tuple[int, dict[str, Any]]:
    now = time.time()
    state = snapshot()
    loop_age_s = max(0.0, now - float(state["last_loop_at"]))
    db_ok, db_error = _database_ok()
    healthy = (
        not bool(state["shutdown_requested"])
        and loop_age_s <= max_loop_age_s
        and db_ok
    )
    checks = {
        "scheduler_loop": {
            "ok": loop_age_s <= max_loop_age_s,
            "age_s": round(loop_age_s, 3),
            "max_age_s": max_loop_age_s,
        },
        "database": {
            "ok": db_ok,
            "error": db_error,
        },
        "shutdown": {
            "ok": not bool(state["shutdown_requested"]),
            "requested": bool(state["shutdown_requested"]),
        },
    }
    payload = {
        "status": "ok" if healthy else "degraded",
        "checks": checks,
        "state": state,
    }
    return (200 if healthy else 503), payload


class WorkerHealthServer:
    def __init__(self, host: str, port: int, max_loop_age_s: int) -> None:
        self.host = host
        self.port = int(port)
        self.max_loop_age_s = max(1, int(max_loop_age_s))
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.port <= 0:
            logger.info("worker_health_disabled")
            return

        max_loop_age_s = self.max_loop_age_s

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/healthz":
                    status, payload = health_payload(max_loop_age_s)
                    body = json.dumps(payload, sort_keys=True).encode("utf-8")
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/metrics":
                    body = generate_latest()
                    self.send_response(200)
                    self.send_header("Content-Type", CONTENT_TYPE_LATEST)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, fmt: str, *args: Any) -> None:
                logger.debug("worker_health_request", extra={"message": fmt % args})

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("worker_health_started", extra={"host": self.host, "port": self.port})

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        logger.info("worker_health_stopped")
