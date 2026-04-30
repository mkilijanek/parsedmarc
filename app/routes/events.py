"""Server-Sent Events endpoint — /api/events.

Streams live operational events: sync status changes, feed health updates, and
periodic heartbeat pings so clients can detect dropped connections early.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Dict

from flask import Response, jsonify, request
from sqlalchemy import func, select

_SSE_SLOT_LOCK = threading.Lock()
_SSE_CONNECTION_SLOTS: Dict[int, threading.BoundedSemaphore] = {}


def register_events_routes(
    app,
    *,
    limiter,
    cfg,
    deps: Dict[str, Any],
) -> None:
    _db = deps["_db"]
    _dep_status = deps["_dep_status"]
    Indicator = deps["Indicator"]
    SyncJob = deps["SyncJob"]
    FeedRun = deps["FeedRun"]

    @app.get("/api/events")
    @limiter.limit("10 per minute")
    def api_events():
        """SSE stream: heartbeat, sync status, feed health, indicator count."""
        if not getattr(cfg.runtime, "SSE_ENABLED", True):
            return jsonify({"error": "sse_disabled"}), 404
        worker_class = str(app.config.get("GUNICORN_WORKER_CLASS") or "").strip().lower()
        if worker_class == "sync" and not getattr(cfg.runtime, "SSE_ALLOW_SYNC_WORKERS", False) and not app.config.get("TESTING"):
            return jsonify({
                "error": "sse_requires_non_sync_workers",
                "message": "Configure gthread/gevent workers or set SSE_ALLOW_SYNC_WORKERS=true for lab-only use.",
            }), 503
        with _SSE_SLOT_LOCK:
            limiter_key = id(app)
            semaphore = _SSE_CONNECTION_SLOTS.setdefault(
                limiter_key,
                threading.BoundedSemaphore(max(1, int(getattr(cfg.runtime, "SSE_MAX_CONNECTIONS", 25)))),
            )
        if not semaphore.acquire(blocking=False):
            return jsonify({"error": "sse_capacity_exceeded"}), 503

        def generate():
            last_sync_status: dict = {}
            last_indicator_count: int = -1
            last_heartbeat = time.time()
            heartbeat_interval = max(5, int(getattr(cfg.runtime, "SSE_HEARTBEAT_INTERVAL_S", 15)))
            max_duration_s = max(heartbeat_interval, int(getattr(cfg.runtime, "SSE_MAX_DURATION_S", 300)))
            max_iterations = max(1, max_duration_s // heartbeat_interval)

            try:
                for _ in range(max_iterations):
                    now = time.time()

                    if now - last_heartbeat >= heartbeat_interval:
                        last_heartbeat = now
                        yield _sse("heartbeat", {"ts": int(now)})

                    try:
                        db = _db(read_only=True)
                        try:
                            total = db.scalar(
                                select(func.count()).select_from(Indicator).where(Indicator.is_active == True)  # noqa: E712
                            ) or 0
                            if total != last_indicator_count:
                                last_indicator_count = total
                                yield _sse("indicators", {"count": total})

                            runs = db.scalars(
                                select(FeedRun)
                                .order_by(FeedRun.started_at.desc())
                                .limit(5)
                            ).all()
                            sync_snapshot = {
                                r.run_id: {
                                    "feed": r.feed_source_id,
                                    "status": r.status,
                                    "started_at": str(r.started_at) if r.started_at else None,
                                }
                                for r in runs
                            }
                            if sync_snapshot != last_sync_status:
                                last_sync_status = sync_snapshot
                                yield _sse("sync", {"runs": list(sync_snapshot.values())})
                        finally:
                            db.close()

                        dep_all = _dep_status.get_all()
                        if dep_all:
                            yield _sse("feed_health", dep_all)

                    except Exception as err:
                        yield _sse("error", {"message": str(err)[:200]})

                    time.sleep(heartbeat_interval)
            finally:
                semaphore.release()

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )


def _sse(event: str, data: Any) -> str:
    payload = json.dumps(data, default=str)
    return f"event: {event}\ndata: {payload}\n\n"
