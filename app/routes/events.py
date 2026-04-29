"""Server-Sent Events endpoint — /api/events.

Streams live operational events: sync status changes, feed health updates, and
periodic heartbeat pings so clients can detect dropped connections early.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict

from flask import Response, request
from sqlalchemy import func, select


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

        def generate():
            last_sync_status: dict = {}
            last_indicator_count: int = -1
            last_heartbeat = time.time()
            heartbeat_interval = 15  # seconds

            for _ in range(180):  # max ~45 minutes (180 × 15s)
                now = time.time()

                # Heartbeat every 15s
                if now - last_heartbeat >= heartbeat_interval:
                    last_heartbeat = now
                    yield _sse("heartbeat", {"ts": int(now)})

                try:
                    db = _db(read_only=True)
                    try:
                        # Active indicator count
                        total = db.scalar(
                            select(func.count()).select_from(Indicator).where(Indicator.is_active == True)  # noqa: E712
                        ) or 0
                        if total != last_indicator_count:
                            last_indicator_count = total
                            yield _sse("indicators", {"count": total})

                        # Latest sync job statuses (last 5 runs)
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

                    # Feed health
                    dep_all = _dep_status.get_all()
                    if dep_all:
                        yield _sse("feed_health", dep_all)

                except Exception as err:
                    yield _sse("error", {"message": str(err)[:200]})

                time.sleep(heartbeat_interval)

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
