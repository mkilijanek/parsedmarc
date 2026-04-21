from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from flask import Response, jsonify, request, send_from_directory
from sqlalchemy import select
from swagger_ui_bundle import swagger_ui_path

from ..openapi_spec import build_openapi_spec, render_openapi_yaml

_LEGACY_TO_V1 = {
    "/api/feeds": "/api/v1/feeds",
    "/api/feeds/metrics": "/api/v1/feeds/metrics",
    "/api/logs": "/api/v1/logs",
    "/api/runs/current": "/api/v1/runs/current",
    "/api/sync": "/api/v1/sync",
}


def _openapi_yaml_path() -> Path:
    return Path(__file__).resolve().parents[1] / "static" / "openapi-v1.yaml"


def _swagger_ui_asset_path() -> Path:
    return Path(swagger_ui_path)


def register_api_v1_routes(
    app,
    *,
    limiter,
    cfg,
    logger: logging.Logger,
    scheduler_state: Dict[str, Any],
    deps: Dict[str, Any],
) -> None:
    _apply_feed_filters_and_sort = deps["_apply_feed_filters_and_sort"]
    _build_feed_items = deps["_build_feed_items"]
    _count_indicators = deps["_count_indicators"]
    _db = deps["_db"]
    _enqueue_sync_job = deps["_enqueue_sync_job"]
    _ensure_default_feeds = deps["_ensure_default_feeds"]
    _get_setting = deps["_get_setting"]
    _parse_limit_offset = deps["_parse_limit_offset"]
    _percentile = deps["_percentile"]
    _query_indicators = deps["_query_indicators"]
    _read_feed_config_state = deps["_read_feed_config_state"]
    _read_feed_rows = deps["_read_feed_rows"]
    _resolve_metrics_window_hours = deps["_resolve_metrics_window_hours"]
    validate_search_query = deps["validate_search_query"]
    AppLog = deps["AppLog"]
    FeedRun = deps["FeedRun"]
    SyncJob = deps["SyncJob"]

    @app.after_request
    def _append_legacy_api_deprecation_headers(response: Response) -> Response:
        successor = _LEGACY_TO_V1.get(request.path)
        if successor:
            response.headers.setdefault("Deprecation", "true")
            response.headers.setdefault("Sunset", "Wed, 31 Dec 2026 23:59:59 GMT")
            response.headers.setdefault("Link", f"<{successor}>; rel=\"successor-version\"")
        return response

    def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(request.args.get(name, str(default)))
        except ValueError:
            value = default
        return max(minimum, min(maximum, value))

    @app.get("/api/v1/openapi.yaml")
    @limiter.limit("30 per minute")
    def api_v1_openapi_yaml():
        return Response(render_openapi_yaml(), mimetype="application/yaml")

    @app.get("/api/v1/openapi.json")
    @limiter.limit("30 per minute")
    def api_v1_openapi_json():
        return jsonify(build_openapi_spec())

    @app.get("/api/v1/docs")
    @limiter.limit("30 per minute")
    def api_v1_docs():
        return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>IOC Service API v1</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; max-width: 60rem; }
    code, pre { background: #f3f4f6; padding: .2rem .35rem; border-radius: 4px; }
    pre { padding: 1rem; overflow: auto; }
  </style>
</head>
<body>
  <h1>IOC Service API v1</h1>
  <p>This is the supported versioned API surface introduced in milestone <code>1.6.0</code>.</p>
  <ul>
    <li><a href="/api/v1/openapi.yaml">OpenAPI YAML</a></li>
    <li><a href="/api/v1/openapi.json">OpenAPI JSON summary</a></li>
    <li><a href="/docs/api.md">Human-readable API documentation</a></li>
  </ul>
  <p>Legacy <code>/api/*</code> routes remain available additively during migration and may return deprecation headers when a versioned successor exists.</p>
</body>
</html>"""

    @app.get("/api/swagger")
    @limiter.limit("30 per minute")
    def api_swagger_ui():
        return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>IOC Service Swagger UI</title>
  <link rel="stylesheet" href="/api/swagger-assets/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/api/swagger-assets/swagger-ui-bundle.js"></script>
  <script src="/api/swagger-assets/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        url: "/api/v1/openapi.yaml",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>"""

    @app.get("/api/swagger-assets/<path:filename>")
    @limiter.limit("60 per minute")
    def api_swagger_assets(filename: str):
        return send_from_directory(str(_swagger_ui_asset_path()), filename)

    @app.get("/api/v1/indicators")
    @limiter.limit("60 per minute")
    def api_v1_indicators():
        q = request.args.get("q", "").strip() or None
        if q and not validate_search_query(q):
            return jsonify({"error": "Invalid query"}), 400

        type_filter = (request.args.get("type") or "all").lower()
        tlp = (request.args.get("tlp") or "all").upper()
        source = (request.args.get("source") or "all").lower()
        try:
            raw_min_conf = request.args.get("min_conf")
            raw_max_conf = request.args.get("max_conf")
            min_conf = request.args.get("min_conf", type=int)
            max_conf = request.args.get("max_conf", type=int)
            if raw_min_conf is not None and raw_min_conf.strip() != "" and min_conf is None:
                raise ValueError("min_conf")
            if raw_max_conf is not None and raw_max_conf.strip() != "" and max_conf is None:
                raise ValueError("max_conf")
        except ValueError:
            return jsonify({"error": "min_conf/max_conf must be integers"}), 400
        limit, offset = _parse_limit_offset(default_limit=100, max_limit=max(1, cfg.QUERY_RESULT_LIMIT_MAX))
        if limit is None or offset is None:
            return jsonify({"error": "limit/offset must be integers"}), 400

        db = _db(read_only=True)
        try:
            rows = _query_indicators(db, q, type_filter, tlp, source, min_conf, max_conf, limit=limit, offset=offset)
            total_count = _count_indicators(db, q, type_filter, tlp, source, min_conf, max_conf)
        finally:
            db.close()

        return jsonify(
            {
                "count": len(rows),
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "filters": {
                    "q": q,
                    "type": type_filter,
                    "tlp": tlp,
                    "source": source,
                    "min_conf": min_conf,
                    "max_conf": max_conf,
                },
                "items": [
                    {
                        "id": row.id,
                        "uuid": str(row.uuid),
                        "value": row.value,
                        "type": row.type,
                        "source": row.source,
                        "source_id": row.source_id,
                        "confidence": row.confidence,
                        "tlp": row.tlp,
                        "is_active": bool(row.is_active),
                        "tags": list(row.tags or []),
                        "metadata": row.metadata_ or {},
                        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
                    }
                    for row in rows
                ],
            }
        )

    @app.post("/api/v1/sync")
    @limiter.limit("10 per minute")
    def api_v1_sync():
        payload = request.get_json(silent=True) or {}
        source_name = str(payload.get("source") or request.args.get("source") or "").strip().lower()
        if not source_name:
            return jsonify({"error": "Missing source"}), 400
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed_rows = _read_feed_rows(db)
            feed_map = {f.source_id: f for f in feed_rows}
            if source_name == "all":
                targets = [f for f in feed_rows if f.enabled]
            elif source_name in feed_map:
                targets = [feed_map[source_name]]
            else:
                return jsonify({"error": "Invalid source"}), 400

            blocked: List[str] = []
            queued: List[Dict[str, Any]] = []
            for feed in targets:
                state = _read_feed_config_state(db, feed)
                if not state["ready"]:
                    blocked.append(feed.source_id)
                    continue
                job, created = _enqueue_sync_job(feed, trigger_type="api_v1", db=db)
                queued.append({"feed_source_id": feed.source_id, "job_id": job.job_id, "created": created})

            if source_name != "all" and not queued:
                return jsonify({"error": "Configuration incomplete", "source": source_name, "blocked": blocked}), 400
            return jsonify({"source": source_name, "jobs": queued, "blocked": blocked}), 202
        finally:
            db.close()

    @app.get("/api/v1/feeds")
    @limiter.limit("100 per minute")
    def api_v1_feeds():
        limit = _int_arg("limit", 25, 1, 100)
        offset = _int_arg("offset", 0, 0, 1000000)
        sort_by = (request.args.get("sort", "source") or "source").strip().lower()
        sort_order = (request.args.get("order", "asc") or "asc").strip().lower()
        status_filter = (request.args.get("status", "all") or "all").strip().upper()
        datasource = (request.args.get("datasource", "all") or "all").strip().lower()
        configured = (request.args.get("configured", "all") or "all").strip().lower()
        query_text = (request.args.get("q", "") or "").strip()
        problems_only = (request.args.get("problems_only", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}

        db = _db(read_only=True)
        try:
            all_items = _build_feed_items(db)
            filtered = _apply_feed_filters_and_sort(
                all_items,
                status_filter=status_filter,
                datasource=datasource,
                configured=configured,
                query_text=query_text,
                problems_only=problems_only,
                sort_by=sort_by,
                sort_order=sort_order,
            )
            total = len(filtered)
            if offset >= total and total > 0:
                offset = max(0, ((total - 1) // max(1, limit)) * max(1, limit))
            page = filtered[offset : offset + limit]
            return jsonify(
                {
                    "items": [
                        {
                            **item,
                            "last_run_at": item["last_run_at"].isoformat() if isinstance(item.get("last_run_at"), datetime) else None,
                            "last_error_at": item["last_error_at"].isoformat() if isinstance(item.get("last_error_at"), datetime) else None,
                        }
                        for item in page
                    ],
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "sort": sort_by,
                    "order": sort_order,
                    "filters": {
                        "status": status_filter,
                        "datasource": datasource,
                        "configured": configured,
                        "q": query_text,
                        "problems_only": problems_only,
                    },
                }
            )
        finally:
            db.close()

    @app.get("/api/v1/feeds/metrics")
    @limiter.limit("100 per minute")
    def api_v1_feeds_metrics():
        hours, window = _resolve_metrics_window_hours(request.args)
        datasource = (request.args.get("datasource") or "all").strip().lower()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        bucket_granularity = "hour" if hours <= 24 else "day"

        db = _db(read_only=True)
        try:
            feed_items = _build_feed_items(db)
            if datasource not in {"", "all"}:
                feed_items = [item for item in feed_items if str(item.get("source_type", "")).lower() == datasource]

            source_ids = [str(item["source_id"]) for item in feed_items]
            if not source_ids:
                return jsonify({"window": window, "hours": hours, "bucket": bucket_granularity, "datasource": datasource, "total_feeds": 0, "items": [], "timeseries": [], "summary": {}})

            runs = list(
                db.scalars(
                    select(FeedRun)
                    .where(FeedRun.feed_source_id.in_(source_ids), FeedRun.started_at >= cutoff)
                    .order_by(FeedRun.feed_source_id.asc(), FeedRun.started_at.asc())
                ).all()
            )
            by_feed: Dict[str, List[FeedRun]] = {sid: [] for sid in source_ids}
            for run in runs:
                by_feed.setdefault(str(run.feed_source_id), []).append(run)

            metric_items: List[Dict[str, Any]] = []
            aggregate_runs = 0
            aggregate_success = 0
            aggregate_errors = 0
            aggregate_fetched = 0
            aggregate_duration_total_ms = 0
            aggregate_duration_count = 0
            all_durations: List[int] = []
            all_buckets: Dict[str, Dict[str, Any]] = {}

            def _bucket_key(ts: datetime) -> str:
                if bucket_granularity == "hour":
                    return ts.replace(minute=0, second=0, microsecond=0).isoformat()
                return ts.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

            for item in feed_items:
                sid = str(item["source_id"])
                feed_runs = by_feed.get(sid, [])
                total_runs = len(feed_runs)
                success_runs = 0
                error_runs = 0
                total_fetched = 0
                duration_ms_total = 0
                duration_ms_count = 0
                durations: List[int] = []
                run_points: List[Dict[str, Any]] = []
                for run in feed_runs:
                    status = str(run.status or "").lower()
                    if status == "success":
                        success_runs += 1
                    if status in {"failed", "cancelled"}:
                        error_runs += 1
                    total_fetched += int(run.fetched_count or 0)
                    duration_ms = None
                    if run.finished_at is not None and run.started_at is not None:
                        duration_ms = max(0, int((run.finished_at - run.started_at).total_seconds() * 1000))
                        duration_ms_total += duration_ms
                        duration_ms_count += 1
                        durations.append(duration_ms)
                        all_durations.append(duration_ms)
                    if run.started_at is not None:
                        bk = _bucket_key(run.started_at)
                        point = all_buckets.setdefault(
                            bk,
                            {"ts": bk, "runs": 0, "success_runs": 0, "error_runs": 0, "fetched_total": 0, "duration_ms_total": 0, "duration_ms_count": 0},
                        )
                        point["runs"] += 1
                        if status == "success":
                            point["success_runs"] += 1
                        if status in {"failed", "cancelled"}:
                            point["error_runs"] += 1
                        point["fetched_total"] += int(run.fetched_count or 0)
                        if duration_ms is not None:
                            point["duration_ms_total"] += int(duration_ms)
                            point["duration_ms_count"] += 1
                    run_points.append(
                        {
                            "run_id": run.run_id,
                            "status": run.status,
                            "started_at": run.started_at.isoformat() if run.started_at else None,
                            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                            "fetched_count": int(run.fetched_count or 0),
                            "duration_ms": duration_ms,
                            "details_url": f"/admin/sync-jobs/{run.run_id}",
                            "logs_url": f"/api/v1/logs?run_id={run.run_id}&limit=200",
                        }
                    )
                availability = round((success_runs / total_runs) * 100, 2) if total_runs else None
                error_rate = round((error_runs / total_runs) * 100, 2) if total_runs else None
                avg_duration_ms = round(duration_ms_total / duration_ms_count, 2) if duration_ms_count else None
                avg_fetched = round(total_fetched / total_runs, 2) if total_runs else None

                aggregate_runs += total_runs
                aggregate_success += success_runs
                aggregate_errors += error_runs
                aggregate_fetched += total_fetched
                aggregate_duration_total_ms += duration_ms_total
                aggregate_duration_count += duration_ms_count

                metric_items.append(
                    {
                        "source_id": sid,
                        "display_name": item["display_name"],
                        "source_type": item["source_type"],
                        "status": item["status"],
                        "runs": total_runs,
                        "success_runs": success_runs,
                        "error_runs": error_runs,
                        "availability_pct": availability,
                        "error_rate_pct": error_rate,
                        "fetched_total": total_fetched,
                        "fetched_avg_per_run": avg_fetched,
                        "duration_avg_ms": avg_duration_ms,
                        "duration_p50_ms": _percentile(durations, 50.0),
                        "duration_p95_ms": _percentile(durations, 95.0),
                        "window_hours": hours,
                        "runs_timeseries": run_points[-200:],
                    }
                )

            timeseries = []
            for ts in sorted(all_buckets.keys()):
                bucket = all_buckets[ts]
                timeseries.append(
                    {
                        "ts": ts,
                        "runs": int(bucket["runs"]),
                        "success_runs": int(bucket["success_runs"]),
                        "error_runs": int(bucket["error_runs"]),
                        "fetched_total": int(bucket["fetched_total"]),
                        "duration_avg_ms": (round(float(bucket["duration_ms_total"]) / float(bucket["duration_ms_count"]), 2) if int(bucket["duration_ms_count"]) > 0 else None),
                    }
                )

            summary = {
                "runs_total": aggregate_runs,
                "availability_pct": round((aggregate_success / aggregate_runs) * 100, 2) if aggregate_runs else None,
                "error_rate_pct": round((aggregate_errors / aggregate_runs) * 100, 2) if aggregate_runs else None,
                "fetched_total": aggregate_fetched,
                "fetched_avg_per_run": round((aggregate_fetched / aggregate_runs), 2) if aggregate_runs else None,
                "duration_avg_ms": round((aggregate_duration_total_ms / aggregate_duration_count), 2) if aggregate_duration_count else None,
                "duration_p50_ms": _percentile(all_durations, 50.0),
                "duration_p95_ms": _percentile(all_durations, 95.0),
            }
            return jsonify({"window": window, "hours": hours, "bucket": bucket_granularity, "datasource": datasource, "total_feeds": len(metric_items), "items": metric_items, "timeseries": timeseries, "summary": summary})
        finally:
            db.close()

    @app.get("/api/v1/runs/current")
    @limiter.limit("100 per minute")
    def api_v1_runs_current():
        db = _db(read_only=True)
        try:
            running = list(db.scalars(select(FeedRun).where(FeedRun.status == "running").order_by(FeedRun.started_at.desc()).limit(20)).all())
            latest = list(db.scalars(select(FeedRun).order_by(FeedRun.started_at.desc()).limit(20)).all())
            queued_jobs = list(db.scalars(select(SyncJob).where(SyncJob.status.in_(["queued", "running"])).order_by(SyncJob.created_at.asc()).limit(50)).all())
            heartbeat = _get_setting(db, "scheduler.heartbeat", "")
            return jsonify(
                {
                    "scheduler_heartbeat": heartbeat,
                    "active_run_id": scheduler_state.get("active_run_id"),
                    "active_job_id": scheduler_state.get("active_job_id"),
                    "queued_jobs": [
                        {
                            "job_id": j.job_id,
                            "feed_source_id": j.feed_source_id,
                            "status": j.status,
                            "trigger_type": j.trigger_type,
                            "created_at": str(j.created_at),
                            "started_at": str(j.started_at),
                            "finished_at": str(j.finished_at),
                        }
                        for j in queued_jobs
                    ],
                    "running": [
                        {
                            "run_id": run.run_id,
                            "feed_source_id": run.feed_source_id,
                            "status": run.status,
                            "started_at": str(run.started_at),
                            "finished_at": str(run.finished_at),
                            "fetched_count": int(run.fetched_count or 0),
                        }
                        for run in running
                    ],
                    "latest": [
                        {
                            "run_id": run.run_id,
                            "feed_source_id": run.feed_source_id,
                            "status": run.status,
                            "started_at": str(run.started_at),
                            "finished_at": str(run.finished_at),
                            "fetched_count": int(run.fetched_count or 0),
                        }
                        for run in latest
                    ],
                }
            )
        finally:
            db.close()

    @app.get("/api/v1/logs")
    @limiter.limit("60 per minute")
    def api_v1_logs():
        db = _db(read_only=True)
        try:
            stmt = select(AppLog).order_by(AppLog.created_at.desc())
            feed = (request.args.get("feed") or "").strip()
            job_id = (request.args.get("job_id") or request.args.get("run_id") or "").strip()
            level = (request.args.get("level") or "").strip().upper()
            component = (request.args.get("component") or "").strip()
            since = (request.args.get("since") or "").strip()
            until = (request.args.get("until") or "").strip()
            if feed:
                stmt = stmt.where(AppLog.feed_source_id == feed)
            if job_id:
                stmt = stmt.where(AppLog.run_id == job_id)
            if level:
                stmt = stmt.where(AppLog.level == level)
            if component:
                stmt = stmt.where(AppLog.component == component)
            if since:
                try:
                    stmt = stmt.where(AppLog.created_at >= datetime.fromisoformat(since.replace("Z", "+00:00")))
                except ValueError:
                    pass
            if until:
                try:
                    stmt = stmt.where(AppLog.created_at <= datetime.fromisoformat(until.replace("Z", "+00:00")))
                except ValueError:
                    pass
            limit = min(500, max(1, int(request.args.get("limit", "200"))))
            rows = list(db.scalars(stmt.limit(limit)).all())
            return jsonify(
                {
                    "count": len(rows),
                    "items": [
                        {
                            "created_at": str(r.created_at),
                            "level": r.level,
                            "component": r.component,
                            "message": r.message,
                            "feed_source_id": r.feed_source_id,
                            "run_id": r.run_id,
                            "metadata": r.metadata_,
                        }
                        for r in rows
                    ],
                }
            )
        finally:
            db.close()
