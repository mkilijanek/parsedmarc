from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from flask import jsonify, redirect, render_template, request, url_for
from sqlalchemy import select


def register_ops_api_routes(
    app,
    *,
    limiter,
    logger: logging.Logger,
    scheduler_state: Dict[str, Any],
    deps: Dict[str, Any],
) -> None:
    _app_log = deps["_app_log"]
    _apply_feed_filters_and_sort = deps["_apply_feed_filters_and_sort"]
    _audit = deps["_audit"]
    _build_feed_items = deps["_build_feed_items"]
    _db = deps["_db"]
    _enqueue_sync_job = deps["_enqueue_sync_job"]
    _ensure_default_feeds = deps["_ensure_default_feeds"]
    _esc = deps["_esc"]
    _get_setting = deps["_get_setting"]
    _percentile = deps["_percentile"]
    _read_feed_config_state = deps["_read_feed_config_state"]
    _read_feed_rows = deps["_read_feed_rows"]
    _resolve_metrics_window_hours = deps["_resolve_metrics_window_hours"]
    Feed = deps["Feed"]
    FeedRun = deps["FeedRun"]
    AppLog = deps["AppLog"]
    SyncJob = deps["SyncJob"]

    @app.post("/admin/sync")
    @limiter.limit("10 per minute")
    def admin_sync():
        source_name = (request.form.get("source") or "").strip().lower()
        if not source_name:
            return redirect(url_for("admin_panel", msg="Missing source for sync."))
        db = _db()
        try:
            _app_log("INFO", "scheduler", "manual_sync_requested", metadata={"source": source_name}, db=db)
            _ensure_default_feeds(db)
            feed_rows = _read_feed_rows(db)
            feed_map = {f.source_id: f for f in feed_rows}
            targets: List[Feed] = []
            if source_name == "all":
                targets = [f for f in feed_rows if f.enabled]
            elif source_name not in feed_map:
                return redirect(url_for("admin_panel", msg="Invalid source for sync."))
            else:
                targets = [feed_map[source_name]]

            blocked: List[str] = []
            queued: List[str] = []
            reused: List[str] = []
            for feed in targets:
                state = _read_feed_config_state(db, feed)
                if not state["ready"]:
                    blocked.append(f"{feed.source_id} (missing: {', '.join(state['missing'])})")
                    continue
                job, created = _enqueue_sync_job(feed, trigger_type="manual", db=db)
                if created:
                    queued.append(job.job_id)
                else:
                    reused.append(job.job_id)

            if source_name != "all" and not queued and not reused:
                return redirect(url_for("admin_panel", msg=f"Cannot sync {source_name}: configuration incomplete."))

            _audit("manual_sync", "feed", None, {"source": source_name, "queued": queued, "reused": reused, "blocked": blocked}, db=db)
            _app_log(
                "INFO",
                "scheduler",
                "manual_sync_queued",
                metadata={"source": source_name, "queued": queued, "reused": reused, "blocked": blocked},
                db=db,
            )
            msg = f"Sync queued for {source_name}."
            if queued:
                msg += f" New jobs: {', '.join(queued)}."
            if reused:
                msg += f" Already queued/running: {', '.join(reused)}."
            if blocked:
                msg += f" Skipped incomplete feeds: {', '.join(blocked)}."
            return redirect(url_for("admin_panel", msg=msg))
        except Exception as e:
            logger.exception("admin_sync_failed")
            _app_log("ERROR", "scheduler", "manual_sync_failed", metadata={"source": source_name, "error": str(e)}, db=db)
            return redirect(url_for("admin_panel", msg=f"Sync failed: {e}"))
        finally:
            db.close()

    @app.get("/admin/sync-jobs/<job_id>")
    @limiter.limit("30 per minute")
    def admin_sync_job_details(job_id: str):
        job_id = (job_id or "").strip()
        if not job_id:
            return redirect(url_for("admin_panel", msg="Missing job_id."))
        db = _db(read_only=True)
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Sync job not found: {job_id}"))
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == job_id))
            logs = list(db.scalars(select(AppLog).where(AppLog.run_id == job_id).order_by(AppLog.created_at.desc()).limit(200)).all())
        finally:
            db.close()

        log_rows = "".join(
            [
                (
                    "<tr>"
                    f"<td>{_esc(str(item.created_at))}</td>"
                    f"<td>{_esc(item.level)}</td>"
                    f"<td>{_esc(item.component)}</td>"
                    f"<td>{_esc(item.message)}</td>"
                    f"<td><code>{_esc(json.dumps(item.metadata_ or {}, ensure_ascii=True))}</code></td>"
                    "</tr>"
                )
                for item in logs
            ]
        ) or "<tr><td colspan='5'>No logs for this job.</td></tr>"

        return render_template(
            "admin/sync_job_details.html",
            job_id=job_id,
            job=job,
            job_result_json=_esc(json.dumps(job.result_json or {}, ensure_ascii=True)),
            run_status=_esc(str(getattr(run, "status", "n/a"))),
            run_fetched=_esc(str(getattr(run, "fetched_count", "n/a"))),
            log_rows=log_rows,
        )

    @app.post("/admin/sync-jobs/<job_id>/retry")
    @limiter.limit("20 per minute")
    def admin_sync_job_retry(job_id: str):
        job_id = (job_id or "").strip()
        db = _db()
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Retry failed: job not found ({job_id})."))
            if str(job.status or "").lower() not in {"failed", "cancelled"}:
                return redirect(url_for("admin_panel", msg=f"Retry allowed only for failed/cancelled jobs (current: {job.status})."))
            feed = db.scalar(select(Feed).where(Feed.source_id == job.feed_source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg=f"Retry failed: feed not found ({job.feed_source_id})."))
            state = _read_feed_config_state(db, feed)
            if not state["ready"]:
                return redirect(url_for("admin_panel", msg=f"Retry blocked: configuration incomplete for {feed.source_id}."))
            new_job, created = _enqueue_sync_job(feed, trigger_type="retry", db=db)
            feed_source_id = str(feed.source_id)
            prior_job_id = str(job.job_id)
            queued_job_id = str(new_job.job_id)
            _audit(
                "admin_sync_job_retry",
                "sync_job",
                int(getattr(job, "id", 0) or 0) or None,
                {
                    "source": feed_source_id,
                    "job_id": prior_job_id,
                    "new_job_id": queued_job_id,
                    "created": created,
                },
                db=db,
            )
            return redirect(url_for("admin_panel", msg=f"Retry {'queued' if created else 'reused existing'} for {feed_source_id} (job_id={queued_job_id})."))
        except Exception as e:
            logger.exception("admin_sync_job_retry_failed")
            return redirect(url_for("admin_panel", msg=f"Retry failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/sync-jobs/<job_id>/cancel")
    @limiter.limit("20 per minute")
    def admin_sync_job_cancel(job_id: str):
        job_id = (job_id or "").strip()
        db = _db()
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Cancel failed: job not found ({job_id})."))
            status = str(job.status or "").lower()
            if status in {"success", "failed", "cancelled"}:
                return redirect(url_for("admin_panel", msg=f"Cancel ignored: job already {status}."))
            now = datetime.now(timezone.utc)
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == job.job_id))
            if status == "queued":
                cancelled_job_id = str(job.job_id)
                cancelled_source = str(job.feed_source_id)
                job.status = "cancelled"
                job.error = "cancelled by admin"
                job.finished_at = now
                job.result_json = {"cancelled": True}
                if run:
                    run.status = "cancelled"
                    run.error = "cancelled by admin"
                    run.finished_at = now
                db.commit()
                _audit(
                    "admin_sync_job_cancel",
                    "sync_job",
                    int(getattr(job, "id", 0) or 0) or None,
                    {"job_id": cancelled_job_id, "status": "cancelled", "source": cancelled_source},
                    db=db,
                )
                return redirect(url_for("admin_panel", msg=f"Job {cancelled_job_id} cancelled."))
            requested_job_id = str(job.job_id)
            requested_source = str(job.feed_source_id)
            job.status = "cancel_requested"
            if not job.error:
                job.error = "cancel requested by admin"
            if run and run.status == "running":
                run.error = "cancel requested by admin"
            db.commit()
            _audit(
                "admin_sync_job_cancel",
                "sync_job",
                int(getattr(job, "id", 0) or 0) or None,
                {"job_id": requested_job_id, "status": "cancel_requested", "source": requested_source},
                db=db,
            )
            return redirect(url_for("admin_panel", msg=f"Cancellation requested for running job {requested_job_id}."))
        except Exception as e:
            db.rollback()
            logger.exception("admin_sync_job_cancel_failed")
            return redirect(url_for("admin_panel", msg=f"Cancel failed: {e}"))
        finally:
            db.close()

    @app.post("/api/sync")
    @limiter.limit("20 per minute")
    def api_sync():
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
                job, created = _enqueue_sync_job(feed, trigger_type="manual", db=db)
                queued.append({"feed_source_id": feed.source_id, "job_id": job.job_id, "created": created})

            if source_name != "all" and not queued:
                return jsonify({"error": "Configuration incomplete", "source": source_name, "blocked": blocked}), 400
            return jsonify({"source": source_name, "jobs": queued, "blocked": blocked}), 202
        finally:
            db.close()

    @app.get("/api/feeds")
    @limiter.limit("60 per minute")
    def api_feeds():
        def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(request.args.get(name, str(default)))
            except ValueError:
                value = default
            return max(minimum, min(maximum, value))

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

    @app.get("/api/feeds/metrics")
    @limiter.limit("60 per minute")
    def api_feeds_metrics():
        hours, window = _resolve_metrics_window_hours()
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
                            "logs_url": f"/api/logs?run_id={run.run_id}&limit=200",
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

    @app.get("/api/runs/current")
    @limiter.limit("60 per minute")
    def api_runs_current():
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
                        }
                        for j in queued_jobs
                    ],
                    "running": [{"feed_source_id": r.feed_source_id, "run_id": r.run_id, "status": r.status, "started_at": str(r.started_at)} for r in running],
                    "latest": [
                        {
                            "feed_source_id": r.feed_source_id,
                            "run_id": r.run_id,
                            "status": r.status,
                            "started_at": str(r.started_at),
                            "finished_at": str(r.finished_at),
                            "error": r.error,
                            "fetched_count": r.fetched_count,
                        }
                        for r in latest
                    ],
                }
            )
        finally:
            db.close()
