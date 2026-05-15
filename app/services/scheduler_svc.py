"""
scheduler_svc — cron matching, sync-job lifecycle, scheduler loop, and
cache-warming / log-retention / audit-integrity maintenance tasks.

All functions are closures bound to the injected dependencies via
make_scheduler_service(). Nothing in this module imports from factory.py.
"""
from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from ..audit_integrity import verify_audit_chain
from ..cache import get_redis
from ..metrics import (
    export_jobs_pending,
    sync_job_retries_total,
    sync_jobs_queued,
    sync_jobs_running,
)
from ..models import (
    AppLog,
    AuditLog,
    DeadLetterJob,
    ExportJob,
    Feed,
    FeedRun,
    Indicator,
    SyncJob,
)
from ..runtime_env import push_runtime_env_overrides
from .common import sum_update_result


@dataclass(frozen=True)
class SyncJobRef:
    id: int
    job_id: str
    feed_source_id: str
    trigger_type: str


def _aggregate_fetched_count(result_data: Any) -> int:
    return int(sum_update_result(result_data).get("fetched", 0) or 0)


def make_scheduler_service(
    *,
    cfg,
    db_fn,
    app_log_fn,
    audit_fn,
    get_setting_fn,
    set_setting_fn,
    read_feed_rows_fn,
    read_feed_config_state_fn,
    feed_value_key_fn,
    feed_secret_key_fn,
    runtime_override_or_env_fn,
    cache_key_fn,
    scheduler_state: Dict[str, Any],
    scheduler_lock,
):
    """Return a namespace of scheduler-related functions."""

    import logging
    logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------ cron

    def _cron_field_match(value: int, expr: str, *, min_v: int, max_v: int) -> bool:
        expr = expr.strip()
        if expr == "*":
            return True
        if expr.startswith("*/"):
            try:
                step = int(expr[2:])
            except ValueError:
                return False
            return value % step == 0
        for part in expr.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                n = int(part)
            except ValueError:
                return False
            if n == value:
                return True
        return False

    def _cron_matches(expr: str, dt: datetime) -> bool:
        parts = (expr or "").split()
        if len(parts) != 5:
            return False
        minute, hour, day, month, dow = parts
        py_dow = (dt.weekday() + 1) % 7
        return (
            _cron_field_match(dt.minute, minute, min_v=0, max_v=59)
            and _cron_field_match(dt.hour, hour, min_v=0, max_v=23)
            and _cron_field_match(dt.day, day, min_v=1, max_v=31)
            and _cron_field_match(dt.month, month, min_v=1, max_v=12)
            and _cron_field_match(py_dow, dow, min_v=0, max_v=6)
        )

    # ------------------------------------------------------------------ failure classification

    def _classify_sync_failure(exc: Exception) -> str:
        text_ = str(exc).lower()
        permanent_markers = (
            "incomplete config",
            "feed not found",
            "unknown source_type",
            "requires threatfox_auth_key",
            "requires yaraify_auth_key",
            "requires hunting_auth_key",
            "authentication failed",
            "invalid api key",
            "unauthorized",
            "forbidden",
        )
        if any(marker in text_ for marker in permanent_markers):
            return "permanent"
        return "transient"

    def _sync_retry_delay_s(retry_count: int) -> int:
        base = max(1, int(cfg.SYNC_JOB_RETRY_BASE_DELAY_S))
        max_delay = max(base, int(cfg.SYNC_JOB_RETRY_MAX_DELAY_S))
        return min(max_delay, base * (2 ** max(0, retry_count - 1)))

    # ------------------------------------------------------------------ advisory locks

    def _db_try_advisory_lock(db: Session, lock_id: int) -> bool:
        bind = db.get_bind()
        if not bind or bind.dialect.name != "postgresql":
            return True
        ok = db.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}).scalar()
        return bool(ok)

    def _db_advisory_unlock(db: Session, lock_id: int) -> None:
        bind = db.get_bind()
        if bind and bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id})
            db.commit()

    # ------------------------------------------------------------------ sync worker

    def _run_sync_worker_for_feed(feed: Feed) -> Dict[str, Any]:
        from ..adapters import build_feed_registry

        registry = build_feed_registry()
        adapter = registry.get(str(feed.source_type))
        return {"source": feed.source_id, "result": adapter.execute()}

    # ------------------------------------------------------------------ enqueue

    def _enqueue_sync_job(feed: Feed, *, trigger_type: str, db: Session | None = None) -> tuple[SyncJob, bool]:
        own_session = db is None
        db = db or db_fn()
        try:
            existing = db.scalar(
                select(SyncJob)
                .where(SyncJob.feed_source_id == feed.source_id, SyncJob.status.in_(["queued", "running"]))
                .order_by(SyncJob.created_at.desc())
                .limit(1)
            )
            if existing:
                return existing, False
            job = SyncJob(
                job_id=uuid.uuid4().hex,
                feed_source_id=feed.source_id,
                trigger_type=trigger_type,
                idempotency_key=f"{feed.source_id}:{trigger_type}",
                status="queued",
                result_json={},
                max_retries=max(0, int(cfg.SYNC_JOB_MAX_RETRIES)),
            )
            db.add(job)
            db.add(
                AppLog(
                    level="INFO",
                    component="scheduler",
                    message="sync_job_enqueued",
                    feed_source_id=feed.source_id,
                    run_id=job.job_id,
                    metadata_={"trigger": trigger_type},
                )
            )
            db.commit()
            db.refresh(job)
            return job, True
        except Exception:
            db.rollback()
            raise
        finally:
            if own_session:
                db.close()

    # ------------------------------------------------------------------ dequeue

    def _dequeue_next_sync_job() -> SyncJobRef | None:
        db = db_fn()
        try:
            now = datetime.now(timezone.utc)
            stmt = (
                select(SyncJob)
                .where(
                    SyncJob.status == "queued",
                    or_(SyncJob.next_attempt_at.is_(None), SyncJob.next_attempt_at <= now),
                )
                .order_by(SyncJob.created_at.asc())
                .limit(1)
            )
            bind = db.get_bind()
            if bind and bind.dialect.name == "postgresql":
                stmt = stmt.with_for_update(skip_locked=True)
            job = db.scalar(stmt)
            if not job:
                db.rollback()
                return None
            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(job)
            return SyncJobRef(
                id=int(job.id),
                job_id=str(job.job_id),
                feed_source_id=str(job.feed_source_id),
                trigger_type=str(job.trigger_type),
            )
        except Exception:
            db.rollback()
            return None
        finally:
            db.close()

    # ------------------------------------------------------------------ execute

    def _execute_sync_job(job: SyncJobRef) -> Dict[str, Any]:
        run_id = job.job_id
        feed_source_id = str(job.feed_source_id or "")
        scheduler_state["active_job_id"] = job.job_id
        scheduler_state["active_run_id"] = run_id
        updates: Dict[str, str | None] = {}
        db = db_fn()
        try:
            feed = db.scalar(select(Feed).where(Feed.source_id == job.feed_source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                raise RuntimeError(f"feed not found: {job.feed_source_id}")
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
            now = datetime.now(timezone.utc)
            if run is None:
                db.add(FeedRun(feed_source_id=feed.source_id, run_id=run_id, trigger_type=job.trigger_type, status="running", started_at=now))
            else:
                run.status = "running"
                run.error = None
                run.started_at = now
            row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if row:
                row.status = "running"
                row.error = None
                row.failure_class = None
                row.started_at = now
            db.commit()

            app_log_fn("INFO", "scheduler", "feed_sync_started", feed_source_id=feed_source_id, run_id=run_id, metadata={"trigger": job.trigger_type}, db=db)

            state = read_feed_config_state_fn(db, feed)
            if not state["ready"]:
                raise RuntimeError(f"incomplete config: {', '.join(state['missing'])}")
            if feed.base_url:
                updates["BASE_URL"] = feed.base_url
            for f in state["fields"]:
                env_key = str(f.get("env") or "")
                if not env_key:
                    continue
                if f["key"] == "base_url":
                    if feed.base_url:
                        updates[env_key] = feed.base_url
                elif f.get("secret"):
                    updates[env_key] = runtime_override_or_env_fn(
                        db,
                        setting_key=feed_secret_key_fn(feed.source_id, str(f["key"])),
                        env_key=env_key,
                        secret=True,
                    )
                else:
                    updates[env_key] = runtime_override_or_env_fn(
                        db,
                        setting_key=feed_value_key_fn(feed.source_id, str(f["key"])),
                        env_key=env_key,
                        secret=False,
                    )
            if feed.source_type == "mwdb":
                updates["MWDB_ORGANIZATIONS"] = runtime_override_or_env_fn(
                    db,
                    setting_key=feed_value_key_fn(feed.source_id, "organizations"),
                    env_key="MWDB_ORGANIZATIONS",
                    secret=False,
                )
                updates["MWDB_MY_GROUP"] = runtime_override_or_env_fn(
                    db,
                    setting_key=feed_value_key_fn(feed.source_id, "my_group"),
                    env_key="MWDB_MY_GROUP",
                    secret=False,
                )
            if feed.source_type == "malwarebazaar":
                shared_key = runtime_override_or_env_fn(
                    db,
                    setting_key=feed_secret_key_fn("abusech", "api_key"),
                    env_key="ABUSECH_AUTH_KEY",
                    secret=True,
                )
                if shared_key:
                    updates["ABUSECH_AUTH_KEY"] = shared_key

            started = time.time()
            with push_runtime_env_overrides(updates):
                if feed.source_type == "misp":
                    timeout_s = max(1, int(cfg.MISP_SYNC_TIMEOUT_S))
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(_run_sync_worker_for_feed, feed)
                        try:
                            result = future.result(timeout=timeout_s)
                        except FuturesTimeoutError as e:
                            future.cancel()
                            raise TimeoutError(f"MISP sync timeout after {timeout_s}s") from e
                else:
                    result = _run_sync_worker_for_feed(feed)
            result_data = result.get("result")
            fetched_count = _aggregate_fetched_count(result_data)
            dur_ms = int((time.time() - started) * 1000)

            cancel_row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if cancel_row and cancel_row.status == "cancel_requested":
                run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
                if run:
                    run.status = "cancelled"
                    run.error = "cancelled by admin"
                    run.finished_at = datetime.now(timezone.utc)
                cancel_row.status = "cancelled"
                cancel_row.error = "cancelled by admin"
                cancel_row.finished_at = datetime.now(timezone.utc)
                cancel_row.result_json = {"cancelled": True, "duration_ms": dur_ms}
                db.commit()
                app_log_fn(
                    "WARNING",
                    "scheduler",
                    "feed_sync_cancelled",
                    feed_source_id=feed_source_id,
                    run_id=run_id,
                    metadata={"duration_ms": dur_ms},
                    db=db,
                )
                return {"source": feed_source_id, "cancelled": 1}

            run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
            if run:
                run.status = "success"
                run.fetched_count = fetched_count
                run.finished_at = datetime.now(timezone.utc)
            row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if row:
                row.status = "success"
                row.error = None
                row.finished_at = datetime.now(timezone.utc)
                row.result_json = {"fetched_count": fetched_count, "duration_ms": dur_ms}
            db.commit()
            app_log_fn("INFO", "scheduler", "feed_sync_completed", feed_source_id=feed_source_id, run_id=run_id, metadata={"duration_ms": dur_ms, "fetched_count": fetched_count}, db=db)
            return result
        except Exception as e:
            db.rollback()
            elapsed_s = 0
            try:
                elapsed_s = int(time.time() - started)  # type: ignore[name-defined]
            except Exception:
                elapsed_s = 0
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
            if run:
                run.status = "failed"
                run.error = str(e)
                run.finished_at = datetime.now(timezone.utc)
            row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if row:
                failure_class = _classify_sync_failure(e)
                retry_count = int(row.retry_count or 0)
                max_retries = max(0, int(row.max_retries if row.max_retries is not None else cfg.SYNC_JOB_MAX_RETRIES))
                should_retry = failure_class == "transient" and retry_count < max_retries
                row.retry_count = retry_count + 1 if should_retry else retry_count
                row.failure_class = failure_class
                row.error = str(e)
                if should_retry:
                    delay_s = _sync_retry_delay_s(row.retry_count)
                    row.status = "queued"
                    row.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=delay_s)
                    row.finished_at = None
                    row.result_json = {
                        "retry_scheduled": True,
                        "retry_count": row.retry_count,
                        "max_retries": max_retries,
                        "delay_s": delay_s,
                        "failure_class": failure_class,
                    }
                    sync_job_retries_total.labels(source=str(job.feed_source_id), failure_class=failure_class).inc()
                    app_log_fn(
                        "WARNING",
                        "scheduler",
                        "sync_job_retry_scheduled",
                        feed_source_id=job.feed_source_id,
                        run_id=run_id,
                        metadata={
                            "error": str(e),
                            "retry_count": row.retry_count,
                            "max_retries": max_retries,
                            "delay_s": delay_s,
                            "next_attempt_at": str(row.next_attempt_at),
                        },
                        db=db,
                    )
                else:
                    row.status = "failed"
                    row.next_attempt_at = None
                    row.finished_at = datetime.now(timezone.utc)
                    row.result_json = {
                        "retry_scheduled": False,
                        "retry_count": retry_count,
                        "max_retries": max_retries,
                        "failure_class": failure_class,
                    }
                    dlq_entry = DeadLetterJob(
                        original_job_id=job.job_id,
                        feed_source_id=job.feed_source_id,
                        failure_class=failure_class,
                        error=str(e)[:4000],
                        retry_count=retry_count,
                        payload=row.result_json,
                    )
                    db.add(dlq_entry)
                    app_log_fn(
                        "WARNING",
                        "scheduler",
                        "sync_job_dead_lettered",
                        feed_source_id=job.feed_source_id,
                        run_id=run_id,
                        metadata={
                            "original_job_id": job.job_id,
                            "retry_count": retry_count,
                            "failure_class": failure_class,
                        },
                        db=db,
                    )
            if job.feed_source_id == "misp":
                err_text = str(e).lower()
                timeout_hit = ("timeout" in err_text and elapsed_s >= max(1, int(cfg.MISP_SYNC_TIMEOUT_S)))
                connect_hit = ("connection" in err_text or "connect" in err_text)
                if timeout_hit or connect_hit:
                    misp_feed = db.scalar(select(Feed).where(Feed.source_id == "misp", Feed.deleted == False))  # noqa: E712
                    if misp_feed and misp_feed.enabled:
                        misp_feed.enabled = False
                        app_log_fn(
                            "WARNING",
                            "scheduler",
                            "misp_auto_disabled_after_connectivity_failure",
                            feed_source_id="misp",
                            run_id=run_id,
                            metadata={"elapsed_s": elapsed_s, "error": str(e), "timeout_s": int(cfg.MISP_SYNC_TIMEOUT_S)},
                            db=db,
                        )
            db.commit()
            app_log_fn("ERROR", "scheduler", "feed_sync_failed", feed_source_id=job.feed_source_id, run_id=run_id, metadata={"error": str(e)}, db=db)
            return {"source": job.feed_source_id, "error": str(e)}
        finally:
            scheduler_state["active_run_id"] = None
            scheduler_state["active_job_id"] = None
            db.close()

    # ------------------------------------------------------------------ queue processing

    def _run_sync_queue_once(*, max_jobs: int = 10) -> int:
        processed = 0
        while processed < max_jobs:
            job = _dequeue_next_sync_job()
            if not job:
                break
            _execute_sync_job(job)
            processed += 1
        return processed

    # ------------------------------------------------------------------ scheduled enqueue

    def _enqueue_due_scheduled_jobs(now: datetime) -> int:
        minute_marker = now.strftime("%Y-%m-%dT%H:%M")
        enqueued = 0
        db = db_fn()
        try:
            set_setting_fn(db, "scheduler.heartbeat", now.isoformat())
            set_setting_fn(db, "scheduler.default_cron", get_setting_fn(db, "scheduler.default_cron", "*/15 * * * *"))
            db.commit()
            for feed in read_feed_rows_fn(db):
                if not feed.enabled:
                    continue
                if scheduler_state["last_minute"].get(feed.source_id) == minute_marker:
                    continue
                cron_expr = str(feed.schedule_cron or "*/15 * * * *")
                if not _cron_matches(cron_expr, now):
                    continue
                _, created = _enqueue_sync_job(feed, trigger_type="scheduled", db=db)
                scheduler_state["last_minute"][feed.source_id] = minute_marker
                if created:
                    enqueued += 1
            return enqueued
        finally:
            db.close()

    # ------------------------------------------------------------------ maintenance tasks

    def _run_log_retention_if_due(now: datetime) -> None:
        retention_days = int(getattr(cfg, "LOG_RETENTION_DAYS", 90))
        if retention_days <= 0:
            return
        interval_s = 86400  # run at most once per day
        last = scheduler_state.get("last_log_retention_at")
        if isinstance(last, datetime) and (now - last).total_seconds() < interval_s:
            return
        cutoff = now.replace(tzinfo=None) - timedelta(days=retention_days)
        dlq_retention_days = int(getattr(cfg, "DLQ_RETENTION_DAYS", retention_days))
        dlq_cutoff = now.replace(tzinfo=None) - timedelta(days=dlq_retention_days)
        db = db_fn()
        try:
            deleted = db.execute(
                AppLog.__table__.delete().where(AppLog.created_at < cutoff)
            ).rowcount
            dlq_deleted = db.execute(
                DeadLetterJob.__table__.delete().where(
                    (DeadLetterJob.__table__.c.created_at < dlq_cutoff)
                )
            ).rowcount
            db.commit()
        except Exception:
            db.rollback()
            deleted = 0
            dlq_deleted = 0
        finally:
            db.close()
        scheduler_state["last_log_retention_at"] = now
        app_log_fn("INFO", "maintenance", "log_retention_cleanup", metadata={"deleted": deleted, "retention_days": retention_days, "dlq_deleted": dlq_deleted, "dlq_retention_days": dlq_retention_days})

    def _run_cache_warming_if_due(now: datetime) -> None:
        """Pre-populate Redis for the most common read queries on cold start or after TTL expiry."""
        interval_s = max(60, int(cfg.CACHE_TTL) * 2)
        last = scheduler_state.get("last_cache_warming_at")
        if isinstance(last, datetime) and (now - last).total_seconds() < interval_s:
            return
        try:
            r = get_redis()
            if r is None:
                return
            db = db_fn(read_only=True)
            try:
                rows = db.execute(
                    select(Indicator.type, func.count().label("cnt"))
                    .where(Indicator.is_active == True)  # noqa: E712
                    .group_by(Indicator.type)
                    .order_by(func.count().desc())
                    .limit(20)
                ).all()
                warm_payload = {row.type: row.cnt for row in rows}
                ck = cache_key_fn("warm:indicator_type_counts")
                r.setex(ck, max(60, int(cfg.CACHE_TTL)), json.dumps(warm_payload))
                total = db.scalar(select(func.count()).select_from(Indicator).where(Indicator.is_active == True))  # noqa: E712
                r.setex(cache_key_fn("warm:total_active"), max(60, int(cfg.CACHE_TTL)), str(total or 0))
            finally:
                db.close()
            scheduler_state["last_cache_warming_at"] = now
        except Exception as warm_err:
            app_log_fn("WARNING", "scheduler", "cache_warming_error", metadata={"error": str(warm_err)})

    def _run_audit_integrity_check_if_due(now: datetime) -> None:
        interval_s = max(60, int(cfg.AUDIT_INTEGRITY_VERIFY_INTERVAL_S))
        last = scheduler_state.get("last_audit_integrity_check_at")
        if isinstance(last, datetime) and (now - last).total_seconds() < interval_s:
            return
        db = db_fn(read_only=True)
        try:
            rows = list(db.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all())
            result = verify_audit_chain(rows, secret_key=cfg.SECRET_KEY)
        finally:
            db.close()
        scheduler_state["last_audit_integrity_check_at"] = now
        app_log_fn(
            "INFO" if result["valid"] else "ERROR",
            "audit",
            "audit_integrity_verified" if result["valid"] else "audit_integrity_failed",
            metadata=result,
        )

    # ------------------------------------------------------------------ scheduler loop

    def _scheduler_loop() -> None:
        lock_id = 993451
        while True:
            try:
                if scheduler_lock.locked():
                    time.sleep(5)
                    continue
                with scheduler_lock:
                    lock_db = db_fn()
                    have_lock = False
                    try:
                        have_lock = _db_try_advisory_lock(lock_db, lock_id)
                    finally:
                        lock_db.close()
                    if not have_lock:
                        time.sleep(5)
                        continue
                    try:
                        now = datetime.now(timezone.utc)
                        _enqueue_due_scheduled_jobs(now)
                        _run_cache_warming_if_due(now)
                        _run_audit_integrity_check_if_due(now)
                        _run_log_retention_if_due(now)
                        _run_sync_queue_once(max_jobs=10)
                    finally:
                        unlock_db = db_fn()
                        try:
                            _db_advisory_unlock(unlock_db, lock_id)
                        finally:
                            unlock_db.close()
                time.sleep(20)
            except Exception as e:
                app_log_fn("ERROR", "scheduler", "scheduler_loop_error", metadata={"error": str(e)})
                time.sleep(20)

    # ------------------------------------------------------------------ metrics

    def _refresh_job_backlog_metrics() -> None:
        db = db_fn(read_only=True)
        try:
            queued = db.scalar(select(func.count()).select_from(SyncJob).where(SyncJob.status == "queued")) or 0
            running = db.scalar(select(func.count()).select_from(SyncJob).where(SyncJob.status == "running")) or 0
            pending = db.scalar(
                select(func.count()).select_from(ExportJob).where(ExportJob.status.in_(["queued", "running"]))
            ) or 0
            sync_jobs_queued.set(int(queued))
            sync_jobs_running.set(int(running))
            export_jobs_pending.set(int(pending))
        except Exception:
            logger.warning("metrics_job_backlog_refresh_failed", exc_info=True)
        finally:
            db.close()

    # ------------------------------------------------------------------ namespace

    from types import SimpleNamespace

    return SimpleNamespace(
        enqueue_sync_job=_enqueue_sync_job,
        execute_sync_job=_execute_sync_job,
        scheduler_loop=_scheduler_loop,
        refresh_job_backlog_metrics=_refresh_job_backlog_metrics,
        run_sync_queue_once=_run_sync_queue_once,
        enqueue_due_scheduled_jobs=_enqueue_due_scheduled_jobs,
        run_log_retention_if_due=_run_log_retention_if_due,
        run_cache_warming_if_due=_run_cache_warming_if_due,
        run_audit_integrity_check_if_due=_run_audit_integrity_check_if_due,
        db_try_advisory_lock=_db_try_advisory_lock,
        db_advisory_unlock=_db_advisory_unlock,
    )
