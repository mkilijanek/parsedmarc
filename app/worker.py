from __future__ import annotations

import logging
import signal
import time
import schedule
from sqlalchemy import select

from .config import Config
from .logging import setup_logging
from .services.crowdsec import update_all_crowdsec_lists
from .services.misp import update_misp_indicators
from .services.malwarebazaar import update_malwarebazaar_indicators
from .services.mwdb import update_mwdb_indicators
from .services.abusech import update_abusech_indicators
from .services.cleanup import cleanup_old_indicators, cleanup_export_files
from .services.correlation_snapshot import refresh_correlation_snapshots
from .services.deps import dep_health_refresh
from .db import SessionLocal, engine, get_session
from .models import AppSetting
from .runtime_env import update_proxy_settings_from_mapping
from .worker_health import (
    WorkerHealthServer,
    active_jobs,
    mark_job_failure,
    mark_job_start,
    mark_job_success,
    mark_loop,
    mark_shutdown_requested,
)

logger = logging.getLogger(__name__)

shutdown_requested = False

def _signal_handler(signum, frame):
    global shutdown_requested
    shutdown_requested = True
    mark_shutdown_requested()
    logger.info("shutdown_requested", extra={"signal": signum})

def _safe_job(name: str, fn):
    def _wrap():
        if shutdown_requested:
            logger.info("job_skipped", extra={"job": name, "skipped_reason": "shutdown"})
            return
        t0 = time.monotonic()
        try:
            logger.info("job_start", extra={"job": name})
            mark_job_start(name)
            fn()
            duration_ms = int((time.monotonic() - t0) * 1000)
            mark_job_success(name)
            logger.info("job_success", extra={"job": name, "duration_ms": duration_ms})
        except Exception as e:
            duration_ms = int((time.monotonic() - t0) * 1000)
            mark_job_failure(name, str(e))
            logger.error("job_failed", extra={"job": name, "error": str(e), "duration_ms": duration_ms}, exc_info=True)
    return _wrap

def _refresh_proxy_settings() -> None:
    db = get_session(read_only=False)
    try:
        keys = {"proxy.http_url", "proxy.https_url", "proxy.no_proxy", "proxy.ca_bundle_path", "proxy.skip_tls_verify"}
        rows = list(db.scalars(select(AppSetting).where(AppSetting.key.in_(keys))).all())
        settings = {str(r.key): str(r.value or "") for r in rows}
        update_proxy_settings_from_mapping(settings)
    except Exception:
        logger.warning("worker_proxy_bootstrap_failed", exc_info=True)
    finally:
        db.close()

def main():
    cfg = Config()
    setup_logging(cfg.LOG_LEVEL)
    _refresh_proxy_settings()
    health_server = WorkerHealthServer(
        cfg.WORKER_HEALTH_HOST,
        cfg.WORKER_HEALTH_PORT,
        cfg.WORKER_HEALTH_MAX_LOOP_AGE_S,
    )
    health_server.start()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    if not cfg.ENABLE_BACKGROUND_JOBS:
        logger.warning("background_jobs_disabled")
        while not shutdown_requested:
            mark_loop()
            time.sleep(1)
        health_server.stop()
        return

    interval = max(30, int(cfg.UPDATE_INTERVAL))
    dep_health_interval = max(10, int(cfg.DEP_HEALTH_INTERVAL_S))

    # Dependency health probes run on a short interval, independently of feed syncs
    schedule.every(dep_health_interval).seconds.do(_safe_job("dep_health_refresh", dep_health_refresh))
    _safe_job("dep_health_refresh_startup", dep_health_refresh)()

    schedule.every(interval).seconds.do(_safe_job("crowdsec_update", update_all_crowdsec_lists))
    schedule.every(interval).seconds.do(_safe_job("misp_update", update_misp_indicators))
    schedule.every(interval).seconds.do(_safe_job("malwarebazaar_update", update_malwarebazaar_indicators))
    schedule.every(interval).seconds.do(_safe_job("mwdb_update", update_mwdb_indicators))
    schedule.every(interval).seconds.do(_safe_job("abusech_update", update_abusech_indicators))
    schedule.every().day.at("02:00").do(_safe_job("cleanup", cleanup_old_indicators))
    schedule.every().day.at("03:00").do(_safe_job("cleanup_export_files", cleanup_export_files))
    if cfg.CORRELATION_SNAPSHOT_ENABLED:
        snapshot_interval = max(30, int(cfg.CORRELATION_SNAPSHOT_INTERVAL))
        schedule.every(snapshot_interval).seconds.do(
            _safe_job("correlation_snapshot_refresh", refresh_correlation_snapshots)
        )
        _safe_job("correlation_snapshot_refresh_startup", refresh_correlation_snapshots)()

    logger.info("worker_started", extra={"update_interval_s": interval})

    while not shutdown_requested:
        mark_loop()
        schedule.run_pending()
        time.sleep(1)

    schedule.clear()
    logger.info("worker_draining", extra={"grace_s": cfg.WORKER_SHUTDOWN_GRACE_S})
    deadline = time.monotonic() + max(0, int(cfg.WORKER_SHUTDOWN_GRACE_S))
    while active_jobs() > 0 and time.monotonic() < deadline:
        time.sleep(0.25)
    if active_jobs() > 0:
        logger.warning("worker_shutdown_grace_exhausted", extra={"active_jobs": active_jobs()})
    SessionLocal.remove()
    engine.dispose()
    health_server.stop()
    logger.info("worker_exiting")

if __name__ == "__main__":
    main()
