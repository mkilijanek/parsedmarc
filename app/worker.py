from __future__ import annotations

import logging
import os
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
from .services.common import configure_requests_tls_verify_from_env
from .db import get_session
from .models import AppSetting

logger = logging.getLogger(__name__)

shutdown_requested = False

def _signal_handler(signum, frame):
    global shutdown_requested
    shutdown_requested = True
    logger.info("shutdown_requested", extra={"signal": signum})

def _safe_job(name: str, fn):
    def _wrap():
        if shutdown_requested:
            logger.info("job_skipped", extra={"job": name, "skipped_reason": "shutdown"})
            return
        t0 = time.monotonic()
        try:
            logger.info("job_start", extra={"job": name})
            fn()
            duration_ms = int((time.monotonic() - t0) * 1000)
            logger.info("job_success", extra={"job": name, "duration_ms": duration_ms})
        except Exception as e:
            duration_ms = int((time.monotonic() - t0) * 1000)
            logger.error("job_failed", extra={"job": name, "error": str(e), "duration_ms": duration_ms}, exc_info=True)
    return _wrap

def _bootstrap_proxy_env_from_settings() -> None:
    db = get_session(read_only=False)
    try:
        keys = {"proxy.http_url", "proxy.https_url", "proxy.no_proxy", "proxy.skip_tls_verify"}
        rows = list(db.scalars(select(AppSetting).where(AppSetting.key.in_(keys))).all())
        settings = {str(r.key): str(r.value or "") for r in rows}
        proxy_http = settings.get("proxy.http_url", "").strip()
        proxy_https = settings.get("proxy.https_url", "").strip()
        proxy_no = settings.get("proxy.no_proxy", "").strip()
        proxy_skip_tls_verify = settings.get("proxy.skip_tls_verify", "").strip()

        if proxy_http:
            os.environ["HTTP_PROXY"] = proxy_http
            os.environ["http_proxy"] = proxy_http
        else:
            os.environ.pop("HTTP_PROXY", None)
            os.environ.pop("http_proxy", None)
        if proxy_https:
            os.environ["HTTPS_PROXY"] = proxy_https
            os.environ["https_proxy"] = proxy_https
        else:
            os.environ.pop("HTTPS_PROXY", None)
            os.environ.pop("https_proxy", None)
        if proxy_no:
            os.environ["NO_PROXY"] = proxy_no
            os.environ["no_proxy"] = proxy_no
        else:
            os.environ.pop("NO_PROXY", None)
            os.environ.pop("no_proxy", None)
        if proxy_skip_tls_verify.lower() in {"1", "true", "yes", "on"}:
            os.environ["REQUESTS_SKIP_TLS_VERIFY"] = "true"
        else:
            os.environ.pop("REQUESTS_SKIP_TLS_VERIFY", None)
        configure_requests_tls_verify_from_env()
    except Exception:
        logger.warning("worker_proxy_bootstrap_failed", exc_info=True)
    finally:
        db.close()

def main():
    cfg = Config()
    setup_logging(cfg.LOG_LEVEL)
    _bootstrap_proxy_env_from_settings()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    if not cfg.ENABLE_BACKGROUND_JOBS:
        logger.warning("background_jobs_disabled")
        while not shutdown_requested:
            time.sleep(1)
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
        schedule.run_pending()
        time.sleep(1)

    schedule.clear()
    logger.info("worker_draining")
    logger.info("worker_exiting")

if __name__ == "__main__":
    main()
