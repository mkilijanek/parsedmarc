from __future__ import annotations

import logging
import os
import signal
import time
import schedule

from .config import Config
from .logging import setup_logging
from .services.crowdsec import update_all_crowdsec_lists
from .services.misp import update_misp_indicators
from .services.cleanup import cleanup_old_indicators

logger = logging.getLogger(__name__)

shutdown_requested = False

def _signal_handler(signum, frame):
    global shutdown_requested
    shutdown_requested = True
    logger.info("shutdown_requested", extra={"signal": signum})

def _safe_job(name: str, fn):
    def _wrap():
        try:
            logger.info("job_start", extra={"job": name})
            fn()
            logger.info("job_success", extra={"job": name})
        except Exception as e:
            logger.error("job_failed", extra={"job": name, "error": str(e)}, exc_info=True)
    return _wrap

def main():
    cfg = Config()
    setup_logging(cfg.LOG_LEVEL)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    if not cfg.ENABLE_BACKGROUND_JOBS:
        logger.warning("background_jobs_disabled")
        while not shutdown_requested:
            time.sleep(1)
        return

    interval = max(30, int(cfg.UPDATE_INTERVAL))

    schedule.every(interval).seconds.do(_safe_job("crowdsec_update", update_all_crowdsec_lists))
    schedule.every(interval).seconds.do(_safe_job("misp_update", update_misp_indicators))
    schedule.every().day.at("02:00").do(_safe_job("cleanup", cleanup_old_indicators))

    logger.info("worker_started", extra={"update_interval_s": interval})

    while not shutdown_requested:
        schedule.run_pending()
        time.sleep(1)

    logger.info("worker_exiting")

if __name__ == "__main__":
    main()
