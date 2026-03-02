from __future__ import annotations

import glob
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from sqlalchemy import delete, update

from ..config import Config
from ..db import SessionLocal
from ..models import Indicator

logger = logging.getLogger(__name__)

def cleanup_export_files(max_age_hours: int = 24) -> int:
    """Delete export files older than max_age_hours from EXPORT_JOB_DIR."""
    cfg = Config()
    export_dir = cfg.EXPORT_JOB_DIR
    if not os.path.isdir(export_dir):
        return 0
    cutoff = time.time() - (max_age_hours * 3600)
    deleted = 0
    for path in glob.glob(os.path.join(export_dir, "*")):
        try:
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.unlink(path)
                deleted += 1
        except OSError:
            logger.warning("cleanup_export_file_failed", extra={"path": path})
    logger.info("cleanup_export_files", extra={"deleted": deleted, "dir": export_dir})
    return deleted


def cleanup_old_indicators(days_inactive: int = 90) -> int:
    """Optional maintenance task: hard-delete indicators that have been inactive for N days.

    This is intentionally conservative and only deletes indicators that are:
      - is_active = FALSE
      - last_seen older than cutoff
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_inactive)
    db = SessionLocal()
    try:
        res = db.execute(
            delete(Indicator).where(Indicator.is_active == False, Indicator.last_seen < cutoff)  # noqa: E712
        )
        db.commit()
        deleted = res.rowcount or 0
        logger.info("cleanup_old_indicators", extra={"deleted": deleted, "cutoff": cutoff.isoformat()})
        return deleted
    except Exception:
        db.rollback()
        logger.error("cleanup_failed", exc_info=True)
        raise
    finally:
        db.close()
