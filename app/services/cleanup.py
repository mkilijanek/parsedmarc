from __future__ import annotations

import glob
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sqlalchemy import delete, select

from ..config import Config
from ..db import SessionLocal
from ..models import ExportJob, Indicator

logger = logging.getLogger(__name__)

def cleanup_export_files(max_age_hours: int | None = None) -> int:
    """Delete export job artifacts that have passed their expires_at timestamp."""
    cfg = Config()
    export_dir = cfg.EXPORT_JOB_DIR
    if not os.path.isdir(export_dir):
        return 0

    now = datetime.now(timezone.utc)
    fallback_age_hours = max_age_hours if max_age_hours is not None else cfg.EXPORT_JOB_TTL_HOURS
    deleted = 0

    db = SessionLocal()
    try:
        from sqlalchemy import and_
        expired_jobs = db.scalars(
            select(ExportJob).where(
                and_(
                    ExportJob.expires_at.isnot(None),
                    ExportJob.expires_at < now,
                    ExportJob.result_path.isnot(None),
                )
            )
        ).all()
        for job in expired_jobs:
            p = Path(job.result_path)
            if p.exists():
                try:
                    p.unlink()
                    deleted += 1
                except OSError:
                    logger.warning("cleanup_export_file_failed", extra={"path": str(p)})
    finally:
        db.close()

    cutoff = time.time() - (fallback_age_hours * 3600)
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
