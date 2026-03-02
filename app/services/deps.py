"""Periodic dependency health refresh.

Runs lightweight probes for each configured external dependency and writes
results to the shared DepStatusCache so that /deps is always fresh,
independently of feed sync job outcomes.
"""
from __future__ import annotations

import logging

from ..config import Config

logger = logging.getLogger(__name__)


def dep_health_refresh() -> None:
    """Probe all configured external dependencies and update DepStatusCache.

    Designed to run as a short-interval background job (DEP_HEALTH_INTERVAL_S,
    default 60 s). Each probe uses its own bounded timeout and never raises —
    failures are recorded in the cache as ``status=down``.
    """
    cfg = Config()

    from .common import _dep_status

    # MISP
    if cfg.MISP_URL and cfg.MISP_API_KEY:
        try:
            from .misp import misp_health_check
            result = misp_health_check(cfg)
            # misp_health_check already writes to _dep_status; we read the result
            # here for logging only (avoids double-write in the happy path).
            logger.debug(
                "dep_health_refresh_misp",
                extra={"status": result.get("status"), "duration_ms": result.get("duration_ms")},
            )
            # Ensure _dep_status is updated even when misp_health_check is mocked in tests
            status = result.get("status") or "unknown"
            if status not in ("ok", "down", "degraded", "unknown"):
                status = "unknown"
            _dep_status.update(
                "misp",
                status,
                error=result.get("error"),
                duration_ms=result.get("duration_ms"),
            )
        except Exception as exc:
            _dep_status.update("misp", "down", error=str(exc))
            logger.warning("dep_health_refresh_misp_error", extra={"error": str(exc)})
    else:
        _dep_status.update("misp", "down", error="not_configured", duration_ms=0)
