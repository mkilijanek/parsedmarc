from __future__ import annotations

import json
import logging

from ..cache import get_redis
from ..config import Config
from ..db import SessionLocal
from .correlation import query_correlations

logger = logging.getLogger(__name__)


def _cache_key(prefix: str, **parts) -> str:
    segs = [prefix] + [f"{k}={parts[k]}" for k in sorted(parts.keys())]
    return "|".join(segs)


def refresh_correlation_snapshots() -> None:
    cfg = Config()
    if not cfg.CORRELATION_SNAPSHOT_ENABLED:
        return

    raw_types = [t.strip().lower() for t in cfg.CORRELATION_SNAPSHOT_TYPES.split(",") if t.strip()]
    types = [t for t in raw_types if t in {"all", "ip", "domain", "url", "hash", "email", "object_id"}]
    if not types:
        types = ["all"]

    limit = max(1, min(cfg.CORRELATION_SNAPSHOT_LIMIT, cfg.CORRELATION_LIMIT_MAX))
    min_sources = max(2, cfg.CORRELATION_SNAPSHOT_MIN_SOURCES)
    ttl = max(1, cfg.CORRELATION_CACHE_TTL)

    db = SessionLocal()
    try:
        r = get_redis()
        for ioc_type in types:
            groups = query_correlations(
                db,
                min_sources=min_sources,
                limit=limit,
                ioc_type=ioc_type,
            )
            payload = {
                "count": len(groups),
                "min_sources": min_sources,
                "type": ioc_type,
                "limit": limit,
                "items": groups,
            }
            key = _cache_key(
                "correlations",
                min_sources=min_sources,
                limit=limit,
                type=ioc_type,
            )
            r.setex(key, ttl, json.dumps(payload, separators=(",", ":")))
        logger.info(
            "correlation_snapshot_refreshed",
            extra={"types": types, "limit": limit, "min_sources": min_sources, "ttl": ttl},
        )
    except Exception:
        logger.exception("correlation_snapshot_refresh_failed")
    finally:
        db.close()
