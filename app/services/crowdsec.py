from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Set
from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..config import Config
from ..db import SessionLocal
from ..models import Indicator, FeedStats
from .common import build_feed_session, retry_with_backoff, throttle_external_request, standardized_update_result

logger = logging.getLogger(__name__)

CROWDSEC_BASE = "https://api.crowdsec.net/v2/blocklists/{list_id}"
DEFAULT_TLP = "AMBER"  # hard requirement

def _fetch_list(api_key: str, list_id: str, *, timeout_s: int, retry_attempts: int, retry_base_delay_s: float) -> List[str]:
    url = CROWDSEC_BASE.format(list_id=list_id)

    def _do():
        with build_feed_session(source="crowdsec") as session:
            throttle_external_request(source="crowdsec")
            resp = session.get(url, headers={"X-Api-Key": api_key}, timeout=max(1, timeout_s))
            resp.raise_for_status()
            lines = [ln.strip() for ln in resp.text.splitlines()]
            return [ln for ln in lines if ln and not ln.startswith("#")]
    return retry_with_backoff(
        _do,
        max_attempts=max(1, retry_attempts),
        base_delay=max(0.1, retry_base_delay_s),
    )

def update_crowdsec_list(list_id: str) -> Dict[str, int]:
    cfg = Config()
    if not cfg.CROWDSEC_API_KEY:
        raise RuntimeError("CROWDSEC_API_KEY not set")
    now = datetime.now(timezone.utc)

    indicators_raw = _fetch_list(
        cfg.CROWDSEC_API_KEY,
        list_id,
        timeout_s=cfg.FEED_HTTP_TIMEOUT_S,
        retry_attempts=cfg.FEED_RETRY_ATTEMPTS,
        retry_base_delay_s=cfg.FEED_RETRY_BASE_DELAY_S,
    )

    # Normalize by preserving CIDR if present
    incoming: Set[str] = set(indicators_raw)

    db = SessionLocal()
    try:
        # Deactivate missing indicators via a single SQL UPDATE (avoids loading all rows to Python)
        if incoming:
            db.execute(
                update(Indicator)
                .where(
                    Indicator.source == "crowdsec",
                    Indicator.source_id == list_id,
                    Indicator.is_active == True,  # noqa: E712
                    ~Indicator.value.in_(list(incoming)),
                )
                .values(is_active=False, last_seen=now)
            )
        else:
            db.execute(
                update(Indicator)
                .where(
                    Indicator.source == "crowdsec",
                    Indicator.source_id == list_id,
                    Indicator.is_active == True,  # noqa: E712
                )
                .values(is_active=False, last_seen=now)
            )

        for val in incoming:
            stmt = pg_insert(Indicator.__table__).values(
                value=val,
                type="ip",
                source="crowdsec",
                source_id=list_id,
                first_seen=now,
                last_seen=now,
                confidence=75,
                tlp=DEFAULT_TLP,
                is_active=True,
                metadata={"raw": val, "list_id": list_id},
                tags=[],
            ).on_conflict_do_update(
                index_elements=["value","source","source_id"],
                set_={
                    "last_seen": now,
                    "is_active": True,
                    "confidence": 75,
                    "tlp": DEFAULT_TLP,
                    "metadata": {"raw": val, "list_id": list_id},
                }
            )
            db.execute(stmt)
        db.commit()

        # Update feed_stats fetch status
        db.execute(
            pg_insert(FeedStats.__table__).values(
                source="crowdsec",
                source_id=list_id,
                last_update=now,
                last_fetch_status="success",
                last_fetch_error=None,
                metadata={"fetched": len(incoming)},
            ).on_conflict_do_update(
                index_elements=["source","source_id"],
                set_={
                    "last_update": now,
                    "last_fetch_status": "success",
                    "last_fetch_error": None,
                    "metadata": {"fetched": len(incoming)},
                }
            )
        )
        db.commit()

        return standardized_update_result(
            fetched=len(incoming),
            deactivated=0,
            errors=0,
            details={"list_id": list_id},
        )
    except Exception as e:
        db.rollback()
        try:
            db.execute(
                pg_insert(FeedStats.__table__).values(
                    source="crowdsec",
                    source_id=list_id,
                    last_update=now,
                    last_fetch_status="error",
                    last_fetch_error=str(e),
                    metadata={},
                ).on_conflict_do_update(
                    index_elements=["source","source_id"],
                    set_={
                        "last_update": now,
                        "last_fetch_status": "error",
                        "last_fetch_error": str(e),
                    }
                )
            )
            db.commit()
        except Exception:
            db.rollback()
        raise
    finally:
        db.close()

def update_all_crowdsec_lists() -> Dict[str, Dict[str, int]]:
    cfg = Config()
    lists = [x.strip() for x in (cfg.CROWDSEC_LISTS or "").split(",") if x.strip()]
    results: Dict[str, Dict[str, int]] = {}
    for lid in lists:
        t0 = datetime.now(timezone.utc)
        try:
            res = update_crowdsec_list(lid)
            dur = (datetime.now(timezone.utc) - t0).total_seconds() * 1000
            logger.info("crowdsec_list_updated", extra={"list_id": lid, "duration_ms": int(dur), **res})
            results[lid] = res
        except Exception as e:
            logger.error("crowdsec_list_update_failed", extra={"list_id": lid, "error": str(e)}, exc_info=True)
            results[lid] = standardized_update_result(fetched=0, deactivated=0, errors=1, details={"list_id": lid, "error": str(e)})
    return results


def update_crowdsec_indicators() -> Dict[str, int]:
    """Compatibility wrapper used by scheduler.

    Returns a standardized aggregate shape with per-list details.
    """
    per_list = update_all_crowdsec_lists()
    fetched = 0
    deactivated = 0
    errors = 0
    for value in per_list.values():
        fetched += int(value.get("fetched", 0) or 0)
        deactivated += int(value.get("deactivated", 0) or 0)
        errors += int(value.get("errors", 0) or 0)
    return standardized_update_result(
        fetched=fetched,
        deactivated=deactivated,
        errors=errors,
        details={"lists": per_list},
    )
