from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Set

from pymisp import PyMISP
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..config import Config
from ..db import SessionLocal
from ..models import Indicator, FeedStats
from .common import retry_with_backoff

logger = logging.getLogger(__name__)

TYPE_MAPPING = {
    'ip-src': 'ip', 'ip-dst': 'ip', 'ip-src|port': 'ip', 'ip-dst|port': 'ip',
    'domain': 'domain', 'hostname': 'domain',
    'url': 'url',
    'md5': 'hash', 'sha1': 'hash', 'sha256': 'hash', 'sha512': 'hash', 'ssdeep': 'hash',
    'email': 'email', 'email-src': 'email', 'email-dst': 'email', 'email-subject': 'email'
}

HIGH_CONF_TAGS = {'apt','malware','ransomware','banker','apt28','apt29'}

def extract_tlp_from_tags(attr_tags: List[str] | None, event_tags: List[str] | None) -> str:
    # Priority: attribute tags -> event tags -> default GREEN
    def _scan(tags: List[str] | None) -> Optional[str]:
        if not tags:
            return None
        for t in tags:
            tl = t.strip().lower()
            if tl.startswith("tlp:"):
                val = tl.split(":",1)[1].strip()
                # Support TLP 2.0 clear=white
                if val == "clear":
                    return "WHITE"
                val = val.upper()
                if val in {"WHITE","GREEN","AMBER","RED"}:
                    return val
        return None

    r = _scan(attr_tags) or _scan(event_tags)
    return r or "GREEN"

def compute_confidence(distribution: int, tags: List[str]) -> int:
    base = 70
    if distribution == 0: base = 90
    elif distribution == 1: base = 80
    elif distribution == 2: base = 70
    elif distribution == 3: base = 60
    elif distribution == 4: base = 50

    tags_l = [t.lower() for t in (tags or [])]
    if any(t in tags_l for t in HIGH_CONF_TAGS):
        base = min(95, base + 10)
    return int(base)

def _init_misp(cfg: Config) -> PyMISP:
    if not cfg.MISP_URL or not cfg.MISP_API_KEY:
        raise RuntimeError("MISP_URL/MISP_API_KEY not set")
    return PyMISP(cfg.MISP_URL, cfg.MISP_API_KEY, ssl=cfg.MISP_VERIFY_SSL)

def _fetch_misp_attributes(cfg: Config) -> List[dict]:
    misp = _init_misp(cfg)
    since = datetime.now(timezone.utc) - timedelta(days=cfg.MISP_DAYS)

    def _do():
        # search returns dict with Attribute entries
        res = misp.search(
            controller="attributes",
            timestamp=since.strftime("%Y-%m-%d"),
            to_ids=True,
            enforce_warninglist=True,
            includeEventTags=True,
            includeAttributeTags=True,
            pythonify=False,
        )
        # Normalize possible output shapes
        if isinstance(res, dict) and "Attribute" in res:
            return res["Attribute"]
        if isinstance(res, list):
            return res
        return []
    return retry_with_backoff(_do)

def _normalize_value(attr_type: str, value: str) -> Tuple[str, dict]:
    meta = {"raw": value}
    if "|" in attr_type:
        # ip-src|port etc: take first part for IOC, keep raw in metadata
        parts = value.split("|", 1)
        meta["compound_raw"] = value
        return parts[0].strip(), meta
    return value.strip(), meta

def update_misp_indicators() -> Dict[str, int]:
    cfg = Config()
    now = datetime.now(timezone.utc)
    attrs = _fetch_misp_attributes(cfg)

    # Track active per event (source_id = event_id)
    # We mark inactive attributes that disappeared from the last window per event.
    db = SessionLocal()
    try:
        # Group incoming by event id
        incoming_by_event: Dict[str, Set[str]] = {}
        inserted = 0
        updated = 0

        for a in attrs:
            a_type = a.get("type")
            mapped = TYPE_MAPPING.get(a_type)
            if not mapped:
                continue
            value_raw = a.get("value") or ""
            value_norm, meta_extra = _normalize_value(a_type, value_raw)
            if not value_norm:
                continue

            event_id = str(a.get("event_id") or a.get("Event", {}).get("id") or "").strip()
            if not event_id:
                # Fallback to attribute's event id is required for traceability
                continue

            attr_tags = [t.get("name") for t in (a.get("Tag") or []) if isinstance(t, dict) and t.get("name")]  # type: ignore
            event_tags = []
            ev = a.get("Event") or {}
            if isinstance(ev, dict):
                event_tags = [t.get("name") for t in (ev.get("Tag") or []) if isinstance(t, dict) and t.get("name")]  # type: ignore

            tlp = extract_tlp_from_tags(attr_tags, event_tags)
            distribution = int(ev.get("distribution") if isinstance(ev, dict) and ev.get("distribution") is not None else 3)
            tags = list({t for t in (attr_tags or []) + (event_tags or []) if t})
            confidence = compute_confidence(distribution, tags)

            incoming_by_event.setdefault(event_id, set()).add(value_norm)

            stmt = pg_insert(Indicator.__table__).values(
                value=value_norm,
                type=mapped,
                source="misp",
                source_id=event_id,
                first_seen=now,
                last_seen=now,
                confidence=confidence,
                tlp=tlp,
                is_active=True,
                metadata={
                    "misp": {
                        "attribute_id": a.get("id"),
                        "event_id": event_id,
                        "type": a_type,
                        "category": a.get("category"),
                        "comment": a.get("comment"),
                        "timestamp": a.get("timestamp"),
                        "distribution": distribution,
                        **meta_extra,
                    }
                },
                tags=tags,
            ).on_conflict_do_update(
                index_elements=["value","source","source_id"],
                set_={
                    "last_seen": now,
                    "is_active": True,
                    "confidence": confidence,
                    "tlp": tlp,
                    "tags": tags,
                    "metadata": {
                        "misp": {
                            "attribute_id": a.get("id"),
                            "event_id": event_id,
                            "type": a_type,
                            "category": a.get("category"),
                            "comment": a.get("comment"),
                            "timestamp": a.get("timestamp"),
                            "distribution": distribution,
                            **meta_extra,
                        }
                    },
                }
            )
            db.execute(stmt)

        # Deactivate missing per event
        for event_id, incoming_values in incoming_by_event.items():
            existing = db.execute(
                select(Indicator.id, Indicator.value).where(
                    Indicator.source == "misp",
                    Indicator.source_id == event_id,
                )
            ).all()
            existing_map = {v: i for (i, v) in existing}
            to_deactivate = [existing_map[v] for v in existing_map.keys() if v not in incoming_values]
            if to_deactivate:
                db.execute(
                    update(Indicator)
                    .where(Indicator.id.in_(to_deactivate))
                    .values(is_active=False, last_seen=now)
                )

        db.commit()

        # Update feed_stats for MISP global (source_id null)
        db.execute(
            pg_insert(FeedStats.__table__).values(
                source="misp",
                source_id=None,
                last_update=now,
                last_fetch_status="success",
                last_fetch_error=None,
                metadata={"fetched": len(attrs), "days": cfg.MISP_DAYS},
            ).on_conflict_do_update(
                index_elements=["source","source_id"],
                set_={
                    "last_update": now,
                    "last_fetch_status": "success",
                    "last_fetch_error": None,
                    "metadata": {"fetched": len(attrs), "days": cfg.MISP_DAYS},
                }
            )
        )
        db.commit()

        logger.info("misp_updated", extra={"fetched": len(attrs), "events": len(incoming_by_event)})
        return {"fetched": len(attrs), "events": len(incoming_by_event)}
    except Exception as e:
        db.rollback()
        try:
            db.execute(
                pg_insert(FeedStats.__table__).values(
                    source="misp",
                    source_id=None,
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
        logger.error("misp_update_failed", extra={"error": str(e)}, exc_info=True)
        raise
    finally:
        db.close()
