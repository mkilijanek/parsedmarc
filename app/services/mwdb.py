from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

import requests
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..config import Config
from ..db import SessionLocal
from ..metrics import quality_normalized_total, quality_dropped_invalid_total, quality_dedup_merged_total
from ..models import FeedStats, Indicator
from .quality import canonicalize_row, dedup_rows

logger = logging.getLogger(__name__)

def _parse_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    # MWDB typically returns ISO 8601 timestamps
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _normalize_obj_tags(raw_tags: Any) -> List[str]:
    if not raw_tags:
        return []
    if isinstance(raw_tags, str):
        return [t.strip() for t in raw_tags.split(",") if t.strip()]
    if isinstance(raw_tags, dict):
        vals: List[str] = []
        for v in raw_tags.values():
            if isinstance(v, dict):
                tag = v.get("tag")
                if isinstance(tag, str) and tag.strip():
                    vals.append(tag.strip())
            elif isinstance(v, str) and v.strip():
                vals.append(v.strip())
        return vals
    if isinstance(raw_tags, list):
        vals: List[str] = []
        for v in raw_tags:
            if isinstance(v, str) and v.strip():
                vals.append(v.strip())
            elif isinstance(v, dict):
                tag = v.get("tag")
                if isinstance(tag, str) and tag.strip():
                    vals.append(tag.strip())
        return vals
    return []


def _escape_lucene_value(value: str) -> str:
    # Minimal escaping for quoted Lucene term.
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _tag_term(tag: str) -> str:
    t = (tag or "").strip()
    if not t:
        return ""
    # Tags like feed:vx require quotes in Lucene query.
    if ":" in t or " " in t:
        return f'tag:"{_escape_lucene_value(t)}"'
    return f"tag:{_escape_lucene_value(t)}"


def _build_tag_query(tags: List[str]) -> str:
    terms = [_tag_term(t) for t in tags if (t or "").strip()]
    if not terms:
        raise ValueError("At least one non-empty tag is required")
    if len(terms) == 1:
        return terms[0]
    return "(" + " OR ".join(terms) + ")"

def fetch_mwdb_by_tags(
    *,
    base_url: str,
    auth_key: str,
    tags: List[str],
    since: Optional[datetime],
    until: Optional[datetime],
    limit: int = 1000,
    timeout_s: int = 30,
    chunk_size: int = 200,
) -> Iterator[Dict[str, Any]]:
    """
    MWDB: uses GET /api/object with query=Lucene syntax.
    Auth: Authorization: Bearer <auth_key> (JWT token).

    Query strategy:
      - build lucene: (tag:tag1 OR tag:tag2 OR ...)
      - fetch recent objects in pages using older_than
      - post-filter by time range if upload_time present
      - stop when limit reached (best-effort)

    Returns rows in internal ingestion format.
    """
    if not base_url:
        raise ValueError("MWDB_URL is required for data-source mwdb")
    if not auth_key:
        raise ValueError("MWDB_AUTH_KEY is required for data-source mwdb")

    base_url = base_url.rstrip("/")
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {auth_key}"})

    # lucene tag query
    q = _build_tag_query(tags)

    older_than = None
    yielded = 0
    while True:
        params = {"query": q, "count": str(min(chunk_size, 1000))}
        if older_than:
            params["older_than"] = older_than

        r = session.get(f"{base_url}/api/object", params=params, timeout=timeout_s)
        r.raise_for_status()
        data = r.json()  # expected key: "objects"
        objs = data.get("objects") or data.get("files") or []
        if not objs:
            return

        for obj in objs:
            # Determine an IOC value - prefer sha256 if present
            sha256 = obj.get("sha256") or obj.get("sha256_hash") or obj.get("checksum") or None
            ioc_value = sha256 or obj.get("id") or obj.get("uuid")
            if not ioc_value:
                continue

            # time filtering
            ts = obj.get("upload_time") or obj.get("first_seen") or obj.get("created_at") or ""
            dt = _parse_dt(ts) or datetime.now(tz=timezone.utc)
            if since and dt < since:
                continue
            if until and dt > until:
                continue

            obj_tags = _normalize_obj_tags(obj.get("tags"))

            # merge tags
            all_tags=[]
            seen=set()
            for t in list(tags) + list(obj_tags):
                if not t:
                    continue
                k=t.lower()
                if k in seen: 
                    continue
                seen.add(k)
                all_tags.append(t)

            metadata = dict(obj)

            yield {
                "ioc_value": str(ioc_value),
                "ioc_type": "hash" if sha256 else "object_id",
                "source": "mwdb",
                "source_ref": str(obj.get("id") or ioc_value),
                "first_seen": dt,
                "last_seen": dt,
                "confidence": 60,
                "tlp": "GREEN",
                "is_active": True,
                "tags": all_tags,
                "comments": "MWDB tag query",
                "metadata": metadata,
            }
            yielded += 1
            if yielded >= limit:
                return

            older_than = obj.get("id") or older_than

        # if we didn't update older_than, break to avoid infinite loop
        if not older_than:
            return


def _parse_tag_list(raw: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for val in (raw or "").split(","):
        tag = val.strip()
        if not tag:
            continue
        key = tag.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(tag)
    return out


def update_mwdb_indicators() -> Dict[str, int]:
    cfg = Config()
    now = datetime.now(timezone.utc)
    tags = _parse_tag_list(cfg.MWDB_TAGS)
    if not tags:
        logger.info("mwdb_skipped_no_tags")
        return {"fetched": 0, "deactivated": 0}

    raw_rows = list(
        fetch_mwdb_by_tags(
            base_url=cfg.MWDB_URL,
            auth_key=cfg.MWDB_AUTH_KEY,
            tags=tags,
            since=None,
            until=None,
            limit=max(1, int(cfg.MWDB_LIMIT)),
        )
    )
    canonical_rows: List[Dict[str, Any]] = []
    for r in raw_rows:
        normalized, reason = canonicalize_row(r, source="mwdb")
        if normalized is None:
            quality_dropped_invalid_total.labels(source="mwdb", reason=(reason or "invalid")).inc()
            continue
        canonical_rows.append(normalized)
    rows, merged = dedup_rows(canonical_rows)
    quality_normalized_total.labels(source="mwdb").inc(len(rows))
    if merged:
        quality_dedup_merged_total.labels(source="mwdb").inc(merged)

    incoming = {r["ioc_value"] for r in rows if r.get("ioc_value")}
    incoming_types = {str(r.get("ioc_type") or "") for r in rows if r.get("ioc_type")}
    db = SessionLocal()
    try:
        existing = db.query(Indicator.id, Indicator.value).filter(Indicator.source == "mwdb").all()
        existing_map = {value: ind_id for (ind_id, value) in existing}
        to_deactivate = [existing_map[v] for v in existing_map.keys() if v not in incoming]
        if to_deactivate:
            db.query(Indicator).filter(Indicator.id.in_(to_deactivate)).update(  # type: ignore[arg-type]
                {"is_active": False, "last_seen": now}, synchronize_session=False
            )

        related_sources_map: Dict[tuple[str, str], set[str]] = {}
        if incoming and incoming_types:
            related_rows = (
                db.query(Indicator.value, Indicator.type, Indicator.source)
                .filter(Indicator.value.in_(list(incoming)))
                .filter(Indicator.type.in_(list(incoming_types)))
                .all()
            )
            for value, ioc_type, rel_source in related_rows:
                related_sources_map.setdefault((str(value), str(ioc_type)), set()).add(str(rel_source))

        for item in rows:
            value = str(item.get("ioc_value") or "").strip()
            if not value:
                continue
            ioc_type = str(item.get("ioc_type") or "hash")
            metadata_obj = dict(item.get("metadata") or {})
            rel_sources = set(related_sources_map.get((value, ioc_type), set()))
            rel_sources.add("mwdb")
            metadata_obj["related_sources"] = sorted(rel_sources)
            stmt = pg_insert(Indicator.__table__).values(
                value=value,
                type=ioc_type,
                source="mwdb",
                source_id=str(item.get("source_ref") or value),
                first_seen=item.get("first_seen") or now,
                last_seen=item.get("last_seen") or now,
                confidence=int(item.get("confidence") or 60),
                tlp=str(item.get("tlp") or "GREEN"),
                is_active=True,
                metadata={"mwdb": metadata_obj},
                tags=list(item.get("tags") or []),
            ).on_conflict_do_update(
                index_elements=["value", "source", "source_id"],
                set_={
                    "last_seen": item.get("last_seen") or now,
                    "is_active": True,
                    "confidence": int(item.get("confidence") or 60),
                    "tlp": str(item.get("tlp") or "GREEN"),
                    "metadata": {"mwdb": metadata_obj},
                    "tags": list(item.get("tags") or []),
                },
            )
            db.execute(stmt)

        db.execute(
            pg_insert(FeedStats.__table__).values(
                source="mwdb",
                source_id=None,
                last_update=now,
                last_fetch_status="success",
                last_fetch_error=None,
                metadata={"fetched": len(rows), "tags": tags},
            ).on_conflict_do_update(
                index_elements=["source", "source_id"],
                set_={
                    "last_update": now,
                    "last_fetch_status": "success",
                    "last_fetch_error": None,
                    "metadata": {"fetched": len(rows), "tags": tags},
                },
            )
        )
        db.commit()
        logger.info("mwdb_updated", extra={"fetched": len(rows), "tags": len(tags)})
        return {"fetched": len(rows), "deactivated": len(to_deactivate)}
    except Exception as e:
        db.rollback()
        try:
            db.execute(
                pg_insert(FeedStats.__table__).values(
                    source="mwdb",
                    source_id=None,
                    last_update=now,
                    last_fetch_status="error",
                    last_fetch_error=str(e),
                    metadata={},
                ).on_conflict_do_update(
                    index_elements=["source", "source_id"],
                    set_={
                        "last_update": now,
                        "last_fetch_status": "error",
                        "last_fetch_error": str(e),
                    },
                )
            )
            db.commit()
        except Exception:
            db.rollback()
        raise
    finally:
        db.close()
