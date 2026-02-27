from __future__ import annotations

import logging
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional

import requests
from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..config import Config
from ..db import SessionLocal
from ..metrics import quality_normalized_total, quality_dropped_invalid_total, quality_dedup_merged_total
from ..models import FeedStats, Indicator
from .common import throttle_external_request, retry_with_backoff, _circuit_breaker
from .quality import canonicalize_row, dedup_rows

logger = logging.getLogger(__name__)


def fetch_mwdb_organizations(*, base_url: str, auth_key: str, timeout_s: int = 10) -> List[Dict[str, str]]:
    if not base_url:
        raise ValueError("MWDB_URL is required for data-source mwdb")
    if not auth_key:
        raise ValueError("MWDB_AUTH_KEY is required for data-source mwdb")
    base_url = base_url.rstrip("/")
    endpoints = ["/api/organization", "/api/user/organizations", "/api/user"]
    found: List[Dict[str, str]] = []
    seen = set()
    with requests.Session() as session:
        session.headers.update({"Authorization": f"Bearer {auth_key}"})
        for path in endpoints:
            try:
                throttle_external_request(source="mwdb")
                resp = session.get(f"{base_url}{path}", params={"count": "200"}, timeout=timeout_s)
                if resp.status_code >= 400:
                    continue
                data = resp.json() if resp.content else {}
                rows: List[Any] = []
                if isinstance(data, list):
                    rows = data
                elif isinstance(data, dict):
                    if isinstance(data.get("organizations"), list):
                        rows = data.get("organizations") or []
                    elif isinstance(data.get("items"), list):
                        rows = data.get("items") or []
                    elif isinstance(data.get("results"), list):
                        rows = data.get("results") or []
                    elif isinstance(data.get("data"), list):
                        rows = data.get("data") or []
                for item in rows:
                    if not isinstance(item, dict):
                        continue
                    org_id = str(item.get("id") or item.get("identifier") or item.get("name") or "").strip()
                    org_name = str(item.get("name") or item.get("login") or org_id).strip()
                    if not org_id:
                        continue
                    key = org_id.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append({"id": org_id, "name": org_name})
            except Exception:
                continue
    return found


def test_mwdb_connection(*, base_url: str, auth_key: str, timeout_s: int = 10) -> Dict[str, Any]:
    if not base_url:
        raise ValueError("MWDB URL is required")
    if not auth_key:
        raise ValueError("MWDB auth key is required")
    base_url = base_url.rstrip("/")
    with requests.Session() as session:
        session.headers.update({"Authorization": f"Bearer {auth_key}"})
        throttle_external_request(source="mwdb")
        resp = session.get(f"{base_url}/api/object", params={"count": "1"}, timeout=timeout_s)
        resp.raise_for_status()
    orgs = fetch_mwdb_organizations(base_url=base_url, auth_key=auth_key, timeout_s=timeout_s)
    return {"ok": True, "organizations": orgs}

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


def _build_object_query(tags: List[str], custom_filter: str) -> str:
    extra = (custom_filter or "").strip()
    tag_query = _build_tag_query(tags) if tags else ""
    if tag_query and extra:
        return f"({tag_query}) AND ({extra})"
    if tag_query:
        return tag_query
    if not extra:
        return ""
    return extra


def _parse_org_list(raw: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for val in (raw or "").split(","):
        item = val.strip()
        if not item:
            continue
        k = item.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(item)
    return out


def _object_matches_organizations(obj: Dict[str, Any], organizations: List[str]) -> bool:
    if not organizations:
        return True
    accepted = {x.strip().lower() for x in organizations if x.strip()}
    if not accepted:
        return True
    candidates: List[str] = []
    for key in ("organization", "org", "uploader", "author", "owner"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            candidates.append(val.strip())
    uploaders = obj.get("uploaders")
    if isinstance(uploaders, list):
        for it in uploaders:
            if isinstance(it, str) and it.strip():
                candidates.append(it.strip())
            elif isinstance(it, dict):
                for key in ("organization", "org", "name", "login", "id"):
                    val = it.get(key)
                    if isinstance(val, str) and val.strip():
                        candidates.append(val.strip())
    return any(c.lower() in accepted for c in candidates)

def _object_matches_group(obj: Dict[str, Any], group: str) -> bool:
    """Return True when the object's uploaders include the specified group name."""
    if not group:
        return False
    g_lower = group.strip().lower()
    if not g_lower:
        return False
    uploaders = obj.get("uploaders") or []
    if isinstance(uploaders, list):
        for u in uploaders:
            if isinstance(u, str) and u.strip().lower() == g_lower:
                return True
            if isinstance(u, dict):
                for key in ("group", "organization", "name", "login", "id"):
                    val = u.get(key)
                    if isinstance(val, str) and val.strip().lower() == g_lower:
                        return True
    # Also check top-level organization field
    for key in ("organization", "org", "group"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip().lower() == g_lower:
            return True
    return False


def fetch_mwdb_by_tags(
    *,
    base_url: str,
    auth_key: str,
    tags: List[str],
    custom_filter: str = "",
    mode: str = "tags",
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    organizations: Optional[List[str]] = None,
    my_group: Optional[str] = None,
    limit: int = 1000,
    timeout_s: int = 30,
    retry_attempts: int = 4,
    retry_base_delay_s: float = 1.0,
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

    # lucene tag/custom query
    q = _build_object_query(tags, custom_filter)
    q_hash = hashlib.sha256(q.encode("utf-8")).hexdigest()[:12] if q else "none"

    older_than = None
    yielded = 0
    with requests.Session() as session:
        session.headers.update({"Authorization": f"Bearer {auth_key}"})
        while True:
            params = {"count": str(min(chunk_size, 1000))}
            if q:
                params["query"] = q
            if older_than:
                params["older_than"] = older_than
            logger.info(
                "mwdb_fetch_page",
                extra={
                    "mode": mode,
                    "count": params.get("count"),
                    "older_than": params.get("older_than"),
                    "query_hash": q_hash,
                    "query_len": len(q or ""),
                },
            )

            def _do():
                throttle_external_request(source="mwdb")
                resp = session.get(f"{base_url}/api/object", params=params, timeout=timeout_s)
                resp.raise_for_status()
                return resp.json()
            data = retry_with_backoff(
                _do,
                max_attempts=max(1, retry_attempts),
                base_delay=max(0.1, retry_base_delay_s),
            )
            objs = data.get("objects") or data.get("files") or []
            logger.info("mwdb_fetch_page_result", extra={"mode": mode, "response_items": len(objs)})
            if not objs:
                logger.info("mwdb_stop_reason", extra={"mode": mode, "reason": "no_results"})
                return

            page_older_than = older_than
            for obj in objs:
                if not _object_matches_organizations(obj, organizations or []):
                    continue
                # Determine an IOC value - prefer sha256 if present
                sha256 = obj.get("sha256") or obj.get("sha256_hash") or obj.get("checksum") or None
                ioc_value = sha256 or obj.get("id") or obj.get("uuid")
                if not ioc_value:
                    continue

                # time filtering
                ts = obj.get("upload_time") or obj.get("first_seen") or obj.get("created_at") or ""
                dt = _parse_dt(ts) or datetime.now(tz=timezone.utc)
                if since and dt < since:
                    logger.info("mwdb_stop_reason", extra={"mode": mode, "reason": "time_cutoff"})
                    return
                if until and dt > until:
                    continue

                obj_tags = _normalize_obj_tags(obj.get("tags"))

                # merge tags
                all_tags = []
                seen: set = set()
                for t in list(tags) + list(obj_tags):
                    if not t:
                        continue
                    k = t.lower()
                    if k in seen:
                        continue
                    seen.add(k)
                    all_tags.append(t)

                metadata = dict(obj)

                tlp = "AMBER" if _object_matches_group(obj, my_group or "") else "GREEN"
                yield {
                    "ioc_value": str(ioc_value),
                    "ioc_type": "hash" if sha256 else "object_id",
                    "source": "mwdb",
                    "source_ref": str(obj.get("id") or ioc_value),
                    "first_seen": dt,
                    "last_seen": dt,
                    "confidence": 60,
                    "tlp": tlp,
                    "is_active": True,
                    "tags": all_tags,
                    "comments": "MWDB tag query",
                    "metadata": metadata,
                }
                yielded += 1
                if yielded >= limit:
                    logger.info("mwdb_stop_reason", extra={"mode": mode, "reason": "limit_reached", "yielded": yielded})
                    return

                older_than = obj.get("id") or older_than

            # if we didn't update older_than, break to avoid infinite loop
            if not older_than:
                logger.info("mwdb_stop_reason", extra={"mode": mode, "reason": "no_older_than"})
                return
            if older_than == page_older_than:
                logger.info("mwdb_stop_reason", extra={"mode": mode, "reason": "stuck_older_than"})
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

    if _circuit_breaker.is_open("mwdb"):
        logger.warning("mwdb_circuit_open_skipping")
        return {"skipped": 1, "fetched": 0}

    tags = _parse_tag_list(cfg.MWDB_TAGS)
    mode = "tags" if tags else "recent"

    since = None if cfg.MWDB_NO_TIME_LIMIT else (now - timedelta(days=max(1, int(cfg.MWDB_DAYS or 0)))) if int(cfg.MWDB_DAYS or 0) > 0 else None
    organizations = _parse_org_list(cfg.MWDB_ORGANIZATIONS)
    my_group = (cfg.MWDB_MY_GROUP or "").strip() or None
    raw_rows = list(
        fetch_mwdb_by_tags(
            base_url=cfg.MWDB_URL,
            auth_key=cfg.MWDB_AUTH_KEY,
            tags=tags,
            custom_filter=cfg.MWDB_CUSTOM_FILTER,
            mode=mode,
            since=since,
            until=None,
            organizations=organizations,
            my_group=my_group,
            limit=max(1, int(cfg.MWDB_LIMIT)),
            timeout_s=max(1, int(cfg.FEED_HTTP_TIMEOUT_S)),
            retry_attempts=max(1, int(cfg.FEED_RETRY_ATTEMPTS)),
            retry_base_delay_s=max(0.1, float(cfg.FEED_RETRY_BASE_DELAY_S)),
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
        # Deactivate missing indicators via a single SQL UPDATE (avoids loading all rows to Python)
        if incoming:
            db.execute(
                update(Indicator)
                .where(
                    Indicator.source == "mwdb",
                    Indicator.is_active == True,  # noqa: E712
                    ~Indicator.value.in_(list(incoming)),
                )
                .values(is_active=False, last_seen=now)
                .execution_options(synchronize_session=False)
            )
        else:
            db.execute(
                update(Indicator)
                .where(Indicator.source == "mwdb", Indicator.is_active == True)  # noqa: E712
                .values(is_active=False, last_seen=now)
                .execution_options(synchronize_session=False)
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
                metadata={"fetched": len(rows), "tags": tags, "mode": mode},
            ).on_conflict_do_update(
                index_elements=["source", "source_id"],
                set_={
                    "last_update": now,
                    "last_fetch_status": "success",
                    "last_fetch_error": None,
                    "metadata": {"fetched": len(rows), "tags": tags, "organizations": organizations, "days": None if cfg.MWDB_NO_TIME_LIMIT else int(cfg.MWDB_DAYS or 0), "mode": mode},
                },
            )
        )
        db.commit()
        _circuit_breaker.record_success("mwdb")
        logger.info("mwdb_updated", extra={"fetched": len(rows), "tags": len(tags), "mode": mode})
        return {"fetched": len(rows)}
    except Exception as e:
        db.rollback()
        _circuit_breaker.record_failure(
            "mwdb",
            fail_threshold=max(1, int(cfg.MWDB_CIRCUIT_FAIL_THRESHOLD)),
            cooldown_s=max(1, int(cfg.MWDB_CIRCUIT_COOLDOWN_S)),
        )
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
