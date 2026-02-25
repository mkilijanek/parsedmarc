from __future__ import annotations

import csv
import io
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional

import requests
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..config import Config
from ..db import SessionLocal
from ..models import FeedStats, Indicator

logger = logging.getLogger(__name__)


def _parse_dt(s: str | None) -> Optional[datetime]:
    if not s:
        return None
    s = str(s).strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _is_hash(value: str) -> bool:
    v = (value or "").strip().lower()
    if len(v) in {32, 40, 64, 96, 128} and re.fullmatch(r"[0-9a-f]+", v):
        return True
    return False


def _infer_ioc_type(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return "object_id"
    if _is_hash(v):
        return "hash"
    if "://" in v:
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except Exception:
        pass
    if "." in v and "/" not in v and " " not in v:
        return "domain"
    return "object_id"


def _normalize_threatfox_ioc(ioc: str, ioc_type: str) -> tuple[str, str]:
    v = (ioc or "").strip()
    t = (ioc_type or "").strip().lower()
    if t in {"ip", "ip:port"}:
        host = v.split(":", 1)[0].strip()
        return host, "ip"
    if t in {"domain"}:
        return v, "domain"
    if t in {"url"}:
        return v, "url"
    if t in {"md5_hash", "sha256_hash", "sha1_hash", "hash"}:
        return v, "hash"
    return v, _infer_ioc_type(v)


def _abusech_headers(auth_key: str) -> Dict[str, str]:
    if not auth_key:
        raise RuntimeError("abuse.ch Auth-Key is required")
    return {"Auth-Key": auth_key, "User-Agent": "ioc-threat-platform/1.0"}


def fetch_threatfox_iocs(
    *,
    api_url: str,
    auth_key: str,
    days: int = 3,
    limit: int = 1000,
    timeout_s: int = 30,
) -> Iterator[Dict[str, Any]]:
    payload = {"query": "get_iocs", "days": max(1, min(days, 7))}
    resp = requests.post(api_url, headers=_abusech_headers(auth_key), json=payload, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()
    if data.get("query_status") != "ok":
        logger.warning("threatfox_query_failed", extra={"status": data.get("query_status")})
        return

    yielded = 0
    for item in data.get("data", []) or []:
        raw_ioc = str(item.get("ioc") or "").strip()
        if not raw_ioc:
            continue
        ioc_value, ioc_type = _normalize_threatfox_ioc(raw_ioc, str(item.get("ioc_type") or ""))
        if not ioc_value:
            continue
        fs = _parse_dt(item.get("first_seen")) or datetime.now(tz=timezone.utc)
        tags = [str(x) for x in (item.get("tags") or []) if str(x).strip()]
        malware = str(item.get("malware_printable") or item.get("malware") or "").strip()
        if malware:
            tags = [malware] + tags
        # de-dup tags while preserving order
        dedup_tags: List[str] = []
        seen = set()
        for t in tags:
            key = t.lower()
            if key in seen:
                continue
            seen.add(key)
            dedup_tags.append(t)

        yield {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "source": "threatfox",
            "source_ref": str(item.get("id") or ioc_value),
            "first_seen": fs,
            "last_seen": fs,
            "confidence": int(item.get("confidence_level") or 60),
            "tlp": "GREEN",
            "is_active": True,
            "tags": dedup_tags,
            "metadata": dict(item),
        }
        yielded += 1
        if yielded >= max(1, limit):
            return


def _fetch_text_lines(url: str, timeout_s: int = 30) -> List[str]:
    resp = requests.get(url, timeout=timeout_s)
    resp.raise_for_status()
    out: List[str] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def fetch_urlhaus_urls(*, url: str, limit: int = 10000, timeout_s: int = 30) -> Iterator[Dict[str, Any]]:
    now = datetime.now(tz=timezone.utc)
    yielded = 0
    for line in _fetch_text_lines(url, timeout_s=timeout_s):
        yield {
            "ioc_value": line,
            "ioc_type": "url",
            "source": "urlhaus",
            "source_ref": line,
            "first_seen": now,
            "last_seen": now,
            "confidence": 65,
            "tlp": "GREEN",
            "is_active": True,
            "tags": [],
            "metadata": {"url": line},
        }
        yielded += 1
        if yielded >= max(1, limit):
            return


def fetch_feodotracker_ips(*, url: str, limit: int = 10000, timeout_s: int = 30) -> Iterator[Dict[str, Any]]:
    now = datetime.now(tz=timezone.utc)
    yielded = 0
    for line in _fetch_text_lines(url, timeout_s=timeout_s):
        candidate = line.split(",")[0].strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except Exception:
            continue
        yield {
            "ioc_value": candidate,
            "ioc_type": "ip",
            "source": "feodotracker",
            "source_ref": candidate,
            "first_seen": now,
            "last_seen": now,
            "confidence": 75,
            "tlp": "AMBER",
            "is_active": True,
            "tags": [],
            "metadata": {"raw": line},
        }
        yielded += 1
        if yielded >= max(1, limit):
            return


def fetch_yaraify_tasks(
    *,
    api_url: str,
    auth_key: str,
    identifier: str,
    task_status: str = "processed",
    limit: int = 250,
    timeout_s: int = 30,
) -> Iterator[Dict[str, Any]]:
    if not identifier:
        return
    payload = {
        "query": "list_tasks",
        "identifier": identifier,
        "task_status": task_status,
    }
    resp = requests.post(api_url, headers=_abusech_headers(auth_key), json=payload, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()
    if data.get("query_status") != "ok":
        logger.warning("yaraify_query_failed", extra={"status": data.get("query_status")})
        return

    yielded = 0
    for item in data.get("data", []) or []:
        ioc_value = str(item.get("sha256_hash") or item.get("md5_hash") or "").strip()
        if not ioc_value:
            continue
        fs = _parse_dt(item.get("first_seen")) or datetime.now(tz=timezone.utc)
        yield {
            "ioc_value": ioc_value,
            "ioc_type": "hash",
            "source": "yaraify",
            "source_ref": str(item.get("task_id") or ioc_value),
            "first_seen": fs,
            "last_seen": fs,
            "confidence": 55,
            "tlp": "GREEN",
            "is_active": True,
            "tags": [str(item.get("task_status") or "").strip()] if item.get("task_status") else [],
            "metadata": dict(item),
        }
        yielded += 1
        if yielded >= max(1, min(limit, 1000)):
            return


def _pick_ioc_from_csv_row(row: Dict[str, str]) -> tuple[str, str] | tuple[None, None]:
    candidates = [
        "ioc", "value", "indicator", "ip", "domain", "url",
        "sha256_hash", "md5_hash", "sha1_hash", "hash",
    ]
    lowered = {str(k).strip().lower(): str(v).strip() for k, v in row.items()}
    for key in candidates:
        val = lowered.get(key, "")
        if not val:
            continue
        return val, _infer_ioc_type(val)
    # Fallback: first meaningful cell
    for val in lowered.values():
        if val and val.lower() not in {"null", "n/a", "none"}:
            return val, _infer_ioc_type(val)
    return None, None


def fetch_hunting_fplist(
    *,
    api_url: str,
    auth_key: str,
    response_format: str = "csv",
    limit: int = 10000,
    timeout_s: int = 30,
) -> Iterator[Dict[str, Any]]:
    fmt = (response_format or "csv").strip().lower()
    if fmt not in {"csv", "json"}:
        fmt = "csv"
    payload = {"query": "get_fplist", "format": fmt}
    resp = requests.post(api_url, headers=_abusech_headers(auth_key), json=payload, timeout=timeout_s)
    resp.raise_for_status()
    now = datetime.now(tz=timezone.utc)

    yielded = 0
    if fmt == "json":
        data = resp.json()
        entries = data.get("data", []) if isinstance(data, dict) else []
        for item in entries or []:
            if not isinstance(item, dict):
                continue
            ioc = str(item.get("ioc") or item.get("value") or "").strip()
            if not ioc:
                continue
            yield {
                "ioc_value": ioc,
                "ioc_type": _infer_ioc_type(ioc),
                "source": "abusech_hunting_fplist",
                "source_ref": str(item.get("id") or ioc),
                "first_seen": _parse_dt(item.get("first_seen")) or now,
                "last_seen": _parse_dt(item.get("last_seen")) or now,
                "confidence": 30,
                "tlp": "WHITE",
                "is_active": True,
                "tags": ["false_positive"],
                "metadata": dict(item),
            }
            yielded += 1
            if yielded >= max(1, limit):
                return
        return

    reader = csv.DictReader(io.StringIO(resp.text))
    for row in reader:
        ioc, ioc_type = _pick_ioc_from_csv_row(row)
        if not ioc or not ioc_type:
            continue
        yield {
            "ioc_value": ioc,
            "ioc_type": ioc_type,
            "source": "abusech_hunting_fplist",
            "source_ref": ioc,
            "first_seen": _parse_dt(row.get("first_seen")) or now,
            "last_seen": _parse_dt(row.get("last_seen")) or now,
            "confidence": 30,
            "tlp": "WHITE",
            "is_active": True,
            "tags": ["false_positive"],
            "metadata": dict(row),
        }
        yielded += 1
        if yielded >= max(1, limit):
            return


def _upsert_source_rows(
    db,
    *,
    source: str,
    rows: List[Dict[str, Any]],
    now: datetime,
    meta: Dict[str, Any],
) -> Dict[str, int]:
    incoming = {str(r.get("ioc_value") or "").strip() for r in rows if str(r.get("ioc_value") or "").strip()}
    existing = db.query(Indicator.id, Indicator.value).filter(Indicator.source == source).all()
    existing_map = {value: ind_id for (ind_id, value) in existing}
    to_deactivate = [existing_map[v] for v in existing_map.keys() if v not in incoming]
    if to_deactivate:
        db.query(Indicator).filter(Indicator.id.in_(to_deactivate)).update(  # type: ignore[arg-type]
            {"is_active": False, "last_seen": now}, synchronize_session=False
        )

    for item in rows:
        value = str(item.get("ioc_value") or "").strip()
        if not value:
            continue
        source_ref = str(item.get("source_ref") or value)
        stmt = pg_insert(Indicator.__table__).values(
            value=value,
            type=str(item.get("ioc_type") or _infer_ioc_type(value)),
            source=source,
            source_id=source_ref,
            first_seen=item.get("first_seen") or now,
            last_seen=item.get("last_seen") or now,
            confidence=int(item.get("confidence") or 50),
            tlp=str(item.get("tlp") or "WHITE"),
            is_active=bool(item.get("is_active", True)),
            metadata={source: item.get("metadata") or {}},
            tags=list(item.get("tags") or []),
        ).on_conflict_do_update(
            index_elements=["value", "source", "source_id"],
            set_={
                "last_seen": item.get("last_seen") or now,
                "is_active": True,
                "confidence": int(item.get("confidence") or 50),
                "tlp": str(item.get("tlp") or "WHITE"),
                "metadata": {source: item.get("metadata") or {}},
                "tags": list(item.get("tags") or []),
            },
        )
        db.execute(stmt)

    db.execute(
        pg_insert(FeedStats.__table__).values(
            source=source,
            source_id=None,
            last_update=now,
            last_fetch_status="success",
            last_fetch_error=None,
            metadata=meta,
        ).on_conflict_do_update(
            index_elements=["source", "source_id"],
            set_={
                "last_update": now,
                "last_fetch_status": "success",
                "last_fetch_error": None,
                "metadata": meta,
            },
        )
    )
    return {"fetched": len(rows), "deactivated": len(to_deactivate)}


def update_abusech_indicators() -> Dict[str, Dict[str, int]]:
    cfg = Config()
    now = datetime.now(tz=timezone.utc)

    auth_key = cfg.ABUSECH_AUTH_KEY
    results: Dict[str, Dict[str, int]] = {}
    source_rows: Dict[str, List[Dict[str, Any]]] = {}

    try:
        if cfg.THREATFOX_ENABLED:
            source_rows["threatfox"] = list(
                fetch_threatfox_iocs(
                    api_url=cfg.THREATFOX_API_URL,
                    auth_key=cfg.THREATFOX_AUTH_KEY or auth_key,
                    days=max(1, int(cfg.THREATFOX_DAYS)),
                    limit=max(1, int(cfg.THREATFOX_LIMIT)),
                )
            )
        if cfg.URLHAUS_ENABLED:
            source_rows["urlhaus"] = list(
                fetch_urlhaus_urls(
                    url=cfg.URLHAUS_FEED_URL,
                    limit=max(1, int(cfg.URLHAUS_LIMIT)),
                )
            )
        if cfg.FEODOTRACKER_ENABLED:
            source_rows["feodotracker"] = list(
                fetch_feodotracker_ips(
                    url=cfg.FEODOTRACKER_FEED_URL,
                    limit=max(1, int(cfg.FEODOTRACKER_LIMIT)),
                )
            )
        if cfg.YARAIFY_ENABLED and (cfg.YARAIFY_IDENTIFIER or "").strip():
            source_rows["yaraify"] = list(
                fetch_yaraify_tasks(
                    api_url=cfg.YARAIFY_API_URL,
                    auth_key=cfg.YARAIFY_AUTH_KEY or auth_key,
                    identifier=cfg.YARAIFY_IDENTIFIER.strip(),
                    task_status=cfg.YARAIFY_TASK_STATUS,
                    limit=max(1, int(cfg.YARAIFY_LIMIT)),
                )
            )
        if cfg.HUNTING_FPLIST_ENABLED:
            source_rows["abusech_hunting_fplist"] = list(
                fetch_hunting_fplist(
                    api_url=cfg.HUNTING_API_URL,
                    auth_key=cfg.HUNTING_AUTH_KEY or auth_key,
                    response_format=cfg.HUNTING_FPLIST_FORMAT,
                    limit=max(1, int(cfg.HUNTING_FPLIST_LIMIT)),
                )
            )

        db = SessionLocal()
        try:
            for source, rows in source_rows.items():
                results[source] = _upsert_source_rows(
                    db,
                    source=source,
                    rows=rows,
                    now=now,
                    meta={"fetched": len(rows)},
                )
            db.commit()
        except Exception as e:
            db.rollback()
            raise e
        finally:
            db.close()
        return results
    except Exception as e:
        logger.error("abusech_update_failed", extra={"error": str(e)}, exc_info=True)
        raise
