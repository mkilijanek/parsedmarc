from __future__ import annotations

import csv
import io
import ipaddress
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

import requests
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..config import Config
from ..db import SessionLocal
from ..metrics import (
    feed_update_errors,
    feed_fetch_total,
    feed_fetched_rows_total,
    feed_deactivated_rows_total,
    feed_update_duration_seconds,
    quality_normalized_total,
    quality_dropped_invalid_total,
    quality_dedup_merged_total,
)
from ..models import FeedStats, Indicator
from .common import retry_with_backoff
from .quality import canonicalize_row, dedup_rows

logger = logging.getLogger(__name__)
_CIRCUIT_STATE: Dict[str, Dict[str, float]] = {}


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


def _post_json_with_retry(
    *,
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout_s: int,
    retry_attempts: int,
    retry_base_delay_s: float,
) -> Dict[str, Any]:
    def _do() -> Dict[str, Any]:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError("Unexpected non-object JSON response")
        return data

    return retry_with_backoff(
        _do,
        max_attempts=max(1, retry_attempts),
        base_delay=max(0.1, retry_base_delay_s),
    )


def _get_text_with_retry(
    *,
    url: str,
    timeout_s: int,
    retry_attempts: int,
    retry_base_delay_s: float,
) -> str:
    def _do() -> str:
        resp = requests.get(url, timeout=timeout_s)
        resp.raise_for_status()
        return resp.text

    return retry_with_backoff(
        _do,
        max_attempts=max(1, retry_attempts),
        base_delay=max(0.1, retry_base_delay_s),
    )


def _cb_is_open(source: str, now_ts: float) -> bool:
    state = _CIRCUIT_STATE.get(source) or {}
    return float(state.get("open_until", 0.0)) > now_ts


def _cb_record_success(source: str) -> None:
    _CIRCUIT_STATE[source] = {"fails": 0.0, "open_until": 0.0}


def _cb_record_failure(source: str, *, fail_threshold: int, cooldown_s: int, now_ts: float) -> None:
    state = _CIRCUIT_STATE.get(source) or {"fails": 0.0, "open_until": 0.0}
    fails = float(state.get("fails", 0.0)) + 1.0
    open_until = float(state.get("open_until", 0.0))
    if fails >= max(1, fail_threshold):
        open_until = now_ts + max(1, cooldown_s)
        fails = 0.0
    _CIRCUIT_STATE[source] = {"fails": fails, "open_until": open_until}


def fetch_threatfox_iocs(
    *,
    api_url: str,
    auth_key: str,
    days: int = 3,
    limit: int = 1000,
    timeout_s: int = 30,
    retry_attempts: int = 4,
    retry_base_delay_s: float = 1.0,
) -> Iterator[Dict[str, Any]]:
    payload = {"query": "get_iocs", "days": max(1, min(days, 7))}
    data = _post_json_with_retry(
        url=api_url,
        headers=_abusech_headers(auth_key),
        payload=payload,
        timeout_s=timeout_s,
        retry_attempts=retry_attempts,
        retry_base_delay_s=retry_base_delay_s,
    )
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


def _fetch_text_lines(
    url: str,
    timeout_s: int = 30,
    retry_attempts: int = 4,
    retry_base_delay_s: float = 1.0,
) -> List[str]:
    text = _get_text_with_retry(
        url=url,
        timeout_s=timeout_s,
        retry_attempts=retry_attempts,
        retry_base_delay_s=retry_base_delay_s,
    )
    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def fetch_urlhaus_urls(
    *,
    url: str,
    limit: int = 10000,
    timeout_s: int = 30,
    retry_attempts: int = 4,
    retry_base_delay_s: float = 1.0,
) -> Iterator[Dict[str, Any]]:
    now = datetime.now(tz=timezone.utc)
    yielded = 0
    for line in _fetch_text_lines(
        url,
        timeout_s=timeout_s,
        retry_attempts=retry_attempts,
        retry_base_delay_s=retry_base_delay_s,
    ):
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


def fetch_feodotracker_ips(
    *,
    url: str,
    limit: int = 10000,
    timeout_s: int = 30,
    retry_attempts: int = 4,
    retry_base_delay_s: float = 1.0,
) -> Iterator[Dict[str, Any]]:
    now = datetime.now(tz=timezone.utc)
    yielded = 0
    for line in _fetch_text_lines(
        url,
        timeout_s=timeout_s,
        retry_attempts=retry_attempts,
        retry_base_delay_s=retry_base_delay_s,
    ):
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
    retry_attempts: int = 4,
    retry_base_delay_s: float = 1.0,
) -> Iterator[Dict[str, Any]]:
    if not identifier:
        return
    payload = {
        "query": "list_tasks",
        "identifier": identifier,
        "task_status": task_status,
    }
    data = _post_json_with_retry(
        url=api_url,
        headers=_abusech_headers(auth_key),
        payload=payload,
        timeout_s=timeout_s,
        retry_attempts=retry_attempts,
        retry_base_delay_s=retry_base_delay_s,
    )
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


def fetch_yaraify_lookup_hashes(
    *,
    api_url: str,
    auth_key: str,
    search_terms: List[str],
    limit: int = 250,
    timeout_s: int = 30,
    retry_attempts: int = 4,
    retry_base_delay_s: float = 1.0,
) -> Iterator[Dict[str, Any]]:
    yielded = 0
    headers = _abusech_headers(auth_key)
    for term in search_terms:
        search_term = (term or "").strip()
        if not search_term:
            continue
        payload = {"query": "lookup_hash", "search_term": search_term}
        data = _post_json_with_retry(
            url=api_url,
            headers=headers,
            payload=payload,
            timeout_s=timeout_s,
            retry_attempts=retry_attempts,
            retry_base_delay_s=retry_base_delay_s,
        )
        if data.get("query_status") != "ok":
            logger.warning(
                "yaraify_lookup_hash_failed",
                extra={"search_term": search_term, "status": data.get("query_status")},
            )
            continue
        entries = data.get("data", []) or []
        if isinstance(entries, dict):
            entries = [entries]
        for item in entries:
            if not isinstance(item, dict):
                continue
            ioc_value = str(
                item.get("sha256_hash")
                or item.get("sha1_hash")
                or item.get("md5_hash")
                or item.get("sha3_384")
                or search_term
            ).strip()
            if not ioc_value:
                continue
            fs = _parse_dt(item.get("first_seen")) or datetime.now(tz=timezone.utc)
            yield {
                "ioc_value": ioc_value,
                "ioc_type": "hash",
                "source": "yaraify",
                "source_ref": str(item.get("task_id") or search_term),
                "first_seen": fs,
                "last_seen": fs,
                "confidence": 55,
                "tlp": "GREEN",
                "is_active": True,
                "tags": ["lookup_hash"],
                "metadata": dict(item),
            }
            yielded += 1
            if yielded >= max(1, min(limit, 1000)):
                return


def _pick_ioc_from_csv_row(row: Dict[str, str]) -> tuple[str, str] | tuple[None, None]:
    lowered = {str(k).strip().lower(): str(v).strip() for k, v in row.items()}

    entry_value = lowered.get("entry_value", "")
    entry_type = lowered.get("entry_type", "").lower()
    if entry_value:
        if entry_type in {"ip"}:
            return entry_value, "ip"
        if entry_type in {"domain"}:
            return entry_value, "domain"
        if entry_type in {"url"}:
            return entry_value, "url"
        if entry_type in {"sha256_hash", "sha1_hash", "md5_hash", "sha3_384", "hash"}:
            return entry_value, "hash"
        return entry_value, _infer_ioc_type(entry_value)

    candidates = [
        "ioc", "value", "indicator", "ip", "domain", "url",
        "sha256_hash", "md5_hash", "sha1_hash", "hash",
    ]
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
    retry_attempts: int = 4,
    retry_base_delay_s: float = 1.0,
) -> Iterator[Dict[str, Any]]:
    fmt = (response_format or "csv").strip().lower()
    if fmt not in {"csv", "json"}:
        fmt = "csv"
    payload = {"query": "get_fplist", "format": fmt}
    data: Dict[str, Any] | None = None
    text_data: str | None = None
    if fmt == "json":
        data = _post_json_with_retry(
            url=api_url,
            headers=_abusech_headers(auth_key),
            payload=payload,
            timeout_s=timeout_s,
            retry_attempts=retry_attempts,
            retry_base_delay_s=retry_base_delay_s,
        )
    else:
        def _do_text() -> str:
            resp = requests.post(api_url, headers=_abusech_headers(auth_key), json=payload, timeout=timeout_s)
            resp.raise_for_status()
            return resp.text
        text_data = retry_with_backoff(
            _do_text,
            max_attempts=max(1, retry_attempts),
            base_delay=max(0.1, retry_base_delay_s),
        )
    now = datetime.now(tz=timezone.utc)

    yielded = 0
    if fmt == "json":
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

    csv_lines = []
    for line in (text_data or "").splitlines():
        ln = line.strip()
        if not ln or ln.startswith("#"):
            continue
        csv_lines.append(line)
    reader = csv.DictReader(io.StringIO("\n".join(csv_lines)))
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
    incoming_types = {str(r.get("ioc_type") or "").strip() for r in rows if str(r.get("ioc_type") or "").strip()}
    existing = db.query(Indicator.id, Indicator.value).filter(Indicator.source == source).all()
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
        ioc_type = str(item.get("ioc_type") or _infer_ioc_type(value))
        metadata_obj = dict(item.get("metadata") or {})
        rel_sources = set(related_sources_map.get((value, ioc_type), set()))
        rel_sources.add(source)
        metadata_obj["related_sources"] = sorted(rel_sources)
        source_ref = str(item.get("source_ref") or value)
        stmt = pg_insert(Indicator.__table__).values(
            value=value,
            type=ioc_type,
            source=source,
            source_id=source_ref,
            first_seen=item.get("first_seen") or now,
            last_seen=item.get("last_seen") or now,
            confidence=int(item.get("confidence") or 50),
            tlp=str(item.get("tlp") or "WHITE"),
            is_active=bool(item.get("is_active", True)),
            metadata={source: metadata_obj},
            tags=list(item.get("tags") or []),
        ).on_conflict_do_update(
            index_elements=["value", "source", "source_id"],
            set_={
                "last_seen": item.get("last_seen") or now,
                "is_active": True,
                "confidence": int(item.get("confidence") or 50),
                "tlp": str(item.get("tlp") or "WHITE"),
                "metadata": {source: metadata_obj},
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


def _quality_prepare_rows(source: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    canonical: List[Dict[str, Any]] = []
    for row in rows:
        normalized, reason = canonicalize_row(row, source=source)
        if normalized is None:
            quality_dropped_invalid_total.labels(source=source, reason=(reason or "invalid")).inc()
            continue
        canonical.append(normalized)
    deduped, merged = dedup_rows(canonical)
    quality_normalized_total.labels(source=source).inc(len(deduped))
    if merged:
        quality_dedup_merged_total.labels(source=source).inc(merged)
    return deduped


def _mark_feed_error(db, *, source: str, now: datetime, error: str) -> None:
    db.execute(
        pg_insert(FeedStats.__table__).values(
            source=source,
            source_id=None,
            last_update=now,
            last_fetch_status="error",
            last_fetch_error=error[:2000],
            metadata={},
        ).on_conflict_do_update(
            index_elements=["source", "source_id"],
            set_={
                "last_update": now,
                "last_fetch_status": "error",
                "last_fetch_error": error[:2000],
            },
        )
    )


def _validate_abusech_config(cfg: Config) -> None:
    shared_key = (cfg.ABUSECH_AUTH_KEY or "").strip()
    if cfg.THREATFOX_ENABLED and not ((cfg.THREATFOX_AUTH_KEY or "").strip() or shared_key):
        raise RuntimeError("THREATFOX_ENABLED=true requires THREATFOX_AUTH_KEY or ABUSECH_AUTH_KEY")
    if cfg.HUNTING_FPLIST_ENABLED and not ((cfg.HUNTING_AUTH_KEY or "").strip() or shared_key):
        raise RuntimeError("HUNTING_FPLIST_ENABLED=true requires HUNTING_AUTH_KEY or ABUSECH_AUTH_KEY")
    if cfg.YARAIFY_ENABLED and not ((cfg.YARAIFY_AUTH_KEY or "").strip() or shared_key):
        raise RuntimeError("YARAIFY_ENABLED=true requires YARAIFY_AUTH_KEY or ABUSECH_AUTH_KEY")
    if cfg.YARAIFY_ENABLED:
        has_identifier = bool((cfg.YARAIFY_IDENTIFIER or "").strip())
        has_hashes = bool((cfg.YARAIFY_LOOKUP_HASHES or "").strip())
        if not has_identifier and not has_hashes:
            raise RuntimeError("YARAIFY_ENABLED=true requires YARAIFY_IDENTIFIER or YARAIFY_LOOKUP_HASHES")


def update_abusech_indicators() -> Dict[str, Dict[str, int]]:
    cfg = Config()
    now = datetime.now(tz=timezone.utc)
    _validate_abusech_config(cfg)

    auth_key = cfg.ABUSECH_AUTH_KEY
    results: Dict[str, Dict[str, int]] = {}

    def _source_specs() -> List[tuple[str, bool, Any]]:
        retry_attempts = max(1, int(cfg.ABUSECH_RETRY_ATTEMPTS))
        retry_base_delay_s = max(1, int(cfg.ABUSECH_RETRY_BASE_DELAY_S))
        timeout_s = max(1, int(cfg.ABUSECH_TIMEOUT_S))
        specs: List[tuple[str, bool, Any]] = []
        specs.append((
            "threatfox",
            bool(cfg.THREATFOX_ENABLED),
            lambda: list(
                fetch_threatfox_iocs(
                    api_url=cfg.THREATFOX_API_URL,
                    auth_key=cfg.THREATFOX_AUTH_KEY or auth_key,
                    days=max(1, int(cfg.THREATFOX_DAYS)),
                    limit=max(1, int(cfg.THREATFOX_LIMIT)),
                    timeout_s=timeout_s,
                    retry_attempts=retry_attempts,
                    retry_base_delay_s=retry_base_delay_s,
                )
            ),
        ))
        specs.append((
            "urlhaus",
            bool(cfg.URLHAUS_ENABLED),
            lambda: list(
                fetch_urlhaus_urls(
                    url=cfg.URLHAUS_FEED_URL,
                    limit=max(1, int(cfg.URLHAUS_LIMIT)),
                    timeout_s=timeout_s,
                    retry_attempts=retry_attempts,
                    retry_base_delay_s=retry_base_delay_s,
                )
            ),
        ))
        specs.append((
            "feodotracker",
            bool(cfg.FEODOTRACKER_ENABLED),
            lambda: list(
                fetch_feodotracker_ips(
                    url=cfg.FEODOTRACKER_FEED_URL,
                    limit=max(1, int(cfg.FEODOTRACKER_LIMIT)),
                    timeout_s=timeout_s,
                    retry_attempts=retry_attempts,
                    retry_base_delay_s=retry_base_delay_s,
                )
            ),
        ))
        if cfg.YARAIFY_ENABLED:
            yk = cfg.YARAIFY_AUTH_KEY or auth_key
            identifier = (cfg.YARAIFY_IDENTIFIER or "").strip()
            if identifier:
                specs.append((
                    "yaraify",
                    True,
                    lambda: list(
                        fetch_yaraify_tasks(
                            api_url=cfg.YARAIFY_API_URL,
                            auth_key=yk,
                            identifier=identifier,
                            task_status=cfg.YARAIFY_TASK_STATUS,
                            limit=max(1, int(cfg.YARAIFY_LIMIT)),
                            timeout_s=timeout_s,
                            retry_attempts=retry_attempts,
                            retry_base_delay_s=retry_base_delay_s,
                        )
                    ),
                ))
            else:
                search_terms = [x.strip() for x in (cfg.YARAIFY_LOOKUP_HASHES or "").split(",") if x.strip()]
                specs.append((
                    "yaraify",
                    True,
                    lambda: list(
                        fetch_yaraify_lookup_hashes(
                            api_url=cfg.YARAIFY_API_URL,
                            auth_key=yk,
                            search_terms=search_terms,
                            limit=max(1, int(cfg.YARAIFY_LIMIT)),
                            timeout_s=timeout_s,
                            retry_attempts=retry_attempts,
                            retry_base_delay_s=retry_base_delay_s,
                        )
                    ),
                ))
        specs.append((
            "abusech_hunting_fplist",
            bool(cfg.HUNTING_FPLIST_ENABLED),
            lambda: list(
                fetch_hunting_fplist(
                    api_url=cfg.HUNTING_API_URL,
                    auth_key=cfg.HUNTING_AUTH_KEY or auth_key,
                    response_format=cfg.HUNTING_FPLIST_FORMAT,
                    limit=max(1, int(cfg.HUNTING_FPLIST_LIMIT)),
                    timeout_s=timeout_s,
                    retry_attempts=retry_attempts,
                    retry_base_delay_s=retry_base_delay_s,
                )
            ),
        ))
        return specs

    db = SessionLocal()
    try:
        for source, enabled, fetch_fn in _source_specs():
            if not enabled:
                continue
            with feed_update_duration_seconds.labels(source=source).time():
                now_ts = time.time()
                if _cb_is_open(source, now_ts):
                    feed_fetch_total.labels(source=source, status="circuit_open").inc()
                    results[source] = {"skipped": 1, "fetched": 0, "deactivated": 0}
                    continue
                try:
                    rows = fetch_fn()
                    rows = _quality_prepare_rows(source, rows)
                    stats = _upsert_source_rows(
                        db,
                        source=source,
                        rows=rows,
                        now=now,
                        meta={"fetched": len(rows)},
                    )
                    db.commit()
                    _cb_record_success(source)
                    feed_fetch_total.labels(source=source, status="success").inc()
                    feed_fetched_rows_total.labels(source=source).inc(stats["fetched"])
                    feed_deactivated_rows_total.labels(source=source).inc(stats["deactivated"])
                    results[source] = stats
                except Exception as e:
                    db.rollback()
                    _cb_record_failure(
                        source,
                        fail_threshold=max(1, int(cfg.ABUSECH_CIRCUIT_FAIL_THRESHOLD)),
                        cooldown_s=max(1, int(cfg.ABUSECH_CIRCUIT_COOLDOWN_S)),
                        now_ts=now_ts,
                    )
                    feed_update_errors.labels(source=source).inc()
                    feed_fetch_total.labels(source=source, status="error").inc()
                    try:
                        _mark_feed_error(db, source=source, now=now, error=str(e))
                        db.commit()
                    except Exception:
                        db.rollback()
                    logger.error("abusech_source_update_failed", extra={"source": source, "error": str(e)}, exc_info=True)
                    results[source] = {"error": 1, "fetched": 0, "deactivated": 0}
        return results
    finally:
        db.close()
