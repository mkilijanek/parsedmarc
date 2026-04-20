from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .enrichment import enrich_metadata


HASH_LENGTHS = {32, 40, 64, 96, 128}
VALID_TYPES = {"ip", "domain", "url", "hash", "email", "object_id"}


def _is_hash(value: str) -> bool:
    v = (value or "").strip().lower()
    return len(v) in HASH_LENGTHS and re.fullmatch(r"[0-9a-f]+", v) is not None


def _normalize_type(raw_type: str, value: str) -> str:
    t = (raw_type or "").strip().lower()
    if t in {"ip", "domain", "url", "hash", "email", "object_id"}:
        return t
    if t in {"sha256_hash", "sha1_hash", "md5_hash", "sha3_384"}:
        return "hash"
    if t in {"ip:port", "ip-src", "ip-dst"}:
        return "ip"
    if t in {"hostname"}:
        return "domain"
    if t == "uri":
        return "url"
    return infer_type_from_value(value)


def infer_type_from_value(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return "object_id"
    if _is_hash(v):
        return "hash"
    if "://" in v:
        return "url"
    if "@" in v and " " not in v:
        return "email"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "." in v and "/" not in v and " " not in v:
        return "domain"
    return "object_id"


def normalize_value(value: str, ioc_type: str) -> Optional[str]:
    v = (value or "").strip()
    if not v:
        return None
    t = _normalize_type(ioc_type, v)
    if t == "ip":
        if ":" in v and v.count(":") == 1 and "." in v:
            v = v.split(":", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(v))
        except Exception:
            return None
    if t == "domain":
        v = v.lower().rstrip(".")
        if " " in v or "/" in v or not v:
            return None
        return v
    if t == "hash":
        v = v.lower()
        if not _is_hash(v):
            return None
        return v
    if t == "email":
        v = v.lower()
        if "@" not in v or " " in v:
            return None
        return v
    # url/object_id
    return v


def normalize_tags(tags: Iterable[str] | None) -> List[str]:
    out: List[str] = []
    seen = set()
    for raw in tags or []:
        t = str(raw or "").strip().lower()
        if not t:
            continue
        if t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def normalize_source_ref(source_ref: Any, fallback_value: str) -> str:
    ref = str(source_ref or "").strip()
    if ref:
        return ref
    return fallback_value


def confidence_v2(*, source: str, base_confidence: int, first_seen: datetime | None) -> int:
    c = int(base_confidence or 50)
    now = datetime.now(timezone.utc)
    if first_seen is not None:
        dt = first_seen if first_seen.tzinfo else first_seen.replace(tzinfo=timezone.utc)
        age_days = max(0.0, (now - dt).total_seconds() / 86400.0)
        # Mild freshness decay, capped to avoid over-penalizing historical IOCs.
        c -= int(min(15, age_days // 30))
    if source in {"threatfox", "misp"}:
        c += 5
    if source in {"abusech_hunting_fplist"}:
        c = min(c, 30)
    return max(0, min(100, c))


def canonicalize_row(
    row: Dict[str, Any],
    *,
    source: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    ioc_value_raw = str(row.get("ioc_value") or "").strip()
    ioc_type = _normalize_type(str(row.get("ioc_type") or ""), ioc_value_raw)
    if ioc_type not in VALID_TYPES:
        return None, "invalid_type"
    value = normalize_value(ioc_value_raw, ioc_type)
    if not value:
        return None, "invalid_value"

    first_seen = row.get("first_seen")
    last_seen = row.get("last_seen")
    if first_seen is None and last_seen is not None:
        first_seen = last_seen
    if last_seen is None and first_seen is not None:
        last_seen = first_seen

    normalized = {
        "ioc_value": value,
        "ioc_type": ioc_type,
        "source": source,
        "source_ref": normalize_source_ref(row.get("source_ref"), value),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "confidence": confidence_v2(
            source=source,
            base_confidence=int(row.get("confidence") or 50),
            first_seen=first_seen if isinstance(first_seen, datetime) else None,
        ),
        "tlp": str(row.get("tlp") or "WHITE").upper(),
        "is_active": bool(row.get("is_active", True)),
        "tags": normalize_tags(row.get("tags") or []),
        "metadata": enrich_metadata(
            value=value,
            ioc_type=ioc_type,
            metadata=row.get("metadata") if isinstance(row.get("metadata"), dict) else {},
        ),
    }
    return normalized, None


def dedup_rows(rows: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    out: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    merged = 0
    for row in rows:
        key = (
            str(row.get("source") or ""),
            str(row.get("ioc_value") or ""),
            str(row.get("ioc_type") or ""),
            str(row.get("source_ref") or ""),
        )
        if key not in out:
            out[key] = dict(row)
            continue
        merged += 1
        existing = out[key]
        existing["confidence"] = max(int(existing.get("confidence") or 0), int(row.get("confidence") or 0))
        existing["is_active"] = bool(existing.get("is_active", True) or row.get("is_active", True))
        # Merge tags preserving normalized uniqueness.
        existing["tags"] = normalize_tags(list(existing.get("tags") or []) + list(row.get("tags") or []))
        # Merge metadata shallowly.
        existing_metadata = existing.get("metadata")
        row_metadata = row.get("metadata")
        md: Dict[str, Any] = {}
        if isinstance(existing_metadata, dict):
            md.update(existing_metadata)
        if isinstance(row_metadata, dict):
            md.update(row_metadata)
        existing["metadata"] = md
        # Keep latest last_seen and earliest first_seen when available.
        fs_a = existing.get("first_seen")
        fs_b = row.get("first_seen")
        if fs_a is None or (fs_b is not None and fs_b < fs_a):
            existing["first_seen"] = fs_b
        ls_a = existing.get("last_seen")
        ls_b = row.get("last_seen")
        if ls_b is not None and (ls_a is None or ls_b > ls_a):
            existing["last_seen"] = ls_b
    return list(out.values()), merged
