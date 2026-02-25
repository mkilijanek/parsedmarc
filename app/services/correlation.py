from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from ..models import Indicator


def _safe_dt_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()


def query_correlations(
    db: Session,
    *,
    min_sources: int = 2,
    limit: int = 1000,
    ioc_type: str | None = None,
) -> List[Dict[str, Any]]:
    min_sources = max(2, int(min_sources))
    limit = max(1, min(5000, int(limit)))

    grouped = (
        select(
            Indicator.value,
            Indicator.type,
            func.count(func.distinct(Indicator.source)).label("src_count"),
            func.max(Indicator.last_seen).label("max_last_seen"),
            func.max(Indicator.confidence).label("max_conf"),
        )
        .where(Indicator.is_active == True)  # noqa: E712
        .group_by(Indicator.value, Indicator.type)
        .having(func.count(func.distinct(Indicator.source)) >= min_sources)
        .order_by(func.max(Indicator.last_seen).desc())
        .limit(limit)
    )
    if ioc_type and ioc_type != "all":
        grouped = grouped.where(Indicator.type == ioc_type)
    groups_cte = grouped.cte("corr_groups")

    rows = db.execute(
        select(
            groups_cte.c.value,
            groups_cte.c.type,
            groups_cte.c.src_count,
            groups_cte.c.max_last_seen,
            groups_cte.c.max_conf,
            Indicator.source,
            Indicator.source_id,
            Indicator.confidence,
            Indicator.tags,
            Indicator.metadata_,
        )
        .join(
            Indicator,
            and_(
                Indicator.value == groups_cte.c.value,
                Indicator.type == groups_cte.c.type,
                Indicator.is_active == True,  # noqa: E712
            ),
        )
        .order_by(groups_cte.c.max_last_seen.desc())
    ).all()
    if not rows:
        return []

    by_key: Dict[tuple[str, str], Dict[str, Any]] = {}
    for (value, typ, src_count, max_last_seen, max_conf, *_rest) in rows:
        key = (str(value), str(typ))
        if key not in by_key:
            by_key[key] = {
                "value": str(value),
                "type": str(typ),
                "source_count": int(src_count or 0),
                "max_confidence": int(max_conf or 0),
                "last_seen": _safe_dt_iso(max_last_seen),
                "sources": [],
                "tags": [],
                "enrichment": {},
            }

    tags_map: Dict[tuple[str, str], List[str]] = defaultdict(list)
    tags_seen: Dict[tuple[str, str], set[str]] = defaultdict(set)
    enrichment_map: Dict[tuple[str, str], Dict[str, Any]] = defaultdict(dict)
    for value, typ, _src_count, _max_last_seen, _max_conf, source, source_id, confidence, tags, metadata in rows:
        key = (str(value), str(typ))
        if key not in by_key:
            continue
        by_key[key]["sources"].append(
            {
                "source": str(source),
                "source_id": str(source_id or ""),
                "confidence": int(confidence or 0),
            }
        )
        for tag in list(tags or []):
            t = str(tag).strip().lower()
            if not t or t in tags_seen[key]:
                continue
            tags_seen[key].add(t)
            tags_map[key].append(t)
        # Gather enrichment fragments from nested source metadata.
        md = metadata if isinstance(metadata, dict) else {}
        for v in md.values():
            if isinstance(v, dict):
                enr = v.get("enrichment")
                if isinstance(enr, dict):
                    enrichment_map[key].update(enr)

    out: List[Dict[str, Any]] = []
    for key, item in by_key.items():
        item["sources"] = sorted(item["sources"], key=lambda s: (s["source"], s["source_id"]))
        item["tags"] = tags_map.get(key, [])
        item["enrichment"] = enrichment_map.get(key, {})
        out.append(item)
    return out
