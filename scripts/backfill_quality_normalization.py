#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select

from app.db import SessionLocal
from app.models import Indicator
from app.services.quality import canonicalize_row, normalize_tags


def main() -> int:
    db = SessionLocal()
    updated = 0
    skipped = 0
    try:
        rows = db.scalars(select(Indicator)).all()
        for ind in rows:
            payload = {
                "ioc_value": ind.value,
                "ioc_type": ind.type,
                "source_ref": ind.source_id,
                "first_seen": ind.first_seen,
                "last_seen": ind.last_seen,
                "confidence": ind.confidence,
                "tlp": ind.tlp,
                "is_active": ind.is_active,
                "tags": list(ind.tags or []),
                "metadata": dict(ind.metadata_ or {}),
            }
            normalized, reason = canonicalize_row(payload, source=ind.source)
            if normalized is None:
                skipped += 1
                continue
            changed = False
            if ind.value != normalized["ioc_value"]:
                ind.value = normalized["ioc_value"]
                changed = True
            if ind.type != normalized["ioc_type"]:
                ind.type = normalized["ioc_type"]
                changed = True
            if (ind.source_id or "") != normalized["source_ref"]:
                ind.source_id = normalized["source_ref"]
                changed = True
            if int(ind.confidence or 0) != int(normalized["confidence"] or 0):
                ind.confidence = int(normalized["confidence"] or 0)
                changed = True
            new_tags = normalize_tags(normalized.get("tags") or [])
            if list(ind.tags or []) != new_tags:
                ind.tags = new_tags
                changed = True
            # Track remediation provenance.
            md = dict(ind.metadata_ or {})
            md["quality_backfill_at"] = datetime.now(timezone.utc).isoformat()
            if ind.metadata_ != md:
                ind.metadata_ = md
                changed = True
            if changed:
                updated += 1
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    print(json.dumps({"updated": updated, "skipped": skipped}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
