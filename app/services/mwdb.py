from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

import requests

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
    if len(tags) == 1:
        q = f"tag:{tags[0]}"
    else:
        q = "(" + " OR ".join([f"tag:{t}" for t in tags]) + ")"

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

            obj_tags = obj.get("tags") or []
            if isinstance(obj_tags, dict):
                # sometimes tags may be returned as list of dicts
                obj_tags = [x.get("tag") for x in obj_tags.values() if isinstance(x, dict)]
            if isinstance(obj_tags, str):
                obj_tags = [t.strip() for t in obj_tags.split(",") if t.strip()]

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
