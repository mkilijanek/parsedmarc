from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, date, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import psycopg2
import psycopg2.extras

from .config import Config
from .services.malwarebazaar import fetch_malwarebazaar_by_tags
from .services.mwdb import fetch_mwdb_by_tags


def _parse_time(s: str) -> datetime:
    """
    Accepts:
      - YYYY-MM-DD
      - ISO datetime (with or without timezone)
    Returns timezone-aware UTC datetime.
    """
    s = s.strip()
    if not s:
        raise ValueError("empty time")
    # date-only
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        d = date.fromisoformat(s)
        return datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=timezone.utc)
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _load_config_file(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return {}
    if p.suffix.lower() == ".json":
        return json.loads(raw)

    # .env / ini-like: KEY=VALUE, ignore comments and empty lines
    out: Dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _merge_list(value: Optional[str], values: Optional[List[str]]) -> List[str]:
    """
    Merge tags from comma-separated string and repeated args.
    """
    result: List[str] = []
    if value:
        result += [x.strip() for x in value.split(",") if x.strip()]
    if values:
        result += [x.strip() for x in values if x.strip()]
    # de-dup while preserving order
    seen = set()
    out = []
    for t in result:
        if t.lower() in seen:
            continue
        seen.add(t.lower())
        out.append(t)
    return out


def _db_connect(dsn: str):
    return psycopg2.connect(dsn)


def _upsert_iocs(conn, rows: Iterable[Dict[str, Any]]) -> Tuple[int, int]:
    """
    Upsert into ti.indicators. Uses parameterized query + ON CONFLICT.
    Expects ti schema installed.
    """
    insert_sql = """
    INSERT INTO ti.indicators (ioc_value, ioc_type, source, source_ref, first_seen, last_seen, confidence, tlp, is_active, tags, comments, metadata)
    VALUES (%(ioc_value)s, %(ioc_type)s, %(source)s, %(source_ref)s, %(first_seen)s, %(last_seen)s, %(confidence)s, %(tlp)s, %(is_active)s, %(tags)s, %(comments)s, %(metadata)s::jsonb)
    ON CONFLICT (ioc_value, ioc_type, source, source_ref) DO UPDATE
    SET last_seen = EXCLUDED.last_seen,
        is_active = TRUE,
        confidence = EXCLUDED.confidence,
        tlp = EXCLUDED.tlp,
        tags = EXCLUDED.tags,
        comments = EXCLUDED.comments,
        metadata = ti.indicators.metadata || EXCLUDED.metadata::jsonb,
        updated_at = now();
    """
    # NOTE: conflict target in schema is (ioc_value,ioc_type,source,source_ref) unique.
    # COALESCE trick for NULL source_ref: we store '' on insert below if None.
    inserted = 0
    updated = 0
    with conn.cursor() as cur:
        for r in rows:
            r = dict(r)
            if r.get("source_ref") is None:
                r["source_ref"] = ""
            cur.execute(insert_sql, r)
            # psycopg2 doesn't tell insert vs update reliably w/out RETURNING + xmax; keep simple
            inserted += 1
    conn.commit()
    return inserted, updated


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="iocctl", description="IOC Threat Feed Aggregator CLI (MWDB/MalwareBazaar)")
    parser.add_argument("--config-file", help="Path to config file (.json or KEY=VALUE .env style)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    fetch = sub.add_parser("fetch", help="Fetch indicators from a data source into PostgreSQL")
    fetch.add_argument("--data-source", required=True, choices=["mwdb", "bazaar"], help="Select data source")
    fetch.add_argument("--tags", action="append", help="Tag to query (repeatable). You can also pass comma-separated.")
    fetch.add_argument("--since", help="Fetch items since date/time (YYYY-MM-DD or ISO datetime)")
    fetch.add_argument("--until", help="Fetch items until date/time (YYYY-MM-DD or ISO datetime)")
    fetch.add_argument("--limit", type=int, default=1000, help="Max items fetched per tag/source (best-effort)")
    fetch.add_argument("--dry-run", action="store_true", help="Do not write to DB, only print counts")

    args = parser.parse_args(argv)

    cfg_overrides: Dict[str, Any] = {}
    if args.config_file:
        cfg_overrides = _load_config_file(args.config_file)

    # Tags
    tags = _merge_list(cfg_overrides.get("TAGS") or cfg_overrides.get("tags"), args.tags)
    if not tags:
        raise SystemExit("No tags provided. Use --tags or TAGS in --config-file.")

    # Time range
    since_s = args.since or cfg_overrides.get("SINCE") or cfg_overrides.get("since") or ""
    until_s = args.until or cfg_overrides.get("UNTIL") or cfg_overrides.get("until") or ""
    since = _parse_time(since_s) if since_s else None
    until = _parse_time(until_s) if until_s else None
    if since and until and since > until:
        raise SystemExit("--since must be <= --until")

    # DB DSN
    dsn = os.getenv("DATABASE_URL") or cfg_overrides.get("DATABASE_URL") or cfg_overrides.get("database_url") or ""
    if not dsn and not args.dry_run:
        raise SystemExit("DATABASE_URL not set (env or config-file).")

    # Load app config from env (already used by other components)
    app_cfg = Config()

    if args.cmd == "fetch":
        src = args.data_source
        limit = int(args.limit)

        if src == "bazaar":
            rows = fetch_malwarebazaar_by_tags(
                base_url=os.getenv("MALWAREBAZAAR_API_URL") or cfg_overrides.get("MALWAREBAZAAR_API_URL") or "https://mb-api.abuse.ch/api/v1/",
                auth_key=(
                    cfg_overrides.get("MALWAREBAZAAR_AUTH_KEY")
                    or cfg_overrides.get("ABUSECH_AUTH_KEY")
                    or os.getenv("MALWAREBAZAAR_AUTH_KEY")
                    or os.getenv("ABUSECH_AUTH_KEY")
                    or app_cfg.MALWAREBAZAAR_AUTH_KEY
                    or app_cfg.ABUSECH_AUTH_KEY
                ),
                tags=tags,
                since=since,
                until=until,
                limit=limit,
            )
        else:
            rows = fetch_mwdb_by_tags(
                base_url=(cfg_overrides.get("MWDB_URL") or os.getenv("MWDB_URL") or app_cfg.MWDB_URL),
                auth_key=(cfg_overrides.get("MWDB_AUTH_KEY") or os.getenv("MWDB_AUTH_KEY") or app_cfg.MWDB_AUTH_KEY),
                tags=tags,
                since=since,
                until=until,
                limit=limit,
            )

        rows_list = list(rows)
        if args.dry_run:
            print(json.dumps({"data_source": src, "tags": tags, "count": len(rows_list)}, indent=2, default=str))
            return 0

        conn = _db_connect(dsn)
        try:
            ins, upd = _upsert_iocs(conn, rows_list)
        finally:
            conn.close()

        print(json.dumps({"data_source": src, "tags": tags, "ingested": ins, "updated": upd, "total_rows": len(rows_list)}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
