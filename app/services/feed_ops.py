from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from ..models import FeedRun, FeedStats


def feed_operational_status(*, enabled: bool, ready: bool, latest_run: FeedRun | None) -> str:
    if not enabled:
        return "DISABLED"
    if not ready:
        return "NOT_CONFIGURED"
    status = str(getattr(latest_run, "status", "") or "").lower()
    if status in {"success"}:
        return "OK"
    if status in {"failed", "cancelled"}:
        return "ERROR"
    if status in {"queued", "running", "cancel_requested"}:
        return "WARNING"
    return "WARNING"


def feed_last_error_at(latest_run: FeedRun | None, feed_stats_row: FeedStats | None) -> datetime | None:
    if latest_run is not None and str(latest_run.status or "").lower() in {"failed", "cancelled"}:
        return latest_run.finished_at or latest_run.started_at
    if feed_stats_row is not None and feed_stats_row.last_fetch_error:
        return feed_stats_row.last_update
    return None


def apply_feed_filters_and_sort(
    items: list[dict[str, Any]],
    *,
    status_filter: str,
    datasource: str,
    configured: str,
    query_text: str,
    problems_only: bool,
    sort_by: str,
    sort_order: str,
) -> list[dict[str, Any]]:
    source_types = {str(item["source_type"]) for item in items}
    status_filter = (status_filter or "").strip().upper()
    datasource = (datasource or "").strip().lower()
    configured = (configured or "").strip().lower()
    query_text = (query_text or "").strip().lower()
    problems_only = bool(problems_only)

    filtered = items
    if status_filter and status_filter != "ALL":
        filtered = [item for item in filtered if str(item["status"]) == status_filter]
    if datasource and datasource not in {"all", ""} and datasource in source_types:
        filtered = [item for item in filtered if str(item["source_type"]).lower() == datasource]
    if configured == "configured":
        filtered = [item for item in filtered if bool(item["ready"])]
    elif configured == "not_configured":
        filtered = [item for item in filtered if not bool(item["ready"])]
    if query_text:
        filtered = [
            item
            for item in filtered
            if query_text in str(item["display_name"]).lower()
            or query_text in str(item["source_id"]).lower()
            or query_text in str(item["source_type"]).lower()
        ]
    if problems_only:
        filtered = [item for item in filtered if str(item["status"]) in {"ERROR", "WARNING"}]

    def _sort_dt_key(value: Any) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        return 0.0

    status_rank = {"ERROR": 5, "WARNING": 4, "NOT_CONFIGURED": 3, "DISABLED": 2, "OK": 1}
    sort_by = (sort_by or "source").strip().lower()
    if sort_by not in {"status", "last_run_at", "last_error_at", "fetched_count", "source"}:
        sort_by = "source"
    reverse = (sort_order or "asc").strip().lower() == "desc"
    if sort_by == "status":
        return sorted(
            filtered,
            key=lambda item: (
                status_rank.get(str(item["status"]), 0),
                str(item["source_id"]).lower(),
            ),
            reverse=reverse,
        )
    if sort_by == "last_run_at":
        return sorted(
            filtered,
            key=lambda item: (
                _sort_dt_key(item.get("last_run_at")),
                str(item["source_id"]).lower(),
            ),
            reverse=reverse,
        )
    if sort_by == "last_error_at":
        return sorted(
            filtered,
            key=lambda item: (
                _sort_dt_key(item.get("last_error_at")),
                str(item["source_id"]).lower(),
            ),
            reverse=reverse,
        )
    if sort_by == "fetched_count":
        return sorted(
            filtered,
            key=lambda item: (
                int(item.get("fetched_count", 0)),
                str(item["source_id"]).lower(),
            ),
            reverse=reverse,
        )
    return sorted(
        filtered,
        key=lambda item: (str(item["source_id"]).lower(),),
        reverse=reverse,
    )


def parse_feed_table_params(args: Mapping[str, str]) -> dict[str, Any]:
    def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
        raw_value = args.get(name, str(default))
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            value = default
        return max(minimum, min(maximum, value))

    return {
        "limit": _int_arg("feeds_limit", 25, 1, 100),
        "offset": _int_arg("feeds_offset", 0, 0, 1000000),
        "sort": (args.get("feeds_sort", "source") or "source").strip().lower(),
        "order": (args.get("feeds_order", "asc") or "asc").strip().lower(),
        "status": (args.get("feeds_status", "all") or "all").strip().upper(),
        "datasource": (args.get("feeds_datasource", "all") or "all").strip().lower(),
        "configured": (args.get("feeds_configured", "all") or "all").strip().lower(),
        "q": (args.get("feeds_q", "") or "").strip(),
        "problems_only": (args.get("feeds_problems_only", "0") or "0").strip().lower() in {"1", "true", "yes", "on"},
    }


def resolve_metrics_window_hours(args: Mapping[str, str]) -> tuple[int, str]:
    window = (args.get("window") or "").strip().lower()
    if window in {"24h", "24"}:
        return 24, "24h"
    if window in {"7d", "168h", "168"}:
        return 24 * 7, "7d"
    if window in {"30d", "720h", "720"}:
        return 24 * 30, "30d"
    try:
        hours = int(args.get("hours", "24"))
    except (TypeError, ValueError):
        hours = 24
    hours = max(1, min(24 * 30, hours))
    if hours == 24:
        return 24, "24h"
    if hours == 24 * 7:
        return 24 * 7, "7d"
    if hours == 24 * 30:
        return 24 * 30, "30d"
    return hours, f"{hours}h"


def percentile(values: list[int], p: float) -> float | None:
    if not values:
        return None
    vals = sorted(values)
    if len(vals) == 1:
        return float(vals[0])
    rank = (max(0.0, min(100.0, p)) / 100.0) * (len(vals) - 1)
    low = int(rank)
    high = min(len(vals) - 1, low + 1)
    if low == high:
        return float(vals[low])
    weight = rank - low
    return round((vals[low] * (1.0 - weight)) + (vals[high] * weight), 2)


def enqueue_sync_for_source(
    source_name: str,
    *,
    feed_rows: list,
    read_feed_config_state_fn,
    enqueue_sync_job_fn,
    db,
    trigger_type: str = "manual",
) -> dict:
    """Resolve targets, check config readiness, and enqueue sync jobs.

    Returns dict: targets_found, queued, reused, blocked, error.
    error is non-empty only when source_name is not a known feed and not 'all'.
    """
    feed_map = {f.source_id: f for f in feed_rows}
    if source_name == "all":
        targets = [f for f in feed_rows if f.enabled]
    elif source_name in feed_map:
        targets = [feed_map[source_name]]
    else:
        return {"targets_found": False, "queued": [], "reused": [], "blocked": [], "error": f"Invalid source: {source_name}"}

    blocked: list[str] = []
    queued: list[dict] = []
    reused: list[dict] = []

    for feed in targets:
        state = read_feed_config_state_fn(db, feed)
        if not state["ready"]:
            blocked.append(f"{feed.source_id} (missing: {', '.join(state['missing'])})")
            continue
        job, created = enqueue_sync_job_fn(feed, trigger_type=trigger_type, db=db)
        entry = {"feed_source_id": str(feed.source_id), "job_id": str(job.job_id), "created": created}
        if created:
            queued.append(entry)
        else:
            reused.append(entry)

    return {"targets_found": True, "queued": queued, "reused": reused, "blocked": blocked, "error": ""}
