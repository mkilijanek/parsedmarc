from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from flask import render_template

from ..models import Indicator







def render_index(total: int, active: int, feeds: list[Any]) -> str:
    return render_template(
        "legacy/index.html",
        total=total,
        active=active,
        feeds=list(feeds),
    )


def render_indicators(
    rows: list[Indicator],
    *,
    q: str | None,
    type_filter: str,
    tlp: str,
    source: str,
    min_conf: int | None,
    max_conf: int | None,
    limit: int,
    offset: int,
    total_count: int,
    source_options: list[str],
) -> str:
    def _query_escape(value: str) -> str:
        return (value or "").replace("\\", "\\\\").replace('"', '\\"')

    view_rows: list[dict[str, Any]] = []
    for ind in rows:
        conf = int(ind.confidence or 0)
        itype = str(ind.type or "")
        itlp = str(ind.tlp or "")
        isource = str(ind.source or "")
        isource_id = str(ind.source_id or "")

        export_formats_misp = ("csv", "txt", "json", "fortigate")
        export_formats_generic = ("txt", "csv", "json", "fortigate")

        if isource == "misp" and isource_id:
            q_row = None
        else:
            q_row = f'value:"{_query_escape(str(ind.value or ""))}" AND source:"{_query_escape(isource)}"'

        view_rows.append(
            {
                "value": str(ind.value or ""),
                "itype": itype,
                "confidence": conf,
                "itlp": itlp,
                "source": isource,
                "source_id": isource_id,
                "is_misp": isource == "misp" and bool(isource_id),
                "q_row": q_row,
                "export_formats_misp": export_formats_misp,
                "export_formats_generic": export_formats_generic,
                "tags": list((ind.tags or [])[:10]),
            }
        )

    active_query: dict[str, str] = {}
    if q:
        active_query["q"] = q
    if type_filter and type_filter != "all":
        active_query["type"] = type_filter
    if tlp and tlp != "ALL" and tlp != "all":
        active_query["tlp"] = tlp
    if source and source != "all":
        active_query["source"] = source
    if min_conf is not None:
        active_query["min_conf"] = str(min_conf)
    if max_conf is not None:
        active_query["max_conf"] = str(max_conf)
    active_query["limit"] = str(limit)
    active_query["offset"] = str(offset)
    filter_qs = urlencode(active_query)
    filter_suffix = f"?{filter_qs}" if filter_qs else ""
    has_filters = any(k in active_query for k in ("q", "type", "tlp", "source", "min_conf", "max_conf"))
    page = (offset // max(1, limit)) + 1
    total_pages = max(1, (total_count + max(1, limit) - 1) // max(1, limit))
    prev_offset = max(0, offset - limit)
    next_offset = offset + limit

    def _page_link(target_offset: int) -> str:
        qv = dict(active_query)
        qv["offset"] = str(target_offset)
        return "/indicators?" + urlencode(qv)

    prev_link = _page_link(prev_offset)
    next_link = _page_link(next_offset)
    min_conf_options = [{"value": "", "label": "", "match_value": None}] + [
        {"value": str(n), "label": str(n), "match_value": n} for n in [0, 25, 50, 60, 70, 80, 90]
    ]
    max_conf_options = [{"value": "", "label": "", "match_value": None}] + [
        {"value": str(n), "label": str(n), "match_value": n} for n in [100, 90, 80, 70, 60, 50, 25]
    ]
    return render_template(
        "legacy/indicators.html",
        q=q,
        type_filter=type_filter,
        tlp=tlp,
        source=source,
        min_conf=min_conf,
        max_conf=max_conf,
        limit=limit,
        offset=offset,
        total_count=total_count,
        source_options=source_options,
        type_options=["all", "ip", "domain", "url", "hash", "email"],
        tlp_options=["all", "WHITE", "GREEN", "AMBER", "RED"],
        min_conf_options=min_conf_options,
        max_conf_options=max_conf_options,
        has_filters=has_filters,
        page=page,
        total_pages=total_pages,
        next_offset=next_offset,
        prev_link=prev_link,
        next_link=next_link,
        filter_suffix=filter_suffix,
        view_rows=view_rows,
    )
