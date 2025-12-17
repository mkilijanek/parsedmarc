from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
from flask import Blueprint, Response, current_app, make_response, render_template, request, url_for
from sqlalchemy import text
from .db import engine

webui_bp = Blueprint("webui", __name__, url_prefix="/ui")

@dataclass
class UnifiedRow:
    id: int
    uuid: str
    ioc_value: str
    ioc_type: str
    source: str
    source_ref: Optional[str]
    confidence: int
    tlp: str
    is_active: bool
    tags: List[str]
    comments: Optional[str]
    metadata: Any
    first_seen: str
    last_seen: str
    platform: Optional[str] = None
    package_name: Optional[str] = None
    app_version: Optional[str] = None
    permissions: Optional[List[str]] = None
    cert_fingerprint: Optional[str] = None
    store_metadata: Any = None

def _split_csv(v: Optional[str]) -> Optional[List[str]]:
    if not v:
        return None
    items = [x.strip() for x in v.split(",") if x.strip()]
    return items or None

def _active_only(v: Optional[str]) -> bool:
    return (v or "").strip() not in {"0","false","no","off"}

def _call_search_unified(q: Optional[str], limit: int, offset: int,
                         types: Optional[List[str]], sources: Optional[List[str]],
                         tlps: Optional[List[str]], active_only: bool) -> List[UnifiedRow]:
    sql = text("""
        SELECT * FROM ti.search_unified(
            :q, :limit, :offset,
            :types, :sources, :tlps,
            :active_only
        )
    """)
    params = {
        "q": q,
        "limit": limit,
        "offset": offset,
        "types": types,
        "sources": sources,
        "tlps": tlps,
        "active_only": active_only,
    }
    rows: List[UnifiedRow] = []
    with engine.connect() as conn:
        res = conn.execute(sql, params)
        for r in res.mappings():
            rows.append(UnifiedRow(**r))
    return rows

def _build_download_links(endpoint: str, **kwargs: Any) -> Tuple[str,str,str]:
    return (
        url_for(endpoint, fmt="csv", **kwargs),
        url_for(endpoint, fmt="tsv", **kwargs),
        url_for(endpoint, fmt="json", **kwargs),
    )

@webui_bp.get("/")
def index():
    return render_template("index.html", title="IOC Viewer")

@webui_bp.get("/unified")
def unified():
    q = request.args.get("q")
    types_raw = request.args.get("types")
    sources_raw = request.args.get("sources")
    tlps_raw = request.args.get("tlps")
    active_only = _active_only(request.args.get("active_only", "1"))
    limit = int(request.args.get("limit", "200"))
    offset = int(request.args.get("offset", "0"))

    types = _split_csv(types_raw)
    sources = _split_csv(sources_raw)
    tlps = _split_csv(tlps_raw)

    rows = _call_search_unified(q, limit, offset, types, sources, tlps, active_only)

    dl_csv, dl_tsv, dl_json = _build_download_links(
        "webui.download_unified",
        q=q or "",
        types=types_raw or "",
        sources=sources_raw or "",
        tlps=tlps_raw or "",
        active_only="1" if active_only else "0",
        limit=str(limit),
        offset=str(offset),
    )

    return render_template(
        "table.html",
        title="Unified IOCs",
        rows=rows,
        q=q,
        types_raw=types_raw,
        sources_raw=sources_raw,
        tlps_raw=tlps_raw,
        active_only=active_only,
        limit=limit,
        show_mobile=True,
        download_csv=dl_csv,
        download_tsv=dl_tsv,
        download_json=dl_json,
    )

@webui_bp.get("/mobile")
def mobile():
    q = request.args.get("q")
    sources_raw = request.args.get("sources")
    tlps_raw = request.args.get("tlps")
    active_only = _active_only(request.args.get("active_only", "1"))
    limit = int(request.args.get("limit", "200"))
    offset = int(request.args.get("offset", "0"))

    sources = _split_csv(sources_raw)
    tlps = _split_csv(tlps_raw)
    # Filter to apk/ios
    types = ["apk","ios"]

    rows = _call_search_unified(q, limit, offset, types, sources, tlps, active_only)

    dl_csv, dl_tsv, dl_json = _build_download_links(
        "webui.download_mobile",
        q=q or "",
        sources=sources_raw or "",
        tlps=tlps_raw or "",
        active_only="1" if active_only else "0",
        limit=str(limit),
        offset=str(offset),
    )

    return render_template(
        "table.html",
        title="Mobile IOCs (APK/iOS)",
        rows=rows,
        q=q,
        types_raw="apk,ios",
        sources_raw=sources_raw,
        tlps_raw=tlps_raw,
        active_only=active_only,
        limit=limit,
        show_mobile=True,
        download_csv=dl_csv,
        download_tsv=dl_tsv,
        download_json=dl_json,
    )

@webui_bp.get("/stats")
def stats():
    sql = text("""
        SELECT * FROM ti.agg_iocs_by_source_type_tlp()
        ORDER BY source, ioc_type, tlp
    """)
    with engine.connect() as conn:
        res = conn.execute(sql).mappings().all()
    # normalize keys to match template
    rows = [
        {
            "source": r.get("source"),
            "ioc_type": r.get("ioc_type"),
            "tlp": r.get("tlp"),
            "total": r.get("total"),
            "active": r.get("active"),
            "inactive": r.get("inactive"),
        }
        for r in res
    ]
    return render_template("stats.html", title="IOC stats", rows=rows)

def _as_delimited(rows: List[UnifiedRow], sep: str) -> str:
    cols = [
        "uuid","ioc_value","ioc_type","source","source_ref","confidence","tlp","is_active",
        "tags","comments","first_seen","last_seen",
        "platform","package_name","app_version","permissions","cert_fingerprint"
    ]
    lines = [sep.join(cols)]
    for r in rows:
        d = r.__dict__
        def norm(v):
            if v is None:
                return ""
            if isinstance(v, list):
                return ",".join([str(x) for x in v])
            return str(v).replace("\n"," ").replace("\r"," ")
        lines.append(sep.join(norm(d.get(c)) for c in cols))
    return "\n".join(lines) + "\n"

def _download_common(fmt: str, q: Optional[str], types: Optional[List[str]], sources: Optional[List[str]],
                     tlps: Optional[List[str]], active_only: bool, limit: int, offset: int) -> Response:
    rows = _call_search_unified(q, limit, offset, types, sources, tlps, active_only)
    if fmt == "json":
        payload = [r.__dict__ for r in rows]
        resp = make_response(current_app.json.dumps(payload, ensure_ascii=False, indent=2))
        resp.headers["Content-Type"] = "application/json; charset=utf-8"
        resp.headers["Content-Disposition"] = "attachment; filename=iocs.json"
        return resp
    elif fmt == "csv":
        body = _as_delimited(rows, ",")
        resp = make_response(body)
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = "attachment; filename=iocs.csv"
        return resp
    elif fmt == "tsv":
        body = _as_delimited(rows, "\t")
        resp = make_response(body)
        resp.headers["Content-Type"] = "text/tab-separated-values; charset=utf-8"
        resp.headers["Content-Disposition"] = "attachment; filename=iocs.tsv"
        return resp
    return make_response("Unsupported format", 400)

@webui_bp.get("/download/unified.<fmt>")
def download_unified(fmt: str):
    q = request.args.get("q") or None
    types = _split_csv(request.args.get("types"))
    sources = _split_csv(request.args.get("sources"))
    tlps = _split_csv(request.args.get("tlps"))
    active_only = _active_only(request.args.get("active_only", "1"))
    limit = int(request.args.get("limit", "5000"))
    offset = int(request.args.get("offset", "0"))
    return _download_common(fmt, q, types, sources, tlps, active_only, limit, offset)

@webui_bp.get("/download/mobile.<fmt>")
def download_mobile(fmt: str):
    q = request.args.get("q") or None
    sources = _split_csv(request.args.get("sources"))
    tlps = _split_csv(request.args.get("tlps"))
    active_only = _active_only(request.args.get("active_only", "1"))
    limit = int(request.args.get("limit", "5000"))
    offset = int(request.args.get("offset", "0"))
    return _download_common(fmt, q, ["apk","ios"], sources, tlps, active_only, limit, offset)
