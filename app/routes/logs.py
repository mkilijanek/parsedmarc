from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from flask import jsonify, make_response, render_template, request
from sqlalchemy import select


_CEF_SEVERITY = {"INFO": "0", "DEBUG": "0", "WARNING": "5", "WARN": "5", "ERROR": "8", "CRITICAL": "10"}


def _cef_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _build_filter_stmt(AppLog, request_args):
    stmt = select(AppLog).order_by(AppLog.created_at.desc())
    feed = (request_args.get("feed") or "").strip()
    job_id = (request_args.get("job_id") or request_args.get("run_id") or "").strip()
    level = (request_args.get("level") or "").strip().upper()
    component = (request_args.get("component") or "").strip()
    since = (request_args.get("since") or "").strip()
    until = (request_args.get("until") or "").strip()
    if feed:
        stmt = stmt.where(AppLog.feed_source_id == feed)
    if job_id:
        stmt = stmt.where(AppLog.run_id == job_id)
    if level:
        levels = [l.strip() for l in level.replace(",", "|").split("|") if l.strip()]
        if len(levels) == 1:
            stmt = stmt.where(AppLog.level == levels[0])
        else:
            stmt = stmt.where(AppLog.level.in_(levels))
    if component:
        stmt = stmt.where(AppLog.component == component)
    if since:
        try:
            stmt = stmt.where(AppLog.created_at >= datetime.fromisoformat(since.replace("Z", "+00:00")))
        except ValueError:
            pass
    if until:
        try:
            stmt = stmt.where(AppLog.created_at <= datetime.fromisoformat(until.replace("Z", "+00:00")))
        except ValueError:
            pass
    return stmt


def register_logs_routes(
    app,
    *,
    limiter,
    cfg,
    logger: logging.Logger,
    deps: Dict[str, Any],
) -> None:
    _db = deps["_db"]
    AppLog = deps["AppLog"]

    @app.get("/api/logs")
    @limiter.limit("60 per minute")
    def api_logs():
        db = _db(read_only=True)
        try:
            stmt = _build_filter_stmt(AppLog, request.args)
            limit = min(500, max(1, int(request.args.get("limit", "200"))))
            rows = list(db.scalars(stmt.limit(limit)).all())
            fmt = (request.args.get("format") or "json").strip().lower()
            if fmt == "cef":
                lines = []
                for r in rows:
                    sev = _CEF_SEVERITY.get((r.level or "INFO").upper(), "0")
                    ext = (
                        f"rt={r.created_at} "
                        f"cs1Label=component cs1={_cef_escape(r.component or '')} "
                        f"cs2Label=feed cs2={_cef_escape(r.feed_source_id or '')} "
                        f"cs3Label=run_id cs3={_cef_escape(r.run_id or '')} "
                        f"msg={_cef_escape(r.message or '')}"
                    )
                    action = _cef_escape(r.level or "INFO")
                    lines.append(f"CEF:0|ioc-service|app|1.0|{action}|{action}|{sev}|{ext}")
                resp = make_response("\n".join(lines) + "\n" if lines else "")
                resp.content_type = "text/plain; charset=utf-8"
                return resp
            return jsonify(
                {
                    "count": len(rows),
                    "items": [
                        {
                            "created_at": str(r.created_at),
                            "level": r.level,
                            "component": r.component,
                            "message": r.message,
                            "feed_source_id": r.feed_source_id,
                            "run_id": r.run_id,
                            "metadata": r.metadata_,
                        }
                        for r in rows
                    ],
                }
            )
        finally:
            db.close()

    @app.get("/api/logs/export")
    @limiter.limit("10 per minute")
    def api_logs_export():
        """Integrity-checksummed bulk log export for compliance/SIEM archival."""
        db = _db(read_only=True)
        try:
            stmt = _build_filter_stmt(AppLog, request.args)
            limit = min(5000, max(1, int(request.args.get("limit", "1000"))))
            rows = list(db.scalars(stmt.limit(limit)).all())
            items = [
                {
                    "created_at": str(r.created_at),
                    "level": r.level,
                    "component": r.component,
                    "message": r.message,
                    "feed_source_id": r.feed_source_id,
                    "run_id": r.run_id,
                    "metadata": r.metadata_,
                }
                for r in rows
            ]
            payload = {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "count": len(items),
                "items": items,
            }
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
            checksum = hashlib.sha256(body.encode("utf-8")).hexdigest()
            payload["export_checksum"] = f"sha256:{checksum}"
            final_body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
            resp = make_response(final_body)
            resp.content_type = "application/json; charset=utf-8"
            resp.headers["X-Export-Checksum"] = f"sha256:{checksum}"
            return resp
        finally:
            db.close()

    @app.get("/logs")
    @limiter.limit("30 per minute")
    def logs_page():
        return render_template("logs.html")
