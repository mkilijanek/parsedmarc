from __future__ import annotations

import hmac
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List

from flask import Response, jsonify, make_response, redirect, request, send_file, stream_with_context, url_for
from sqlalchemy import func, select


def _runtime_attr(name: str, default: Any) -> Any:
    main_mod = sys.modules.get("app.main")
    if main_mod is not None and hasattr(main_mod, name):
        return getattr(main_mod, name)
    return default


def register_public_routes(
    app,
    *,
    limiter,
    cfg,
    logger: logging.Logger,
    deps: Dict[str, Any],
) -> None:
    _db = deps["_db"]
    _audit = deps["_audit"]
    _cache_key = deps["_cache_key"]
    _count_indicators = deps["_count_indicators"]
    _parse_limit_offset = deps["_parse_limit_offset"]
    _persist_export_job = deps["_persist_export_job"]
    _query_indicators = deps["_query_indicators"]
    _refresh_job_backlog_metrics = deps["_refresh_job_backlog_metrics"]
    _render_export_body = deps["_render_export_body"]
    _render_index = deps["_render_index"]
    _render_indicators = deps["_render_indicators"]
    _spawn_export_job = deps["_spawn_export_job"]
    get_redis = deps["get_redis"]
    _admin_token_authorized = deps["_admin_token_authorized"]
    validate_search_query = deps["validate_search_query"]
    Indicator = deps["Indicator"]
    FeedStats = deps["FeedStats"]
    ExportJob = deps["ExportJob"]
    FORMATTERS = deps["FORMATTERS"]
    DB_SUPPORTED_FORMATS = deps["DB_SUPPORTED_FORMATS"]
    query_correlations = deps["query_correlations"]
    active_indicators = deps["active_indicators"]
    generate_latest = deps["generate_latest"]
    CONTENT_TYPE_LATEST = deps["CONTENT_TYPE_LATEST"]
    correlation_queries_total = deps["correlation_queries_total"]
    correlation_query_duration_seconds = deps["correlation_query_duration_seconds"]
    correlation_groups_returned_total = deps["correlation_groups_returned_total"]
    cache_access_total = deps["cache_access_total"]
    db_query_duration_seconds = deps["db_query_duration_seconds"]

    @app.get("/metrics")
    @limiter.limit("30 per minute")
    def metrics():
        if cfg.METRICS_AUTH_TOKEN:
            auth = (request.headers.get("Authorization") or "").strip()
            expected = f"Bearer {cfg.METRICS_AUTH_TOKEN}"
            if not hmac.compare_digest(auth, expected):
                return jsonify({"error": "Unauthorized"}), 401
        _refresh_job_backlog_metrics()
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    @app.get("/")
    def index():
        db = _db(read_only=True)
        try:
            total = db.scalar(select(func.count()).select_from(Indicator))
            active = db.scalar(select(func.count()).select_from(Indicator).where(Indicator.is_active == True))  # noqa: E712
            active_indicators.set(int(active or 0))
            feeds = db.scalars(select(FeedStats).order_by(FeedStats.last_update.desc())).all()
        finally:
            db.close()

        html = _render_index(total or 0, active or 0, feeds)
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp

    @app.get("/indicators")
    @limiter.limit("20 per minute")
    def indicators_view():
        q = request.args.get("q", "").strip() or None
        if q and not validate_search_query(q):
            return jsonify({"error": "Invalid query"}), 400

        type_filter = (request.args.get("type") or "all").lower()
        tlp = (request.args.get("tlp") or "all").upper()
        source = (request.args.get("source") or "all").lower()
        try:
            raw_min_conf = request.args.get("min_conf")
            raw_max_conf = request.args.get("max_conf")
            min_conf = request.args.get("min_conf", type=int)
            max_conf = request.args.get("max_conf", type=int)
            if raw_min_conf is not None and raw_min_conf.strip() != "" and min_conf is None:
                raise ValueError("min_conf")
            if raw_max_conf is not None and raw_max_conf.strip() != "" and max_conf is None:
                raise ValueError("max_conf")
        except ValueError:
            return jsonify({"error": "min_conf/max_conf must be integers"}), 400
        limit, offset = _parse_limit_offset(default_limit=1000, max_limit=max(1, cfg.QUERY_RESULT_LIMIT_MAX))
        if limit is None or offset is None:
            return jsonify({"error": "limit/offset must be integers"}), 400

        cache_key = _cache_key(
            "indicators_html",
            q=q or "",
            type=type_filter,
            tlp=tlp,
            source=source,
            min=min_conf,
            max=max_conf,
            limit=limit,
            offset=offset,
        )
        r = None
        cached = None
        try:
            r = _runtime_attr("get_redis", get_redis)()
            cached = r.get(cache_key)
        except Exception:
            cache_access_total.labels(endpoint="indicators_html", status="error").inc()
            logger.warning("cache_unavailable", extra={"endpoint": "indicators_html"})

        if cached:
            cache_access_total.labels(endpoint="indicators_html", status="hit").inc()
            resp = make_response(cached)
            resp.headers["Content-Type"] = "text/html; charset=utf-8"
            return resp
        cache_access_total.labels(endpoint="indicators_html", status="miss").inc()

        source_options: List[str] = ["all"]
        total_count = 0
        db = _db(read_only=True)
        try:
            with db_query_duration_seconds.labels(endpoint="indicators_view").time():
                rows = _query_indicators(db, q, type_filter, tlp, source, min_conf, max_conf, limit=limit, offset=offset)
                total_count = _count_indicators(db, q, type_filter, tlp, source, min_conf, max_conf)
            available_sources = db.scalars(select(Indicator.source).distinct().order_by(Indicator.source.asc())).all()
            source_options.extend([str(s) for s in available_sources if s and str(s) != "all"])
            if source not in source_options:
                source_options.append(source)
        except Exception:
            logger.exception("indicators_view_query_failed")
            return jsonify({"error": "Query failed"}), 400
        finally:
            try:
                db.close()
            except Exception:
                pass

        _audit("query", "indicator", None, {"q": q, "type": type_filter, "tlp": tlp, "source": source})

        html = _render_indicators(
            rows,
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
        )
        if r is not None:
            try:
                r.setex(cache_key, cfg.CACHE_TTL, html)
            except Exception:
                cache_access_total.labels(endpoint="indicators_html", status="error").inc()
                logger.warning("cache_write_failed", extra={"endpoint": "indicators_html"})
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp

    @app.get("/sources/<src>")
    @limiter.limit("30 per minute")
    def indicators_by_source(src: str):
        src = (src or "").strip().lower()
        if not src or any(c in src for c in [" ", "\t", "\n", "\r", "/", "\\"]):
            return jsonify({"error": "Invalid source"}), 400
        return redirect(url_for("indicators_view", source=src))

    @app.get("/correlations")
    @limiter.limit("20 per minute")
    def correlations():
        try:
            min_sources = int(request.args.get("min_sources", "2"))
            limit = int(request.args.get("limit", "1000"))
        except ValueError:
            correlation_queries_total.labels(status="error").inc()
            return jsonify({"error": "min_sources/limit must be integers"}), 400
        ioc_type = (request.args.get("type") or "all").lower()
        if ioc_type not in {"all", "ip", "domain", "url", "hash", "email", "object_id"}:
            correlation_queries_total.labels(status="error").inc()
            return jsonify({"error": "invalid type"}), 400

        cache_key = _cache_key(
            "correlations",
            min_sources=max(2, min_sources),
            limit=min(limit, max(1, cfg.CORRELATION_LIMIT_MAX)),
            type=ioc_type,
        )
        r = None
        try:
            r = _runtime_attr("get_redis", get_redis)()
            cached = r.get(cache_key)
            if isinstance(cached, (str, bytes, bytearray)) and len(cached) > 0:
                cache_access_total.labels(endpoint="correlations", status="hit").inc()
                return Response(cached, mimetype="application/json")
            cache_access_total.labels(endpoint="correlations", status="miss").inc()
        except Exception:
            cache_access_total.labels(endpoint="correlations", status="error").inc()

        db = _db(read_only=True)
        try:
            with correlation_query_duration_seconds.time():
                with db_query_duration_seconds.labels(endpoint="correlations").time():
                    groups = _runtime_attr("query_correlations", query_correlations)(
                        db,
                        min_sources=min_sources,
                        limit=min(limit, max(1, cfg.CORRELATION_LIMIT_MAX)),
                        ioc_type=ioc_type,
                    )
            correlation_queries_total.labels(status="success").inc()
            correlation_groups_returned_total.inc(len(groups))
            payload = {
                "count": len(groups),
                "min_sources": max(2, min_sources),
                "type": ioc_type,
                "limit": min(limit, max(1, cfg.CORRELATION_LIMIT_MAX)),
                "items": groups,
            }
            body = json.dumps(payload, separators=(",", ":"))
            if r is not None:
                try:
                    r.setex(cache_key, max(1, cfg.CORRELATION_CACHE_TTL), body)
                except Exception:
                    cache_access_total.labels(endpoint="correlations", status="error").inc()
            return Response(body, mimetype="application/json")
        except Exception:
            correlation_queries_total.labels(status="error").inc()
            raise
        finally:
            db.close()

    @app.get("/indicators/<fmt>")
    @limiter.limit("30 per minute")
    def export_indicators(fmt: str):
        fmt = fmt.lower()
        if fmt not in FORMATTERS and fmt not in DB_SUPPORTED_FORMATS:
            return jsonify({"error": "Unknown format"}), 404

        q = request.args.get("q", "").strip() or None
        if q and not validate_search_query(q):
            return jsonify({"error": "Invalid query"}), 400

        type_filter = (request.args.get("type") or "all").lower()
        tlp = (request.args.get("tlp") or "all").upper()
        source = (request.args.get("source") or "all").lower()
        stream = (request.args.get("stream") or "").strip().lower() in {"1", "true", "yes"}
        async_export = (request.args.get("async") or "").strip().lower() in {"1", "true", "yes"}
        limit, offset = _parse_limit_offset(default_limit=100000, max_limit=max(1, cfg.EXPORT_RESULT_LIMIT_MAX))
        if limit is None or offset is None:
            return jsonify({"error": "limit/offset must be integers"}), 400

        cache_key = _cache_key(
            "export",
            fmt=fmt,
            q=q or "",
            type=type_filter,
            tlp=tlp,
            source=source,
            limit=limit,
            offset=offset,
        )
        auto_async = (request.args.get("auto_async") or "").strip().lower() in {"1", "true", "yes"}
        if async_export or (auto_async and limit >= max(1, cfg.EXPORT_ASYNC_THRESHOLD)):
            job_id = uuid.uuid4().hex
            params = {
                "q": q,
                "type_filter": type_filter,
                "tlp": tlp,
                "source": source,
                "limit": limit,
                "offset": offset,
            }
            _persist_export_job(job_id, fmt, params)
            _spawn_export_job(job_id)
            return (
                jsonify(
                    {
                        "job_id": job_id,
                        "status_url": url_for("export_job_status", job_id=job_id, _external=False),
                        "download_url": url_for("export_job_download", job_id=job_id, _external=False),
                    }
                ),
                202,
            )

        r = None
        cached = None
        try:
            r = _runtime_attr("get_redis", get_redis)()
            cached = r.get(cache_key)
        except Exception:
            cache_access_total.labels(endpoint=f"export_{fmt}", status="error").inc()
            logger.warning("cache_unavailable", extra={"endpoint": f"export_{fmt}"})
        if cached:
            cache_access_total.labels(endpoint=f"export_{fmt}", status="hit").inc()
            _, mime = FORMATTERS[fmt]
            resp = make_response(cached)
            resp.headers["Content-Type"] = mime
            return resp
        cache_access_total.labels(endpoint=f"export_{fmt}", status="miss").inc()

        db = _db(read_only=True)
        try:
            with db_query_duration_seconds.labels(endpoint=f"export_{fmt}").time():
                rows = _query_indicators(db, q, type_filter, tlp, source, None, None, limit=limit, offset=offset)
        except Exception:
            db.close()
            logger.exception("export_query_failed")
            return jsonify({"error": "Query failed"}), 400
        finally:
            try:
                db.close()
            except Exception:
                pass

        body, mime = _render_export_body(fmt, rows)
        _audit("export", "indicator", None, {"fmt": fmt, "count": len(rows), "q": q})
        if not stream and r is not None:
            try:
                r.setex(cache_key, cfg.CACHE_TTL, body)
            except Exception:
                cache_access_total.labels(endpoint=f"export_{fmt}", status="error").inc()
                logger.warning("cache_write_failed", extra={"endpoint": f"export_{fmt}"})
        if stream and fmt in {"elasticsearch", "cribl"}:
            def _iter():
                for line in body.splitlines(True):
                    yield line

            return Response(stream_with_context(_iter()), mimetype=mime)
        resp = make_response(body)
        resp.headers["Content-Type"] = mime
        return resp

    @app.get("/export-jobs/<job_id>")
    @limiter.limit("60 per minute")
    def export_job_status(job_id: str):
        db = _db(read_only=True)
        try:
            job = db.scalar(select(ExportJob).where(ExportJob.job_id == job_id))
            if not job:
                return jsonify({"error": "job not found"}), 404
            payload = {
                "job_id": job.job_id,
                "format": job.fmt,
                "status": job.status,
                "error": job.error,
                "download_url": url_for("export_job_download", job_id=job.job_id, _external=False),
            }
            return jsonify(payload)
        finally:
            db.close()

    @app.post("/api/sentinel/export")
    @limiter.limit("20 per minute")
    def sentinel_graph_export():
        if not _admin_token_authorized():
            return jsonify({"error": "Unauthorized", "hint": "Pass admin token in X-Admin-Token header"}), 401
        q = request.args.get("q", "").strip() or None
        type_filter = (request.args.get("type") or "all").lower()
        tlp = (request.args.get("tlp") or "all").upper()
        source = (request.args.get("source") or "all").lower()
        min_conf = request.args.get("min_conf", type=int)
        max_conf = request.args.get("max_conf", type=int)
        limit, offset = _parse_limit_offset(default_limit=10000, max_limit=max(1, cfg.EXPORT_RESULT_LIMIT_MAX))
        if limit is None or offset is None:
            return jsonify({"error": "limit/offset must be integers"}), 400

        job_id = uuid.uuid4().hex
        params = {
            "q": q,
            "type_filter": type_filter,
            "tlp": tlp,
            "source": source,
            "min_conf": min_conf,
            "max_conf": max_conf,
            "limit": limit,
            "offset": offset,
            "chunk_size": request.args.get("chunk_size", type=int),
        }
        _persist_export_job(job_id, "sentinel_graph", params)
        _spawn_export_job(job_id)
        return (
            jsonify(
                {
                    "job_id": job_id,
                    "status_url": url_for("export_job_status", job_id=job_id, _external=False),
                    "download_url": url_for("export_job_download", job_id=job_id, _external=False),
                }
            ),
            202,
        )

    @app.get("/export-jobs/<job_id>/download")
    @limiter.limit("30 per minute")
    def export_job_download(job_id: str):
        db = _db(read_only=True)
        try:
            job = db.scalar(select(ExportJob).where(ExportJob.job_id == job_id))
            if not job:
                return jsonify({"error": "job not found"}), 404
            if job.status != "completed" or not job.result_path:
                return jsonify({"error": "job not completed", "status": job.status}), 409
            p = Path(job.result_path)
            if not p.exists():
                return jsonify({"error": "artifact missing"}), 410
            _, mime = FORMATTERS.get(job.fmt, (None, "application/octet-stream"))
            return send_file(p, mimetype=mime, as_attachment=True, download_name=f"indicators.{job.fmt}")
        finally:
            db.close()

    @app.get("/misp/event/<event_id>/<ioc_type>/<fmt>")
    @limiter.limit("30 per minute")
    def export_misp_event(event_id: str, ioc_type: str, fmt: str):
        fmt = fmt.lower()
        if fmt not in FORMATTERS:
            return jsonify({"error": "Unknown format"}), 404

        ioc_type = ioc_type.lower()
        if ioc_type not in {"ip", "domain", "url", "hash", "email", "all"}:
            return jsonify({"error": "Unknown ioc_type"}), 400

        db = _db(read_only=True)
        try:
            stmt = select(Indicator).where(
                Indicator.is_active == True,  # noqa: E712
                Indicator.source == "misp",
                Indicator.source_id == event_id,
            )
            if ioc_type != "all":
                stmt = stmt.where(Indicator.type == ioc_type)
            rows = list(db.scalars(stmt.order_by(Indicator.last_seen.desc()).limit(100000)).all())
        finally:
            db.close()

        func_, mime = FORMATTERS[fmt]
        body = func_(rows)  # type: ignore[misc]
        _audit("export", "indicator", None, {"fmt": fmt, "count": len(rows), "event_id": event_id, "type": ioc_type})
        resp = make_response(body)
        resp.headers["Content-Type"] = mime
        return resp

    @app.get("/crowdsec/list/<list_id>/<fmt>")
    @limiter.limit("30 per minute")
    def export_crowdsec_list(list_id: str, fmt: str):
        fmt = fmt.lower()
        if fmt not in FORMATTERS:
            return jsonify({"error": "Unknown format"}), 404
        db = _db(read_only=True)
        try:
            stmt = select(Indicator).where(
                Indicator.is_active == True,  # noqa: E712
                Indicator.source == "crowdsec",
                Indicator.source_id == list_id,
            )
            rows = list(db.scalars(stmt.order_by(Indicator.last_seen.desc()).limit(100000)).all())
        finally:
            db.close()
        func_, mime = FORMATTERS[fmt]
        body = func_(rows)  # type: ignore[misc]
        _audit("export", "indicator", None, {"fmt": fmt, "count": len(rows), "list_id": list_id})
        resp = make_response(body)
        resp.headers["Content-Type"] = mime
        return resp

    @app.get("/misp/event/<event_id>")
    @limiter.limit("30 per minute")
    def misp_event_redirect(event_id: str):
        if not cfg.MISP_URL:
            return jsonify({"error": "MISP_URL not configured"}), 400
        return ("", 302, {"Location": f"{cfg.MISP_URL.rstrip('/')}/events/view/{event_id}"})
