from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, jsonify, request, make_response, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import select, func, and_, or_, text
from sqlalchemy.orm import Session

from .config import Config
from .webui import webui_bp
from .logging import setup_logging
from .db import SessionLocal
from .models import Indicator, FeedStats, AuditLog, tags_contains
from .cache import get_redis
from .security import validate_search_query, enforce_allowed_hosts, get_client_ip
from .query_parser import parse_kibana_query, Term, Token
from .formatters import FORMATTERS

from .metrics import request_count, request_duration, active_indicators, generate_latest, CONTENT_TYPE_LATEST

logger = logging.getLogger(__name__)

SUPPORTED_FIELDS = {"value","type","confidence","tlp","tags","source"}
# Database-native export formats (formats supported by ti.export_indicators SQL function)
DB_SUPPORTED_FORMATS = {"txt", "csv", "json"}

def create_app() -> Flask:
    cfg = Config()
    setup_logging(cfg.LOG_LEVEL)

    app = Flask(__name__)
    app.config["SECRET_KEY"] = cfg.SECRET_KEY

    # SECURITY: Secure session cookie configuration
    app.config["SESSION_COOKIE_SECURE"] = True  # Only send over HTTPS
    app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript access
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour session

    # Web UI blueprint
    app.register_blueprint(webui_bp)

    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri=cfg.REDIS_URL,
        default_limits=["60 per minute"],
    )

    @app.before_request
    def _sec_headers():
        enforce_allowed_hosts()

    @app.after_request
    def _add_headers(resp: Response) -> Response:
        # SECURITY: Defense-in-depth security headers
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("X-XSS-Protection", "1; mode=block")
        # CSP: Allow same origin for scripts/styles, block everything else by default
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'"
        )
        # HSTS: Force HTTPS for 1 year (should be set by reverse proxy, but adding here too)
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # Permissions Policy: Disable unnecessary browser features
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return resp

    @app.before_request
    def _metrics_start():
        request._t0 = time.time()

    @app.after_request
    def _metrics_end(resp: Response):
        endpoint = request.endpoint or "unknown"
        dur = max(0.0, time.time() - getattr(request, "_t0", time.time()))
        request_duration.labels(endpoint=endpoint).observe(dur)
        request_count.labels(method=request.method, endpoint=endpoint, http_status=str(resp.status_code)).inc()
        return resp

    def _db() -> Session:
        return SessionLocal()

    def _audit(action: str, entity_type: str | None = None, entity_id: int | None = None, metadata: dict | None = None) -> None:
        db = _db()
        try:
            # SECURITY: Use safe IP extraction that respects proxy configuration
            client_ip = get_client_ip()
            db.add(AuditLog(
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                user_id=None,
                ip_address=client_ip,
                metadata=metadata or {},
            ))
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    def _cache_key(prefix: str, **parts: Any) -> str:
        # stable ordering
        segs = [prefix] + [f"{k}={parts[k]}" for k in sorted(parts.keys())]
        return "|".join(segs)

    def _apply_term(db: Session, term: Term):
        field = term.field
        op = term.op
        value = term.value

        # Field normalization
        field_l = field.lower()
        if field_l not in SUPPORTED_FIELDS:
            raise ValueError(f"Unsupported field: {field}")

        col = {
            "value": Indicator.value,
            "type": Indicator.type,
            "confidence": Indicator.confidence,
            "tlp": Indicator.tlp,
            "source": Indicator.source,
            "tags": Indicator.tags,
        }[field_l]

        # Wildcards: * and ? (SQL ILIKE with % and _)
        def wildcard_to_like(v: str) -> str:
            v = v.replace('%', '\\%').replace('_', '\\_')
            v = v.replace('*', '%').replace('?', '_')
            return v

        if field_l == "confidence":
            try:
                n = int(value)
            except ValueError:
                raise ValueError("confidence must be integer")
            if op == ":":
                return col == n
            if op == ">": return col > n
            if op == "<": return col < n
            if op == ">=": return col >= n
            if op == "<=": return col <= n
            raise ValueError("Invalid operator for confidence")

        if field_l == "tags":
            # tags:foo => array contains foo (case-insensitive compare by normalizing in query)
            # For simplicity we compare exact; upstream sources usually consistent.
            if op != ":":
                raise ValueError("tags only supports ':' operator")
            return tags_contains(col, value)

        # Text fields: tlp/type/source/value
        if op != ":":
            raise ValueError(f"Invalid operator for field {field_l}")
        # If wildcard present, use ILIKE
        if '*' in value or '?' in value:
            like = wildcard_to_like(value)
            return col.ilike(like, escape='\\')
        return col == value

    def _rpn_to_filter(db: Session, rpn: List[Token]):
        stack: List[Any] = []
        for tok in rpn:
            if isinstance(tok, Term):
                stack.append(_apply_term(db, tok))
            elif tok == "NOT":
                if not stack:
                    raise ValueError("NOT without operand")
                a = stack.pop()
                stack.append(~a)
            elif tok in {"AND","OR"}:
                if len(stack) < 2:
                    raise ValueError(f"{tok} without operands")
                b = stack.pop()
                a = stack.pop()
                stack.append(and_(a,b) if tok == "AND" else or_(a,b))
            else:
                raise ValueError("Unexpected token in RPN")
        if len(stack) != 1:
            raise ValueError("Invalid query")
        return stack[0]

    def _query_indicators(
        db: Session,
        q: str | None,
        type_filter: str | None,
        tlp: str | None,
        source: str | None,
        min_conf: int | None,
        max_conf: int | None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[Indicator]:
        stmt = select(Indicator).where(Indicator.is_active == True)  # noqa: E712
        if q:
            rpn = parse_kibana_query(q)
            stmt = stmt.where(_rpn_to_filter(db, rpn))
        if type_filter and type_filter != "all":
            stmt = stmt.where(Indicator.type == type_filter)
        if tlp and tlp != "ALL":
            stmt = stmt.where(Indicator.tlp == tlp)
        if source and source != "all":
            stmt = stmt.where(Indicator.source == source)
        if min_conf is not None:
            stmt = stmt.where(Indicator.confidence >= min_conf)
        if max_conf is not None:
            stmt = stmt.where(Indicator.confidence <= max_conf)
        stmt = stmt.order_by(Indicator.last_seen.desc()).limit(limit).offset(offset)
        return list(db.scalars(stmt).all())

    @app.get("/metrics")
    @limiter.limit("30 per minute")
    def metrics():
        # No auth in spec; deploy behind internal network/VPN if needed.
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    @app.get("/health")
    @limiter.limit("60 per minute")
    def health():
        cfg = Config()
        checks = {"database": False, "redis": False, "misp": False, "crowdsec": False}
        # DB check
        try:
            db = _db()
            db.execute(select(func.now()))
            checks["database"] = True
        except Exception:
            checks["database"] = False
        finally:
            try:
                db.close()
            except Exception:
                pass
        # Redis check
        try:
            r = get_redis()
            r.ping()
            checks["redis"] = True
        except Exception:
            checks["redis"] = False
        # MISP check (lightweight)
        if cfg.MISP_URL and cfg.MISP_API_KEY:
            try:
                from pymisp import PyMISP
                m = PyMISP(cfg.MISP_URL, cfg.MISP_API_KEY, ssl=cfg.MISP_VERIFY_SSL)
                # server version call
                _ = m.server_settings()
                checks["misp"] = True
            except Exception:
                checks["misp"] = False
        else:
            checks["misp"] = False
        # CrowdSec check (auth header present)
        checks["crowdsec"] = bool(cfg.CROWDSEC_API_KEY)

        status = "healthy" if all(checks.values()) else "degraded"
        return jsonify({"status": status, "checks": checks})

    @app.get("/")
    def index():
        db = _db()
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
            min_conf = int(request.args.get("min_conf")) if request.args.get("min_conf") else None
            max_conf = int(request.args.get("max_conf")) if request.args.get("max_conf") else None
        except ValueError:
            return jsonify({"error": "min_conf/max_conf must be integers"}), 400

        # Cache HTML response by params
        cfg = Config()
        cache_key = _cache_key("indicators_html", q=q or "", type=type_filter, tlp=tlp, source=source, min=min_conf, max=max_conf)
        r = get_redis()
        cached = r.get(cache_key)
        if cached:
            resp = make_response(cached)
            resp.headers["Content-Type"] = "text/html; charset=utf-8"
            return resp

        db = _db()
        try:
            rows = _query_indicators(db, q, type_filter, tlp, source, min_conf, max_conf, limit=1000, offset=0)
        except Exception as e:
            db.close()
            return jsonify({"error": str(e)}), 400
        finally:
            try:
                db.close()
            except Exception:
                pass

        _audit("query", "indicator", None, {"q": q, "type": type_filter, "tlp": tlp, "source": source})

        html = _render_indicators(rows, q=q, type_filter=type_filter, tlp=tlp, source=source, min_conf=min_conf, max_conf=max_conf)
        r.setex(cache_key, cfg.CACHE_TTL, html)
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp

    
    @app.get("/sources/<src>")
    @limiter.limit("30 per minute")
    def indicators_by_source(src: str):
        # Dedicated endpoint: shortcut to /indicators with source preselected.
        src = (src or "").strip().lower()
        if not src or any(c in src for c in [' ', '\t', '\n', '\r', '/', '\\']):
            return jsonify({"error": "Invalid source"}), 400
        return redirect(url_for("indicators_view", source=src))

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

        mime_map = {
            "txt": "text/plain; charset=utf-8",
            "csv": "text/csv; charset=utf-8",
            "tsv": "text/tab-separated-values; charset=utf-8",
            "json": "application/json; charset=utf-8",
            "elasticsearch": "application/x-ndjson; charset=utf-8",
            "cribl": "application/x-ndjson; charset=utf-8",
            "splunk": "application/json; charset=utf-8",
            "arcsight": "text/plain; charset=utf-8",
            "fidelis": "application/json; charset=utf-8",
        }

        cfg = Config()
        cache_key = _cache_key("export", fmt=fmt, q=q or "", type=type_filter, tlp=tlp, source=source)
        r = get_redis()
        cached = r.get(cache_key)
        if cached:
            func_, mime = FORMATTERS[fmt]
            resp = make_response(cached)
            resp.headers["Content-Type"] = mime
            return resp

        db = _db()
        try:
            rows = _query_indicators(db, q, type_filter, tlp, source, None, None, limit=100000, offset=0)
        except Exception as e:
            db.close()
            return jsonify({"error": str(e)}), 400
        finally:
            try:
                db.close()
            except Exception:
                pass

        func_, mime = FORMATTERS[fmt]
        # Some formatters accept extra args; handle via simple arity check
        try:
            if fmt == "elasticsearch":
                body = func_(rows)  # type: ignore[arg-type]
            else:
                body = func_(rows)  # type: ignore[misc]
        except TypeError:
            body = func_(rows)  # fallback

        _audit("export", "indicator", None, {"fmt": fmt, "count": len(rows), "q": q})
        r.setex(cache_key, cfg.CACHE_TTL, body)
        resp = make_response(body)
        resp.headers["Content-Type"] = mime
        return resp

    
    @app.get("/misp/event/<event_id>/<ioc_type>/<fmt>")
    @limiter.limit("30 per minute")
    def export_misp_event(event_id: str, ioc_type: str, fmt: str):
        """Per-event export, matches UI examples.

        URL schema: /misp/event/<event_id>/<ioc_type>/<fmt>
        Example: /misp/event/123/ip/csv
        """
        fmt = fmt.lower()
        if fmt not in FORMATTERS:
            return jsonify({"error": "Unknown format"}), 404

        ioc_type = ioc_type.lower()
        if ioc_type not in {"ip","domain","url","hash","email","all"}:
            return jsonify({"error": "Unknown ioc_type"}), 400

        db = _db()
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
        db = _db()
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
        cfg = Config()
        if not cfg.MISP_URL:
            return jsonify({"error": "MISP_URL not configured"}), 400
        # Clickable link target is shown in UI; redirect for convenience
        return ("", 302, {"Location": f"{cfg.MISP_URL.rstrip('/')}/events/view/{event_id}"})

    return app

# ---------- HTML rendering (no external templates, minimal dependencies) ----------

def _esc(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _badge(label: str, cls: str, aria: str) -> str:
    return f"<span class='badge {cls}' aria-label='{_esc(aria)}'>{_esc(label)}</span>"

def _render_index(total: int, active: int, feeds) -> str:
    feed_rows = "".join([
        f"<tr role='row'><td role='cell'>{_esc(f.source)}</td><td role='cell'>{_esc(str(f.source_id or ''))}</td><td role='cell'>{_esc(str(f.last_fetch_status or ''))}</td><td role='cell'>{_esc(str(f.last_update or ''))}</td></tr>"
        for f in feeds
    ])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Threat Feed Aggregator</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 1.5rem; }}
    .card {{ border: 1px solid #ddd; border-radius: 16px; padding: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,.06); margin-bottom: 1rem; }}
    a {{ color: #0b5; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #eee; padding: 0.5rem; text-align: left; }}
    .skip-link {{ position: absolute; left: -9999px; top: auto; width: 1px; height: 1px; overflow: hidden; }}
    .skip-link:focus {{ left: 1rem; top: 1rem; width: auto; height: auto; background: #fff; padding: .5rem; border: 1px solid #000; }}
  </style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<main id="main-content" role="main">
  <div class="card" role="region" aria-label="System overview">
    <h1>Threat Feed Aggregator</h1>
    <p>Total indicators: <strong>{total}</strong> | Active: <strong>{active}</strong></p>
    <p><a href="/indicators" aria-label="Open unified indicators view">Open /indicators</a></p>
    <p>Exports: 
      <a href="/indicators/txt">TXT</a> · <a href="/indicators/csv">CSV</a> · <a href="/indicators/json">JSON</a> · <a href="/indicators/fortigate">FortiGate</a> ·
      <a href="/indicators/arcsight">ArcSight</a> · <a href="/indicators/elasticsearch">Elasticsearch</a> · <a href="/indicators/splunk">Splunk</a>
    </p>
  </div>

  <div class="card" role="region" aria-label="Feed statistics">
    <h2>Feed stats</h2>
    <table role="table" aria-label="Feed statistics table">
      <thead>
        <tr role="row">
          <th role="columnheader">Source</th>
          <th role="columnheader">Source ID</th>
          <th role="columnheader">Last status</th>
          <th role="columnheader">Last update</th>
        </tr>
      </thead>
      <tbody>
        {feed_rows}
      </tbody>
    </table>
  </div>
</main>
</body>
</html>
"""

def _render_indicators(rows: List[Indicator], *, q: str | None, type_filter: str, tlp: str, source: str, min_conf: int | None, max_conf: int | None) -> str:
    def type_badge(t: str) -> str:
        cls = {"ip":"b-ip","domain":"b-domain","url":"b-url","hash":"b-hash","email":"b-email"}.get(t,"b-other")
        return _badge(t, cls, f"Type {t}")
    def tlp_badge(t: str) -> str:
        cls = {"WHITE":"b-white","GREEN":"b-green","AMBER":"b-amber","RED":"b-red"}.get(t,"b-green")
        return _badge(t, cls, f"TLP {t}")

    rows_html = []
    for ind in rows:
        conf = int(ind.confidence or 0)
        bar = f"<div class='confbar' role='progressbar' aria-valuenow='{conf}' aria-valuemin='0' aria-valuemax='100' aria-label='Confidence {conf} percent'><div class='confbar-in' style='width:{conf}%'></div></div>"
        tags = " ".join([f"<span class='tag' aria-label='Tag {_esc(t)}'>{_esc(t)}</span>" for t in (ind.tags or [])][:10])
        misp_link = ""
        if ind.source == "misp" and ind.source_id:
            misp_link = f"<a href='/misp/event/{_esc(ind.source_id)}' aria-label='Open MISP event {ind.source_id}'>Event {ind.source_id}</a>"

        # Per-row quick exports (required URL schema for MISP rows)
        if ind.source == "misp" and ind.source_id:
            exports = " ".join([
                f"<a href='/misp/event/{_esc(ind.source_id)}/{_esc(ind.type)}/{fmt}' aria-label='Export MISP event indicator in {fmt} format'>{fmt.upper()}</a>"
                for fmt in ("csv","txt","json","fortigate")
            ])
        else:
            q_parts = [f"value:{ind.value}", f"source:{ind.source}"]
            q_row = " AND ".join(q_parts)
            exports = " ".join([
                f"<a href='/indicators/{fmt}?q={_esc(q_row)}' aria-label='Export indicator in {fmt} format'>{fmt.upper()}</a>"
                for fmt in ("txt","csv","json","fortigate")
            ])

        rows_html.append(
            f"<tr role='row'>"
            f"<td role='cell'><code>{_esc(ind.value)}</code></td>"
            f"<td role='cell'>{type_badge(ind.type)}</td>"
            f"<td role='cell'>{bar}</td>"
            f"<td role='cell'>{tlp_badge(ind.tlp)}</td>"
            f"<td role='cell'>{_esc(ind.source)}</td>"
            f"<td role='cell'>{exports}</td>"
            f"<td role='cell'>{tags}</td>"
            f"<td role='cell'>{misp_link}</td>"
            f"</tr>"
        )

    table_rows = "".join(rows_html) if rows_html else "<tr role='row'><td role='cell' colspan='8'>No results</td></tr>"

    # Search help panel
    search_help = """<div id="search-syntax" role="region" aria-label="Search syntax help" class="help">
  <strong>Search Syntax (Kibana-like):</strong>
  <ul>
    <li><code>value:192.168.*</code> - Match IP pattern</li>
    <li><code>confidence:>70</code> - Confidence greater than 70</li>
    <li><code>tlp:RED</code> - Exact TLP match</li>
    <li><code>type:ip AND confidence:>50</code> - Combined conditions</li>
    <li><code>tags:apt</code> - Contains tag</li>
  </ul>
  <p><strong>Available fields:</strong> value, type, confidence, tlp, tags, source</p>
  <p><strong>Operators:</strong> AND, OR, NOT, :, &gt;, &lt;, &gt;=, &lt;=, *, ?</p>
</div>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Indicators</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 1.5rem; }}
    .toolbar {{ display: grid; grid-template-columns: 1fr; gap: .75rem; margin-bottom: 1rem; }}
    .row {{ display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }}
    input[type=text] {{ width: 100%; padding: .6rem; border-radius: 12px; border: 1px solid #ccc; }}
    select {{ padding: .5rem; border-radius: 12px; border: 1px solid #ccc; }}
    button {{ padding: .55rem .8rem; border-radius: 12px; border: 1px solid #333; background: #fff; cursor: pointer; }}
    button:focus, a:focus, input:focus, select:focus {{ outline: 3px solid #000; outline-offset: 2px; }}
    .card {{ border: 1px solid #ddd; border-radius: 16px; padding: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,.06); margin-bottom: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #eee; padding: 0.5rem; text-align: left; vertical-align: top; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 999px; border: 1px solid #333; font-size: .85rem; }}
    .tag {{ display: inline-block; padding: .1rem .45rem; border-radius: 999px; border: 1px solid #999; font-size: .8rem; margin-right: .25rem; margin-bottom: .15rem; }}
    .confbar {{ width: 140px; height: 12px; border: 1px solid #333; border-radius: 999px; overflow: hidden; }}
    .confbar-in {{ height: 100%; background: #333; }}
    .b-ip{{}} .b-domain{{}} .b-url{{}} .b-hash{{}} .b-email{{}} .b-other{{}}
    .b-white{{}} .b-green{{}} .b-amber{{}} .b-red{{}}
    .help {{ font-size: .95rem; }}
    .skip-link {{ position: absolute; left: -9999px; top: auto; width: 1px; height: 1px; overflow: hidden; }}
    .skip-link:focus {{ left: 1rem; top: 1rem; width: auto; height: auto; background: #fff; padding: .5rem; border: 1px solid #000; }}
    @media (prefers-reduced-motion: reduce) {{
      * {{ scroll-behavior: auto !important; transition: none !important; animation: none !important; }}
    }}
  </style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<main id="main-content" role="main">
  <div class="card">
    <h1>Unified Indicators</h1>
    <form method="get" action="/indicators" class="toolbar" aria-label="Indicator search and filters">
      <label for="searchBox"><strong>Search</strong></label>
      <input type="text" id="searchBox" name="q" value="{_esc(q or '')}"
             aria-label="Search indicators using Kibana syntax"
             aria-describedby="search-syntax"
             placeholder="e.g. value:192.168.* AND confidence:>70" />
      <div class="row">
        <label for="typeSel">Type</label>
        <select id="typeSel" name="type" aria-label="Filter by indicator type">
          {"".join([f"<option value='{t}' {'selected' if type_filter==t else ''}>{t}</option>" for t in ["all","ip","domain","url","hash","email"]])}
        </select>

        <label for="tlpSel">TLP</label>
        <select id="tlpSel" name="tlp" aria-label="Filter by TLP level">
          {"".join([f"<option value='{t}' {'selected' if tlp==t else ''}>{t}</option>" for t in ["all","WHITE","GREEN","AMBER","RED"]])}
        </select>

        <label for="srcSel">Source</label>
        <select id="srcSel" name="source" aria-label="Filter by source">
          {"".join([f"<option value='{s}' {'selected' if source==s else ''}>{s}</option>" for s in ["all","crowdsec","misp"]])}
        </select>

        <label for="minConf">Min conf</label>
        <select id="minConf" name="min_conf" aria-label="Minimum confidence">
          {"".join([f"<option value='{n}' {'selected' if (min_conf==n) else ''}>{n}</option>" for n in ["",0,25,50,60,70,80,90]])}
        </select>

        <label for="maxConf">Max conf</label>
        <select id="maxConf" name="max_conf" aria-label="Maximum confidence">
          {"".join([f"<option value='{n}' {'selected' if (max_conf==n) else ''}>{n}</option>" for n in ["",100,90,80,70,60,50,25]])}
        </select>

        <button type="submit" aria-label="Apply search and filters">Apply</button>
        <a href="/indicators" aria-label="Clear search and filters">Clear</a>
      </div>
    </form>

    {search_help}

    <p>Quick exports:
      <a href="/indicators/txt?q={_esc(q or '')}" aria-label="Export current results as TXT">TXT</a> ·
      <a href="/indicators/csv?q={_esc(q or '')}" aria-label="Export current results as CSV">CSV</a> ·
      <a href="/indicators/json?q={_esc(q or '')}" aria-label="Export current results as JSON">JSON</a> ·
      <a href="/indicators/fortigate?q={_esc(q or '')}" aria-label="Export current results as FortiGate list">FortiGate</a>
    </p>
  </div>

  <div class="card">
    <table role="table" aria-label="Threat indicators">
      <thead>
        <tr role="row">
          <th role="columnheader" aria-sort="none">Indicator</th>
          <th role="columnheader" aria-sort="none">Type</th>
          <th role="columnheader" aria-sort="none">Confidence</th>
          <th role="columnheader" aria-sort="none">TLP</th>
          <th role="columnheader" aria-sort="none">Source</th>
          <th role="columnheader" aria-sort="none">Formats</th>
          <th role="columnheader" aria-sort="none">Tags</th>
          <th role="columnheader" aria-sort="none">MISP Event</th>
        </tr>
      </thead>
      <tbody>
        {table_rows}
      </tbody>
    </table>
  </div>
</main>

<script>
  const searchBox = document.getElementById('searchBox');
  document.addEventListener('keydown', (e) => {{
    if (e.key === '/') {{
      e.preventDefault();
      searchBox.focus();
    }}
    if (e.key === 'Escape') {{
      if (document.activeElement === searchBox) {{
        searchBox.value = '';
        searchBox.blur();
      }}
    }}
  }});
</script>
</body>
</html>
"""
