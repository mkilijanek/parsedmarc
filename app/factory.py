from __future__ import annotations

import hmac
import logging
import os
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock, Thread
from typing import Any, Dict, List
from flask import Flask, Response, jsonify, make_response, render_template, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session
from werkzeug.exceptions import HTTPException

from .audit_integrity import signed_audit_hash, verify_audit_chain
from .cache import get_redis
from .config import Config
from .db import SessionLocal, get_session, register_db_circuit_observers
from .formatters import FORMATTERS
from .logging import setup_logging
from .metrics import (
    CONTENT_TYPE_LATEST,
    active_indicators,
    cache_access_total,
    correlation_groups_returned_total,
    correlation_queries_total,
    correlation_query_duration_seconds,
    db_query_duration_seconds,
    generate_latest,
    request_count,
    request_duration,
)
from .models import (
    AppLog,
    AppSetting,
    AuditLog,
    DeadLetterJob,
    ExportJob,
    Feed,
    FeedRun,
    FeedStats,
    Indicator,
    SyncJob,
    tags_contains,
)
from .runtime_env import get_runtime_env
from .query_parser import Term, Token, parse_kibana_query
from .routes import (
    register_api_v1_routes,
    register_auth_routes,
    register_events_routes,
    register_health_blueprint,
    register_logs_routes,
    register_ops_routes,
    register_public_routes,
)
from .routes.auth import auth_surface_request_is_secure, canonical_https_url
from .security import enforce_allowed_hosts, get_client_ip, validate_search_query
from .settings_store import admin_auth_disable_allowed_in_production
from .services.common import (
    _db_circuit_breaker,
    _dep_status,
    configure_requests_tls_verify_from_env,
    sum_update_result,
)
from .services.correlation import query_correlations
from .services.feed_ops import (
    apply_feed_filters_and_sort,
    feed_last_error_at,
    feed_operational_status,
    parse_feed_table_params,
    percentile,
    resolve_metrics_window_hours,
)
from .views.legacy_public import render_index as legacy_render_index
from .views.legacy_public import render_indicators as legacy_render_indicators
from .webui import webui_bp

logger = logging.getLogger(__name__)
_SECURITY_WARNINGS_ONCE_FILE = "/tmp/ioc-service-security-warnings.once"

SUPPORTED_FIELDS = {"value","type","confidence","tlp","tags","source"}
# Database-native export formats (formats supported by ti.export_indicators SQL function)
DB_SUPPORTED_FORMATS = {"txt", "csv", "json"}

@dataclass(frozen=True)
class SyncJobRef:
    id: int
    job_id: str
    feed_source_id: str
    trigger_type: str


def _aggregate_fetched_count(result_data: Any) -> int:
    return int(sum_update_result(result_data).get("fetched", 0) or 0)

def create_app() -> Flask:
    cfg = Config()
    setup_logging(cfg.LOG_LEVEL)
    is_production = cfg.APP_ENV in {"prod", "production"}

    # Warn once per container start (avoid duplicate logs from multiple Gunicorn workers).
    should_warn = True
    try:
        fd = os.open(_SECURITY_WARNINGS_ONCE_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.close(fd)
    except FileExistsError:
        should_warn = False
    except Exception:
        should_warn = True
    if should_warn:
        if cfg.ALLOWED_HOSTS == "*":
            logger.warning("security_permissive_allowed_hosts", extra={"value": cfg.ALLOWED_HOSTS, "recommendation": "Set ALLOWED_HOSTS to specific hosts in production"})
        if cfg.CORS_ORIGINS == "*":
            logger.warning("security_permissive_cors_origins", extra={"value": cfg.CORS_ORIGINS, "recommendation": "Set CORS_ORIGINS to specific origins in production"})
        if not getattr(cfg.security, "ADMIN_AUTH_ENABLED", True):
            logger.warning("security_admin_auth_disabled", extra={"message": "ADMIN_AUTH_ENABLED is false. Use only in development/test environments."})
    if is_production and not cfg.SECURITY_ALLOW_PERMISSIVE_DEFAULTS:
        if cfg.ALLOWED_HOSTS == "*":
            raise RuntimeError("SECURITY ERROR: ALLOWED_HOSTS cannot be '*' in production. Set explicit hosts or SECURITY_ALLOW_PERMISSIVE_DEFAULTS=true.")
        if cfg.CORS_ORIGINS == "*":
            raise RuntimeError("SECURITY ERROR: CORS_ORIGINS cannot be '*' in production. Set explicit origins or SECURITY_ALLOW_PERMISSIVE_DEFAULTS=true.")
    if is_production and not getattr(cfg.security, "ADMIN_AUTH_ENABLED", True) and not admin_auth_disable_allowed_in_production(cfg):
        raise RuntimeError(
            "SECURITY ERROR: ADMIN_AUTH_ENABLED=false is blocked in production. "
            "Use ADMIN_AUTH_ALLOW_DISABLED_IN_PRODUCTION=true only for isolated lab/test scenarios."
        )

    app = Flask(__name__)
    app.config["SECRET_KEY"] = cfg.SECRET_KEY
    app.config["GUNICORN_WORKER_CLASS"] = str(get_runtime_env("GUNICORN_WORKER_CLASS", "") or "")
    register_db_circuit_observers(
        on_success=_db_circuit_breaker.record_success,
        on_failure=_db_circuit_breaker.record_failure,
    )

    # SECURITY: Secure session cookie configuration
    app.config["SESSION_COOKIE_SECURE"] = bool(cfg.SESSION_COOKIE_SECURE_ENABLED)
    app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript access
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour session
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit

    # Web UI blueprint
    app.register_blueprint(webui_bp)

    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri=cfg.REDIS_URL,
        default_limits=["60 per minute"],
        enabled=cfg.RATE_LIMITS_ENABLED,
    )
    # Keep a strong reference on the app to prevent flask-limiter weakref GC issues under load.
    app.limiter = limiter  # type: ignore[attr-defined]
    fallback_rps_window: deque[float] = deque()
    fallback_rps_lock = Lock()

    register_auth_routes(
        app,
        limiter=limiter,
        cfg=cfg,
    )

    def _check_fallback_rps() -> bool:
        now = time.time()
        with fallback_rps_lock:
            cutoff = now - 1.0
            while fallback_rps_window and fallback_rps_window[0] < cutoff:
                fallback_rps_window.popleft()
            if len(fallback_rps_window) >= max(1, int(cfg.REQUESTS_PER_SECOND_MAX)):
                return False
            fallback_rps_window.append(now)
        return True

    def _check_global_rps() -> bool:
        limit = max(1, int(cfg.REQUESTS_PER_SECOND_MAX))
        key = f"rps:{int(time.time())}"
        try:
            r = get_redis()
            count = int(r.incr(key))
            if count == 1:
                r.expire(key, 2)
            return count <= limit
        except Exception:
            return _check_fallback_rps()

    @app.before_request
    def _sec_headers():
        # Hard upper bound for inbound request rate (configured default: 1,000,000 req/s).
        if not _check_global_rps():
            return jsonify({"error": "Global request rate exceeded"}), 429
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
        if cfg.HSTS_ENABLED:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # Permissions Policy: Disable unnecessary browser features
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        resp.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
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

    @app.before_request
    def _attach_correlation_id():
        incoming = (request.headers.get("X-Correlation-ID") or "").strip()
        request._correlation_id = incoming or uuid.uuid4().hex

    @app.after_request
    def _append_correlation_header(resp: Response):
        corr = getattr(request, "_correlation_id", "")
        if corr:
            resp.headers["X-Correlation-ID"] = corr
        return resp

    @app.errorhandler(Exception)
    def _json_internal_error(err: Exception):
        corr = getattr(request, "_correlation_id", uuid.uuid4().hex)
        if isinstance(err, HTTPException):
            if request.path.startswith("/api/"):
                return jsonify({"error": err.description or err.name, "correlation_id": corr}), int(err.code or 500)
            return err
        logger.exception("unhandled_error correlation_id=%s", corr)
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error", "correlation_id": corr}), 500
        return make_response(f"Internal server error (correlation_id={_esc(corr)})", 500)

    def _db(*, read_only: bool = False) -> Session:
        # In tests we keep a single mocked session to avoid split in-memory DB state.
        if app.config.get("TESTING"):
            return SessionLocal()
        if not _db_circuit_breaker.allow_request():
            raise RuntimeError(
                "db_circuit_open: database circuit breaker is open; "
                f"state={_db_circuit_breaker.state}"
            )
        try:
            if read_only and cfg.DATABASE_READ_URL:
                sess = get_session(read_only=True)
            else:
                sess = get_session(read_only=False)
            return sess
        except Exception:
            _db_circuit_breaker.record_failure()
            raise

    def _audit(
        action: str,
        entity_type: str | None = None,
        entity_id: int | None = None,
        metadata: dict | None = None,
        *,
        db: Session | None = None,
    ) -> None:
        owns_session = db is None
        db = db or _db()
        try:
            # SECURITY: Use safe IP extraction that respects proxy configuration
            client_ip = get_client_ip()
            user_id = str(session.get("admin_user_id") or "").strip() or None
            previous_hash = str(
                db.scalar(select(AuditLog.log_hash).where(AuditLog.log_hash.is_not(None)).order_by(AuditLog.id.desc()).limit(1))
                or ""
            )
            created_at = datetime.now(timezone.utc).replace(tzinfo=None)
            row = AuditLog(
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                user_id=user_id,
                ip_address=client_ip,
                metadata_=metadata or {},
                previous_hash=previous_hash,
                created_at=created_at,
            )
            row.log_hash = signed_audit_hash(
                secret_key=cfg.SECRET_KEY,
                action=row.action,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                user_id=row.user_id,
                ip_address=row.ip_address,
                metadata=row.metadata_,
                created_at=row.created_at,
                previous_hash=row.previous_hash,
            )
            db.add(row)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            if owns_session:
                db.close()

    @app.errorhandler(429)
    def _rate_limit_exceeded(err: HTTPException):
        corr = getattr(request, "_correlation_id", uuid.uuid4().hex)
        _audit(
            "rate_limit_exceeded",
            "request",
            None,
            {
                "path": request.path,
                "method": request.method,
                "description": err.description or err.name,
                "correlation_id": corr,
            },
        )
        if request.path.startswith("/api/"):
            return jsonify({"error": err.description or "Rate limit exceeded", "correlation_id": corr}), 429
        if request.path.startswith("/auth/login"):
            retry_after = str(getattr(err, "retry_after", "") or request.headers.get("Retry-After") or "").strip()
            wait_minutes = int(getattr(cfg, "ADMIN_LOGIN_RATE_LIMIT_WINDOW_MINUTES", 15) or 15)
            secure_hint = ""
            if not auth_surface_request_is_secure():
                target = canonical_https_url(cfg)
                secure_hint = (
                    f"<p>If you opened the direct app port, switch to the HTTPS admin entrypoint: "
                    f"<a href=\"{_esc(target)}\">{_esc(target)}</a>.</p>"
                )
            html_body = render_template(
                "auth/rate_limit.html",
                wait_minutes=wait_minutes,
                retry_after=retry_after,
                secure_hint=secure_hint,
                corr=corr,
            )
            response = make_response(html_body, 429)
            if retry_after:
                response.headers["Retry-After"] = retry_after
            return response
        return err

    @app.get("/admin/audit/verify")
    @limiter.limit("30 per minute")
    def admin_audit_verify():
        db = _db(read_only=True)
        try:
            rows = list(db.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all())
            result = verify_audit_chain(rows, secret_key=cfg.SECRET_KEY)
            status_code = 200 if result["valid"] else 409
            return jsonify(result), status_code
        finally:
            db.close()

    @app.get("/admin/audit/report")
    @limiter.limit("10 per minute")
    def admin_audit_report():
        db = _db(read_only=True)
        try:
            rows = list(db.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all())
            result = verify_audit_chain(rows, secret_key=cfg.SECRET_KEY)
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "instance": cfg.INSTANCE_NAME,
                "controls": ["ISO27001-A.12.4.1", "ISO27001-A.12.4.3", "NIST-PR.PT-1"],
                "central_log_table": "app_logs",
                "audit_table": "audit_log",
                "required_fields": ["action", "user_id", "ip_address", "created_at", "metadata", "log_hash"],
                "integrity": result,
            }
            status_code = 200 if result["valid"] else 409
            return jsonify(report), status_code
        finally:
            db.close()

    def _cache_key(prefix: str, **parts: Any) -> str:
        # stable ordering
        segs = [prefix] + [f"{k}={parts[k]}" for k in sorted(parts.keys())]
        return "|".join(segs)

    # --- settings service (crypto + AppSetting CRUD + proxy bootstrap) ---
    from .services import settings_svc as _settings_svc
    _settings = _settings_svc.make_settings_service(cfg=cfg, db_fn=_db)
    _get_setting = _settings.get_setting
    _set_setting = _settings.set_setting
    _mask_secret = _settings.mask_secret
    _runtime_override_or_env = _settings.runtime_override_or_env
    _bootstrap_runtime_settings = _settings.bootstrap_runtime_settings
    _write_proxy_env = _settings.write_proxy_env
    _secret_decrypt = _settings.secret_decrypt

    # --- feed config service ---
    from .services import feed_config_svc as _feed_config_svc
    _feed_cfg = _feed_config_svc.make_feed_config_service(
        cfg=cfg,
        get_setting_fn=_get_setting,
        set_setting_fn=_set_setting,
        secret_decrypt_fn=_secret_decrypt,
    )
    _source_templates = _feed_cfg.source_templates
    _read_feed_enabled = _feed_cfg.read_feed_enabled
    _ensure_default_feeds = _feed_cfg.ensure_default_feeds
    _read_feed_config_state = _feed_cfg.read_feed_config_state
    _is_valid_http_url = _feed_cfg.is_valid_http_url
    _validate_feed_form = _feed_cfg.validate_feed_form
    _fetch_mwdb_orgs = _feed_cfg.fetch_mwdb_orgs
    _get_feed_field_value = _feed_cfg.get_feed_field_value
    _test_feed_connection = _feed_cfg.test_feed_connection
    _field_input_name = _feed_cfg.field_input_name
    _feed_value_key = _feed_cfg.feed_value_key
    _feed_secret_key = _feed_cfg.feed_secret_key
    _run_proxy_test = _feed_cfg.run_proxy_test
    _proxy_test_expected_match = _feed_cfg.proxy_test_expected_match

    def _parse_limit_offset(*, default_limit: int, max_limit: int) -> tuple[int, int] | tuple[None, None]:
        try:
            limit = int(request.args.get("limit", str(default_limit)))
            offset = int(request.args.get("offset", "0"))
        except ValueError:
            return None, None
        if limit < 1:
            limit = 1
        if limit > max_limit:
            limit = max_limit
        if offset < 0:
            offset = 0
        return limit, offset

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
            if op == ">":
                return col > n
            if op == "<":
                return col < n
            if op == ">=":
                return col >= n
            if op == "<=":
                return col <= n
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

    def _count_indicators(
        db: Session,
        q: str | None,
        type_filter: str | None,
        tlp: str | None,
        source: str | None,
        min_conf: int | None,
        max_conf: int | None,
    ) -> int:
        stmt = select(func.count()).select_from(Indicator).where(Indicator.is_active == True)  # noqa: E712
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
        return int(db.scalar(stmt) or 0)

    def _app_log(
        level: str,
        component: str,
        message: str,
        *,
        feed_source_id: str | None = None,
        run_id: str | None = None,
        metadata: dict | None = None,
        db: Session | None = None,
    ) -> None:
        own_session = db is None
        db = db or _db()
        try:
            db.add(
                AppLog(
                    level=level.upper(),
                    component=component,
                    message=message,
                    feed_source_id=feed_source_id,
                    run_id=run_id,
                    metadata_=metadata or {},
                )
            )
            db.commit()
        except Exception:
            db.rollback()
        finally:
            if own_session:
                db.close()

    # --- export service ---
    from .services import export_svc as _export_svc
    _export = _export_svc.make_export_service(
        cfg=cfg,
        db_fn=_db,
        app_log_fn=_app_log,
        count_indicators_fn=_count_indicators,
        query_indicators_fn=_query_indicators,
        get_setting_fn=_get_setting,
    )
    _render_export_body = _export.render_export_body
    _persist_export_job = _export.persist_export_job

    # _spawn_export_job needs to check app.config["TESTING"], so wrap it here
    def _spawn_export_job(job_id: str) -> None:
        if app.config.get("TESTING"):
            _export.run_export_job(job_id)
            return
        _export.spawn_export_job(job_id)

    scheduler_lock = Lock()
    scheduler_state: Dict[str, Any] = {
        "active_run_id": None,
        "active_job_id": None,
        "last_minute": {},
        "last_audit_integrity_check_at": None,
    }

    def _read_feed_rows(db: Session) -> List[Feed]:
        _ensure_default_feeds(db)
        return list(db.scalars(select(Feed).where(Feed.deleted == False).order_by(Feed.source_id.asc())).all())  # noqa: E712

    def _latest_runs_map(db: Session, source_ids: List[str]) -> Dict[str, FeedRun]:
        if not source_ids:
            return {}
        from .db import engine as _engine
        if _engine.dialect.name == "postgresql":
            rows = db.scalars(
                select(FeedRun)
                .where(FeedRun.feed_source_id.in_(source_ids))
                .order_by(FeedRun.feed_source_id, FeedRun.started_at.desc())
                .distinct(FeedRun.feed_source_id)
            ).all()
            return {r.feed_source_id: r for r in rows}
        rows: List[FeedRun] = []
        for sid in source_ids:
            row = db.scalar(
                select(FeedRun)
                .where(FeedRun.feed_source_id == sid)
                .order_by(FeedRun.started_at.desc())
                .limit(1)
            )
            if row is not None:
                rows.append(row)
        return {r.feed_source_id: r for r in rows}

    def _build_feed_items(db: Session) -> List[Dict[str, Any]]:
        feeds = _read_feed_rows(db)
        source_ids = [f.source_id for f in feeds]
        latest_runs = _latest_runs_map(db, source_ids)
        stats_rows = list(db.scalars(select(FeedStats).where(FeedStats.source_id.in_(source_ids))).all())
        stats_map = {str(s.source_id or s.source): s for s in stats_rows}
        items: List[Dict[str, Any]] = []
        for feed in feeds:
            state = _read_feed_config_state(db, feed)
            latest = latest_runs.get(feed.source_id)
            stats_row = stats_map.get(feed.source_id)
            status = feed_operational_status(enabled=bool(state["enabled"]), ready=bool(state["ready"]), latest_run=latest)
            last_error_at = feed_last_error_at(latest, stats_row)
            fetched_count = int(getattr(latest, "fetched_count", 0) or 0)
            row = {
                "source_id": feed.source_id,
                "display_name": feed.display_name,
                "source_type": feed.source_type,
                "enabled": bool(state["enabled"]),
                "schedule_cron": str(feed.schedule_cron or ""),
                "ready": bool(state["ready"]),
                "missing": list(state.get("missing") or []),
                "status": status,
                "last_run_status": str(getattr(latest, "status", "never")),
                "last_run_at": latest.started_at if latest is not None else None,
                "last_error_at": last_error_at,
                "fetched_count": fetched_count,
            }
            items.append(row)
        return items

    def _admin_dangerous_ops_enabled() -> bool:
        return bool(cfg.ADMIN_DANGEROUS_OPS)

    def _admin_token_authorized() -> bool:
        expected = (cfg.ADMIN_API_TOKEN or "").strip()
        if not expected:
            return False
        token = (
            (request.headers.get("X-Admin-Token") or "").strip()
            or (request.form.get("admin_token") or "").strip()
        )
        return bool(token) and hmac.compare_digest(token, expected)

    _db_circuit_breaker.record_success()
    _bootstrap_runtime_settings()
    configure_requests_tls_verify_from_env()

    # --- scheduler service ---
    from .services import scheduler_svc as _scheduler_svc
    _sched = _scheduler_svc.make_scheduler_service(
        cfg=cfg,
        db_fn=_db,
        app_log_fn=_app_log,
        audit_fn=_audit,
        get_setting_fn=_get_setting,
        set_setting_fn=_set_setting,
        read_feed_rows_fn=_read_feed_rows,
        read_feed_config_state_fn=_read_feed_config_state,
        feed_value_key_fn=_feed_value_key,
        feed_secret_key_fn=_feed_secret_key,
        runtime_override_or_env_fn=_runtime_override_or_env,
        cache_key_fn=_cache_key,
        scheduler_state=scheduler_state,
        scheduler_lock=scheduler_lock,
    )
    _enqueue_sync_job = _sched.enqueue_sync_job
    _execute_sync_job = _sched.execute_sync_job
    _scheduler_loop = _sched.scheduler_loop
    _refresh_job_backlog_metrics = _sched.refresh_job_backlog_metrics
    _run_sync_queue_once = _sched.run_sync_queue_once
    _enqueue_due_scheduled_jobs = _sched.enqueue_due_scheduled_jobs
    _run_log_retention_if_due = _sched.run_log_retention_if_due
    _run_cache_warming_if_due = _sched.run_cache_warming_if_due
    _run_audit_integrity_check_if_due = _sched.run_audit_integrity_check_if_due
    _db_try_advisory_lock = _sched.db_try_advisory_lock
    _db_advisory_unlock = _sched.db_advisory_unlock

    register_health_blueprint(
        app,
        limiter=limiter,
        cfg=cfg,
        db_factory=_db,
        cache_key_fn=_cache_key,
    )

    register_public_routes(
        app,
        limiter=limiter,
        cfg=cfg,
        logger=logger,
        deps={
            "_admin_token_authorized": _admin_token_authorized,
            "_audit": _audit,
            "_cache_key": _cache_key,
            "_count_indicators": _count_indicators,
            "_db": _db,
            "_parse_limit_offset": _parse_limit_offset,
            "_persist_export_job": _persist_export_job,
            "_query_indicators": _query_indicators,
            "_refresh_job_backlog_metrics": _refresh_job_backlog_metrics,
            "_render_export_body": _render_export_body,
            "_render_index": _render_index,
            "_render_indicators": _render_indicators,
            "_spawn_export_job": _spawn_export_job,
            "get_redis": get_redis,
            "validate_search_query": validate_search_query,
            "Indicator": Indicator,
            "FeedStats": FeedStats,
            "ExportJob": ExportJob,
            "FORMATTERS": FORMATTERS,
            "DB_SUPPORTED_FORMATS": DB_SUPPORTED_FORMATS,
            "query_correlations": query_correlations,
            "request_count": request_count,
            "request_duration": request_duration,
            "active_indicators": active_indicators,
            "generate_latest": generate_latest,
            "CONTENT_TYPE_LATEST": CONTENT_TYPE_LATEST,
            "correlation_queries_total": correlation_queries_total,
            "correlation_query_duration_seconds": correlation_query_duration_seconds,
            "correlation_groups_returned_total": correlation_groups_returned_total,
            "cache_access_total": cache_access_total,
            "db_query_duration_seconds": db_query_duration_seconds,
        },
    )

    register_logs_routes(
        app,
        limiter=limiter,
        cfg=cfg,
        logger=logger,
        deps={
            "_db": _db,
            "AppLog": AppLog,
        },
    )

    register_events_routes(
        app,
        limiter=limiter,
        cfg=cfg,
        deps={
            "_db": _db,
            "_dep_status": _dep_status,
            "Indicator": Indicator,
            "SyncJob": SyncJob,
            "FeedRun": FeedRun,
        },
    )

    register_api_v1_routes(
        app,
        limiter=limiter,
        cfg=cfg,
        logger=logger,
        scheduler_state=scheduler_state,
        deps={
            "_admin_token_authorized": _admin_token_authorized,
            "_apply_feed_filters_and_sort": apply_feed_filters_and_sort,
            "_build_feed_items": _build_feed_items,
            "_count_indicators": _count_indicators,
            "_db": _db,
            "_enqueue_sync_job": _enqueue_sync_job,
            "_ensure_default_feeds": _ensure_default_feeds,
            "_get_setting": _get_setting,
            "_parse_limit_offset": _parse_limit_offset,
            "_percentile": percentile,
            "_query_indicators": _query_indicators,
            "_read_feed_config_state": _read_feed_config_state,
            "_read_feed_rows": _read_feed_rows,
            "_resolve_metrics_window_hours": resolve_metrics_window_hours,
            "validate_search_query": validate_search_query,
            "AppLog": AppLog,
            "Feed": Feed,
            "FeedRun": FeedRun,
            "Indicator": Indicator,
            "SyncJob": SyncJob,
        },
    )

    register_ops_routes(
        app,
        limiter=limiter,
        cfg=cfg,
        logger=logger,
        scheduler_state=scheduler_state,
        deps={
            "_admin_dangerous_ops_enabled": _admin_dangerous_ops_enabled,
            "_admin_token_authorized": _admin_token_authorized,
            "_app_log": _app_log,
            "_apply_feed_filters_and_sort": apply_feed_filters_and_sort,
            "_audit": _audit,
            "_build_feed_items": _build_feed_items,
            "_db": _db,
            "_enqueue_sync_job": _enqueue_sync_job,
            "_ensure_default_feeds": _ensure_default_feeds,
            "_esc": _esc,
            "_feed_secret_key": _feed_secret_key,
            "_feed_value_key": _feed_value_key,
            "_fetch_mwdb_orgs": _fetch_mwdb_orgs,
            "_get_feed_field_value": _get_feed_field_value,
            "_get_setting": _get_setting,
            "_mask_secret": _mask_secret,
            "_parse_feed_table_params": lambda: parse_feed_table_params(request.args),
            "_percentile": percentile,
            "_read_feed_config_state": _read_feed_config_state,
            "_read_feed_rows": _read_feed_rows,
            "_resolve_metrics_window_hours": lambda: resolve_metrics_window_hours(request.args),
            "_run_proxy_test": _run_proxy_test,
            "_set_setting": _set_setting,
            "_source_templates": _source_templates,
            "_test_feed_connection": _test_feed_connection,
            "_validate_feed_form": _validate_feed_form,
            "_write_proxy_env": _write_proxy_env,
            "get_redis": get_redis,
            "Indicator": Indicator,
            "FeedStats": FeedStats,
            "AppSetting": AppSetting,
            "ExportJob": ExportJob,
            "Feed": Feed,
            "FeedRun": FeedRun,
            "AppLog": AppLog,
            "SyncJob": SyncJob,
            "DeadLetterJob": DeadLetterJob,
            "_db_circuit_breaker": _db_circuit_breaker,
        },
    )

    if cfg.ENABLE_BACKGROUND_JOBS and not app.config.get("TESTING"):
        Thread(target=_scheduler_loop, daemon=True).start()

    return app


def _esc(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _render_index(total: int, active: int, feeds) -> str:
    return legacy_render_index(total, active, list(feeds))

def _render_indicators(
    rows: List[Indicator],
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
    source_options: List[str],
) -> str:
    return legacy_render_indicators(
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
