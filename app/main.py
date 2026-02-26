from __future__ import annotations

import logging
import json
import os
import base64
import hashlib
import hmac
import secrets
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from pathlib import Path
from threading import Thread
from urllib.parse import urlencode
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, jsonify, request, make_response, redirect, url_for, stream_with_context, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from sqlalchemy import select, func, and_, or_, text
from sqlalchemy.orm import Session

from .config import Config
from .webui import webui_bp
from .logging import setup_logging
from .db import SessionLocal, get_session
from .models import (
    Indicator,
    FeedStats,
    AuditLog,
    AppSetting,
    ExportJob,
    Feed,
    FeedRun,
    AppLog,
    SyncJob,
    tags_contains,
)
from .cache import get_redis
from .security import validate_search_query, enforce_allowed_hosts, get_client_ip
from .query_parser import parse_kibana_query, Term, Token
from .formatters import FORMATTERS
from .services.correlation import query_correlations

from .metrics import (
    request_count,
    request_duration,
    active_indicators,
    generate_latest,
    CONTENT_TYPE_LATEST,
    correlation_queries_total,
    correlation_query_duration_seconds,
    correlation_groups_returned_total,
    cache_access_total,
    db_query_duration_seconds,
)

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
        enabled=cfg.RATE_LIMITS_ENABLED,
    )
    # Keep a strong reference on the app to prevent flask-limiter weakref GC issues under load.
    app.limiter = limiter  # type: ignore[attr-defined]
    rps_window: deque[float] = deque()
    rps_lock = Lock()

    @app.before_request
    def _sec_headers():
        # Hard upper bound for inbound request rate (configured default: 1,000,000 req/s).
        now = time.time()
        with rps_lock:
            cutoff = now - 1.0
            while rps_window and rps_window[0] < cutoff:
                rps_window.popleft()
            if len(rps_window) >= max(1, int(cfg.REQUESTS_PER_SECOND_MAX)):
                return jsonify({"error": "Global request rate exceeded"}), 429
            rps_window.append(now)
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
        if read_only and cfg.DATABASE_READ_URL:
            return get_session(read_only=True)
        return get_session(read_only=False)

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

    def _secret_enc_key() -> bytes:
        return hashlib.sha256(cfg.SECRET_KEY.encode("utf-8")).digest()

    def _secret_encrypt(value: str) -> str:
        raw = (value or "").encode("utf-8")
        nonce = secrets.token_bytes(16)
        key = _secret_enc_key()
        stream = bytearray()
        counter = 0
        while len(stream) < len(raw):
            block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
            stream.extend(block)
            counter += 1
        cipher = bytes(a ^ b for a, b in zip(raw, stream))
        mac = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
        return "v1:" + base64.urlsafe_b64encode(nonce + mac + cipher).decode("ascii")

    def _secret_decrypt(value: str) -> str:
        if not value:
            return ""
        if not value.startswith("v1:"):
            return value
        blob = base64.urlsafe_b64decode(value[3:].encode("ascii"))
        if len(blob) < 48:
            return ""
        nonce = blob[:16]
        mac = blob[16:48]
        cipher = blob[48:]
        key = _secret_enc_key()
        expected = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            return ""
        stream = bytearray()
        counter = 0
        while len(stream) < len(cipher):
            block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
            stream.extend(block)
            counter += 1
        plain = bytes(a ^ b for a, b in zip(cipher, stream))
        return plain.decode("utf-8")

    def _get_setting(db: Session, key: str, default: str = "", *, secret: bool = False) -> str:
        row = db.scalar(select(AppSetting).where(AppSetting.key == key))
        if not row:
            return default
        if secret:
            return _secret_decrypt(row.value)
        return row.value

    def _set_setting(db: Session, key: str, value: str, *, secret: bool = False) -> None:
        row = db.scalar(select(AppSetting).where(AppSetting.key == key))
        stored = _secret_encrypt(value) if secret else value
        if row is None:
            db.add(AppSetting(key=key, value=stored, is_secret=secret))
            return
        row.value = stored
        row.is_secret = secret

    def _mask_secret(value: str) -> str:
        if not value:
            return ""
        tail = value[-4:] if len(value) >= 4 else value
        return "*" * max(4, len(value) - len(tail)) + tail

    def _read_feed_enabled(db: Session, source_name: str) -> bool:
        raw = _get_setting(db, f"feed.{source_name}.enabled", "1")
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _write_proxy_env(db: Session) -> None:
        proxy_http = _get_setting(db, "proxy.http_url", "")
        proxy_https = _get_setting(db, "proxy.https_url", "")
        proxy_no = _get_setting(db, "proxy.no_proxy", "")
        if proxy_http:
            os.environ["HTTP_PROXY"] = proxy_http
        else:
            os.environ.pop("HTTP_PROXY", None)
        if proxy_https:
            os.environ["HTTPS_PROXY"] = proxy_https
        else:
            os.environ.pop("HTTPS_PROXY", None)
        if proxy_no:
            os.environ["NO_PROXY"] = proxy_no
        else:
            os.environ.pop("NO_PROXY", None)

    def _source_templates() -> Dict[str, Dict[str, Any]]:
        return {
            "misp": {
                "display_name": "MISP",
                "fields": [
                    {"key": "base_url", "label": "MISP URL", "secret": False, "required": True, "env": "MISP_URL", "placeholder": "https://misp.example.local"},
                    {"key": "api_key", "label": "MISP API key", "secret": True, "required": True, "env": "MISP_API_KEY", "placeholder": "Leave blank to keep current"},
                ],
            },
            "crowdsec": {
                "display_name": "CrowdSec",
                "fields": [
                    {"key": "api_key", "label": "CrowdSec API key", "secret": True, "required": True, "env": "CROWDSEC_API_KEY", "placeholder": "Leave blank to keep current"},
                ],
            },
            "malwarebazaar": {
                "display_name": "MalwareBazaar",
                "fields": [
                    {"key": "api_key", "label": "MalwareBazaar auth key", "secret": True, "required": True, "env": "MALWAREBAZAAR_AUTH_KEY", "placeholder": "Leave blank to keep current"},
                ],
            },
            "mwdb": {
                "display_name": "MWDB",
                "fields": [
                    {"key": "base_url", "label": "MWDB URL", "secret": False, "required": True, "env": "MWDB_URL", "placeholder": "https://mwdb.example.local"},
                    {"key": "api_key", "label": "MWDB auth key", "secret": True, "required": True, "env": "MWDB_AUTH_KEY", "placeholder": "Leave blank to keep current"},
                ],
            },
            "abusech": {
                "display_name": "abuse.ch",
                "fields": [
                    {"key": "api_key", "label": "abuse.ch auth key", "secret": True, "required": False, "env": "ABUSECH_AUTH_KEY", "placeholder": "Leave blank to keep current"},
                ],
            },
        }

    def _field_input_name(setting_key: str) -> str:
        return setting_key.replace(".", "__")

    def _feed_value_key(source_id: str, key: str) -> str:
        return f"feedcfg.{source_id}.{key}"

    def _feed_secret_key(source_id: str, key: str) -> str:
        return f"feedsecret.{source_id}.{key}"

    def _ensure_default_feeds(db: Session) -> None:
        existing = db.scalars(select(Feed).where(Feed.deleted == False)).all()  # noqa: E712
        if existing:
            return
        defaults = [
            ("misp", "misp", "MISP"),
            ("crowdsec", "crowdsec", "CrowdSec"),
            ("malwarebazaar", "malwarebazaar", "MalwareBazaar"),
            ("mwdb", "mwdb", "MWDB"),
            ("abusech", "abusech", "abuse.ch"),
        ]
        for source_id, source_type, display_name in defaults:
            db.add(
                Feed(
                    source_id=source_id,
                    source_type=source_type,
                    display_name=display_name,
                    schedule_cron="*/15 * * * *",
                    enabled=True,
                    deleted=False,
                )
            )
        db.commit()

    def _read_feed_config_state(db: Session, feed: Feed) -> Dict[str, Any]:
        defs = _source_templates().get(feed.source_type)
        if not defs:
            return {"source_id": feed.source_id, "ready": False, "missing": ["unknown source type"], "enabled": feed.enabled}
        missing: List[str] = []
        normalized_fields: List[Dict[str, Any]] = []
        for field_def in defs["fields"]:
            key = str(field_def["key"])
            if not key:
                continue
            required = bool(field_def.get("required", False))
            secret = bool(field_def.get("secret", False))
            if key == "base_url":
                val = str(feed.base_url or "")
            else:
                setting_key = _feed_secret_key(feed.source_id, key) if secret else _feed_value_key(feed.source_id, key)
                val = _get_setting(db, setting_key, "", secret=secret)
            if required and not str(val).strip():
                missing.append(str(field_def.get("label") or key))
            normalized_fields.append(
                {
                    "key": key,
                    "label": str(field_def.get("label") or key),
                    "secret": secret,
                    "required": required,
                    "placeholder": str(field_def.get("placeholder") or ""),
                    "value": "" if secret else str(val),
                    "current_masked": _mask_secret(str(val)) if secret else "",
                    "input_name": _field_input_name(key),
                    "env": str(field_def.get("env") or ""),
                }
            )
        return {
            "source_id": feed.source_id,
            "source_type": feed.source_type,
            "display_name": feed.display_name,
            "ready": len(missing) == 0,
            "missing": missing,
            "enabled": bool(feed.enabled),
            "fields": normalized_fields,
        }

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

    def _render_export_body(fmt: str, rows: List[Indicator]) -> tuple[str, str]:
        func_, mime = FORMATTERS[fmt]
        try:
            if fmt == "elasticsearch":
                body = func_(rows)  # type: ignore[arg-type]
            else:
                body = func_(rows)  # type: ignore[misc]
        except TypeError:
            body = func_(rows)  # type: ignore[misc]
        return body, mime

    def _persist_export_job(job_id: str, fmt: str, params: Dict[str, Any]) -> None:
        db = _db()
        try:
            db.add(
                ExportJob(
                    job_id=job_id,
                    fmt=fmt,
                    status="queued",
                    query_json=params,
                )
            )
            db.commit()
        finally:
            db.close()

    def _run_export_job(job_id: str) -> None:
        db = _db()
        out_dir = Path(cfg.EXPORT_JOB_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            job = db.scalar(select(ExportJob).where(ExportJob.job_id == job_id))
            if not job:
                return
            job.status = "running"
            db.commit()
            params = dict(job.query_json or {})
            fmt = str(job.fmt)
            rows = _query_indicators(
                db,
                params.get("q"),
                params.get("type_filter"),
                params.get("tlp"),
                params.get("source"),
                None,
                None,
                limit=int(params.get("limit", 100000)),
                offset=int(params.get("offset", 0)),
            )
            body, _ = _render_export_body(fmt, rows)
            out_path = out_dir / f"{job_id}.{fmt}"
            out_path.write_text(body, encoding="utf-8")
            job.status = "completed"
            job.result_path = str(out_path)
            job.error = None
            db.commit()
        except Exception as e:
            try:
                job = db.scalar(select(ExportJob).where(ExportJob.job_id == job_id))
                if job:
                    job.status = "failed"
                    job.error = str(e)
                    db.commit()
            except Exception:
                db.rollback()
        finally:
            db.close()

    def _spawn_export_job(job_id: str) -> None:
        if app.config.get("TESTING"):
            _run_export_job(job_id)
            return
        th = Thread(target=_run_export_job, args=(job_id,), daemon=True)
        th.start()

    scheduler_lock = Lock()
    scheduler_state: Dict[str, Any] = {"active_run_id": None, "active_job_id": None, "last_minute": {}}

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

    def _read_feed_rows(db: Session) -> List[Feed]:
        _ensure_default_feeds(db)
        return list(db.scalars(select(Feed).where(Feed.deleted == False).order_by(Feed.source_id.asc())).all())  # noqa: E712

    def _db_try_advisory_lock(db: Session, lock_id: int) -> bool:
        bind = db.get_bind()
        if not bind or bind.dialect.name != "postgresql":
            return True
        ok = db.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}).scalar()
        return bool(ok)

    def _db_advisory_unlock(db: Session, lock_id: int) -> None:
        bind = db.get_bind()
        if bind and bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id})
            db.commit()

    def _run_sync_worker_for_feed(feed: Feed) -> Dict[str, Any]:
        source_type = feed.source_type
        if source_type == "misp":
            from .services.misp import update_misp_indicators
            return {"source": feed.source_id, "result": update_misp_indicators()}
        if source_type == "crowdsec":
            from .services.crowdsec import update_crowdsec_indicators
            return {"source": feed.source_id, "result": update_crowdsec_indicators()}
        if source_type == "malwarebazaar":
            from .services.malwarebazaar import update_malwarebazaar_indicators
            return {"source": feed.source_id, "result": update_malwarebazaar_indicators()}
        if source_type == "mwdb":
            from .services.mwdb import update_mwdb_indicators
            return {"source": feed.source_id, "result": update_mwdb_indicators()}
        if source_type == "abusech":
            from .services.abusech import update_abusech_indicators
            return {"source": feed.source_id, "result": update_abusech_indicators()}
        raise ValueError(f"Unknown source_type: {source_type}")

    def _enqueue_sync_job(feed: Feed, *, trigger_type: str, db: Session | None = None) -> tuple[SyncJob, bool]:
        own_session = db is None
        db = db or _db()
        try:
            existing = db.scalar(
                select(SyncJob)
                .where(SyncJob.feed_source_id == feed.source_id, SyncJob.status.in_(["queued", "running"]))
                .order_by(SyncJob.created_at.desc())
                .limit(1)
            )
            if existing:
                return existing, False
            job = SyncJob(
                job_id=uuid.uuid4().hex,
                feed_source_id=feed.source_id,
                trigger_type=trigger_type,
                idempotency_key=f"{feed.source_id}:{trigger_type}",
                status="queued",
                result_json={},
            )
            db.add(job)
            db.add(
                AppLog(
                    level="INFO",
                    component="scheduler",
                    message="sync_job_enqueued",
                    feed_source_id=feed.source_id,
                    run_id=job.job_id,
                    metadata_={"trigger": trigger_type},
                )
            )
            db.commit()
            db.refresh(job)
            return job, True
        except Exception:
            db.rollback()
            raise
        finally:
            if own_session:
                db.close()

    def _execute_sync_job(job: SyncJob) -> Dict[str, Any]:
        run_id = job.job_id
        scheduler_state["active_job_id"] = job.job_id
        scheduler_state["active_run_id"] = run_id
        updates: Dict[str, str | None] = {}
        previous: Dict[str, str | None] = {}
        db = _db()
        try:
            feed = db.scalar(select(Feed).where(Feed.source_id == job.feed_source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                raise RuntimeError(f"feed not found: {job.feed_source_id}")
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
            now = datetime.now(timezone.utc)
            if run is None:
                db.add(FeedRun(feed_source_id=feed.source_id, run_id=run_id, trigger_type=job.trigger_type, status="running", started_at=now))
            else:
                run.status = "running"
                run.error = None
                run.started_at = now
            row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if row:
                row.status = "running"
                row.error = None
                row.started_at = now
            db.commit()

            _app_log("INFO", "scheduler", "feed_sync_started", feed_source_id=feed.source_id, run_id=run_id, metadata={"trigger": job.trigger_type}, db=db)

            state = _read_feed_config_state(db, feed)
            if not state["ready"]:
                raise RuntimeError(f"incomplete config: {', '.join(state['missing'])}")
            if feed.base_url:
                updates["BASE_URL"] = feed.base_url
            for f in state["fields"]:
                env_key = str(f.get("env") or "")
                if not env_key:
                    continue
                if f["key"] == "base_url":
                    if feed.base_url:
                        updates[env_key] = feed.base_url
                elif f.get("secret"):
                    updates[env_key] = _get_setting(db, _feed_secret_key(feed.source_id, str(f["key"])), "", secret=True)
                else:
                    updates[env_key] = _get_setting(db, _feed_value_key(feed.source_id, str(f["key"])), "", secret=False)

            previous = {k: os.environ.get(k) for k in updates.keys()}
            for k, v in updates.items():
                if v:
                    os.environ[k] = str(v)
                else:
                    os.environ.pop(k, None)

            started = time.time()
            result = _run_sync_worker_for_feed(feed)
            fetched_count = 0
            result_data = result.get("result")
            if isinstance(result_data, dict):
                for value in result_data.values():
                    if isinstance(value, dict):
                        fetched_count += int(value.get("fetched", 0) or 0)
            dur_ms = int((time.time() - started) * 1000)

            run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
            if run:
                run.status = "success"
                run.fetched_count = fetched_count
                run.finished_at = datetime.now(timezone.utc)
            row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if row:
                row.status = "success"
                row.error = None
                row.finished_at = datetime.now(timezone.utc)
                row.result_json = {"fetched_count": fetched_count, "duration_ms": dur_ms}
            db.commit()
            _app_log("INFO", "scheduler", "feed_sync_completed", feed_source_id=feed.source_id, run_id=run_id, metadata={"duration_ms": dur_ms, "fetched_count": fetched_count}, db=db)
            return result
        except Exception as e:
            db.rollback()
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
            if run:
                run.status = "failed"
                run.error = str(e)
                run.finished_at = datetime.now(timezone.utc)
            row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if row:
                row.status = "failed"
                row.error = str(e)
                row.finished_at = datetime.now(timezone.utc)
                row.result_json = {}
            db.commit()
            _app_log("ERROR", "scheduler", "feed_sync_failed", feed_source_id=job.feed_source_id, run_id=run_id, metadata={"error": str(e)}, db=db)
            return {"source": job.feed_source_id, "error": str(e)}
        finally:
            for k, v in updates.items():
                prev = previous.get(k)
                if prev is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = prev
            scheduler_state["active_run_id"] = None
            scheduler_state["active_job_id"] = None
            db.close()

    def _dequeue_next_sync_job() -> SyncJob | None:
        db = _db()
        try:
            stmt = select(SyncJob).where(SyncJob.status == "queued").order_by(SyncJob.created_at.asc()).limit(1)
            bind = db.get_bind()
            if bind and bind.dialect.name == "postgresql":
                stmt = stmt.with_for_update(skip_locked=True)
            job = db.scalar(stmt)
            if not job:
                db.rollback()
                return None
            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(job)
            return job
        except Exception:
            db.rollback()
            return None
        finally:
            db.close()

    def _run_sync_queue_once(*, max_jobs: int = 10) -> int:
        processed = 0
        while processed < max_jobs:
            job = _dequeue_next_sync_job()
            if not job:
                break
            _execute_sync_job(job)
            processed += 1
        return processed

    def _cron_field_match(value: int, expr: str, *, min_v: int, max_v: int) -> bool:
        expr = expr.strip()
        if expr == "*":
            return True
        if expr.startswith("*/"):
            try:
                step = int(expr[2:])
            except ValueError:
                return False
            return step > 0 and (value - min_v) % step == 0
        for part in expr.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                n = int(part)
            except ValueError:
                return False
            if n == value:
                return True
        return False

    def _cron_matches(expr: str, dt: datetime) -> bool:
        parts = (expr or "").split()
        if len(parts) != 5:
            return False
        minute, hour, day, month, dow = parts
        py_dow = (dt.weekday() + 1) % 7
        return (
            _cron_field_match(dt.minute, minute, min_v=0, max_v=59)
            and _cron_field_match(dt.hour, hour, min_v=0, max_v=23)
            and _cron_field_match(dt.day, day, min_v=1, max_v=31)
            and _cron_field_match(dt.month, month, min_v=1, max_v=12)
            and _cron_field_match(py_dow, dow, min_v=0, max_v=6)
        )

    def _enqueue_due_scheduled_jobs(now: datetime) -> int:
        minute_marker = now.strftime("%Y-%m-%dT%H:%M")
        enqueued = 0
        db = _db()
        try:
            _set_setting(db, "scheduler.heartbeat", now.isoformat())
            _set_setting(db, "scheduler.default_cron", _get_setting(db, "scheduler.default_cron", "*/15 * * * *"))
            db.commit()
            for feed in _read_feed_rows(db):
                if not feed.enabled:
                    continue
                if scheduler_state["last_minute"].get(feed.source_id) == minute_marker:
                    continue
                cron_expr = str(feed.schedule_cron or "*/15 * * * *")
                if not _cron_matches(cron_expr, now):
                    continue
                _, created = _enqueue_sync_job(feed, trigger_type="scheduled", db=db)
                scheduler_state["last_minute"][feed.source_id] = minute_marker
                if created:
                    enqueued += 1
            return enqueued
        finally:
            db.close()

    def _scheduler_loop() -> None:
        lock_id = 993451
        while True:
            try:
                if scheduler_lock.locked():
                    time.sleep(5)
                    continue
                with scheduler_lock:
                    lock_db = _db()
                    have_lock = False
                    try:
                        have_lock = _db_try_advisory_lock(lock_db, lock_id)
                    finally:
                        lock_db.close()
                    if not have_lock:
                        time.sleep(5)
                        continue
                    try:
                        now = datetime.now(timezone.utc)
                        _enqueue_due_scheduled_jobs(now)
                        _run_sync_queue_once(max_jobs=10)
                    finally:
                        unlock_db = _db()
                        try:
                            _db_advisory_unlock(unlock_db, lock_id)
                        finally:
                            unlock_db.close()
                time.sleep(20)
            except Exception as e:
                _app_log("ERROR", "scheduler", "scheduler_loop_error", metadata={"error": str(e)})
                time.sleep(20)

    @app.get("/metrics")
    @limiter.limit("30 per minute")
    def metrics():
        if cfg.METRICS_AUTH_TOKEN:
            auth = (request.headers.get("Authorization") or "").strip()
            expected = f"Bearer {cfg.METRICS_AUTH_TOKEN}"
            if not hmac.compare_digest(auth, expected):
                return jsonify({"error": "Unauthorized"}), 401
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    @app.get("/health")
    @limiter.limit("60 per minute")
    def health():
        health_cache_key = _cache_key("health", deep=True)
        try:
            r = get_redis()
            cached = r.get(health_cache_key)
            if isinstance(cached, (str, bytes, bytearray)) and len(cached) > 0:
                cache_access_total.labels(endpoint="health", status="hit").inc()
                return Response(cached, mimetype="application/json")
            cache_access_total.labels(endpoint="health", status="miss").inc()
        except Exception:
            cache_access_total.labels(endpoint="health", status="error").inc()
            r = None

        checks = {"database": False, "redis": False, "misp": False, "crowdsec": False}
        # DB check
        try:
            db = _db(read_only=True)
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
        payload = {"status": status, "checks": checks}
        body = json.dumps(payload, separators=(",", ":"))
        if r is not None:
            try:
                r.setex(health_cache_key, max(1, cfg.HEALTH_CACHE_TTL), body)
            except Exception:
                cache_access_total.labels(endpoint="health", status="error").inc()
        return Response(body, mimetype="application/json")

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
            min_conf = int(request.args.get("min_conf")) if request.args.get("min_conf") else None
            max_conf = int(request.args.get("max_conf")) if request.args.get("max_conf") else None
        except ValueError:
            return jsonify({"error": "min_conf/max_conf must be integers"}), 400
        limit, offset = _parse_limit_offset(default_limit=1000, max_limit=max(1, cfg.QUERY_RESULT_LIMIT_MAX))
        if limit is None or offset is None:
            return jsonify({"error": "limit/offset must be integers"}), 400

        # Cache HTML response by params
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
            r = get_redis()
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
        except Exception as e:
            db.close()
            return jsonify({"error": str(e)}), 400
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
        # Dedicated endpoint: shortcut to /indicators with source preselected.
        src = (src or "").strip().lower()
        if not src or any(c in src for c in [' ', '\t', '\n', '\r', '/', '\\']):
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
            r = get_redis()
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
                    groups = query_correlations(
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
            r = get_redis()
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
        except Exception as e:
            db.close()
            return jsonify({"error": str(e)}), 400
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
            return send_file(
                p,
                mimetype=mime,
                as_attachment=True,
                download_name=f"indicators.{job.fmt}",
            )
        finally:
            db.close()

    
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
        cfg = Config()
        if not cfg.MISP_URL:
            return jsonify({"error": "MISP_URL not configured"}), 400
        # Clickable link target is shown in UI; redirect for convenience
        return ("", 302, {"Location": f"{cfg.MISP_URL.rstrip('/')}/events/view/{event_id}"})

    @app.get("/admin")
    @limiter.limit("30 per minute")
    def admin_panel():
        db = _db()
        try:
            _ensure_default_feeds(db)
            feeds = _read_feed_rows(db)
            feed_rows = db.scalars(select(FeedStats).order_by(FeedStats.source.asc(), FeedStats.source_id.asc())).all()
            settings_count = int(db.scalar(select(func.count()).select_from(AppSetting)) or 0)
            proxy_conf = {
                "proxy_http_url": _get_setting(db, "proxy.http_url", os.getenv("HTTP_PROXY", "")),
                "proxy_https_url": _get_setting(db, "proxy.https_url", os.getenv("HTTPS_PROXY", "")),
                "proxy_no_proxy": _get_setting(db, "proxy.no_proxy", os.getenv("NO_PROXY", "")),
                "trusted_proxy_count": _get_setting(db, "proxy.trusted_proxy_count", os.getenv("TRUSTED_PROXY_COUNT", "0")),
            }
            feed_states = {f.source_id: _read_feed_config_state(db, f) for f in feeds}
            latest_runs = {
                f.source_id: db.scalar(
                    select(FeedRun).where(FeedRun.feed_source_id == f.source_id).order_by(FeedRun.started_at.desc()).limit(1)
                )
                for f in feeds
            }
            scheduler_heartbeat = _get_setting(db, "scheduler.heartbeat", "")
        finally:
            db.close()

        status_msg = request.args.get("msg", "")
        feed_rows_html = "".join(
            [
                (
                    "<tr>"
                    f"<td>{_esc(str(row.source))}</td>"
                    f"<td>{_esc(str(row.source_id or ''))}</td>"
                    f"<td>{_esc(str(row.last_fetch_status or ''))}</td>"
                    f"<td>{_esc(str(row.last_update or ''))}</td>"
                    f"<td>{_esc(str(row.last_fetch_error or ''))}</td>"
                    "</tr>"
                )
                for row in feed_rows
            ]
        )
        if not feed_rows_html:
            feed_rows_html = "<tr><td colspan='5'>No feed statistics yet.</td></tr>"

        source_ctrl_html = "".join(
            [
                (
                    "<tr>"
                    f"<td><code>{_esc(f.source_id)}</code><br/>{_esc(f.display_name)}<br/><small>{_esc(f.source_type)}</small></td>"
                    f"<td>{'enabled' if feed_states[f.source_id]['enabled'] else 'disabled'}</td>"
                    f"<td>{_esc(f.schedule_cron)}</td>"
                    f"<td>{'OK' if feed_states[f.source_id]['ready'] else 'Incomplete: ' + _esc(', '.join(feed_states[f.source_id]['missing']))}</td>"
                    f"<td>{_esc(str(getattr(latest_runs.get(f.source_id), 'status', 'never')))}</td>"
                    f"<td>{_esc(str(getattr(latest_runs.get(f.source_id), 'started_at', 'n/a')))}</td>"
                    f"<td><form method='post' action='/admin/feed-toggle' style='display:inline'>"
                    f"<input type='hidden' name='source' value='{_esc(f.source_id)}'/>"
                    f"<input type='hidden' name='enabled' value='{'0' if feed_states[f.source_id]['enabled'] else '1'}'/>"
                    f"<button type='submit'>{'Disable' if feed_states[f.source_id]['enabled'] else 'Enable'}</button>"
                    "</form> "
                    f"<a href='/admin/feed/{_esc(f.source_id)}/configure'>Configure</a> "
                    f"<form method='post' action='/admin/sync' style='display:inline'>"
                    f"<input type='hidden' name='source' value='{_esc(f.source_id)}'/>"
                    f"<button type='submit' {'disabled' if not feed_states[f.source_id]['ready'] else ''}>Sync now</button>"
                    "</form> "
                    f"<form method='post' action='/admin/feed/{_esc(f.source_id)}/delete' style='display:inline' onsubmit='return confirm(\"Delete feed {_esc(f.source_id)}?\")'>"
                    "<button type='submit'>Delete</button>"
                    "</form></td>"
                    "</tr>"
                )
                for f in feeds
            ]
        )

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Admin Controls</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }}
    body[data-theme="light"] {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
    body[data-theme="dark"] {{ --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }}
    body:not([data-theme]) {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }}
    .topbar nav a {{ margin-right:.8rem; }}
    .card {{ border: 1px solid var(--line); border-radius: 16px; padding: 1rem; margin-bottom: 1rem; background: var(--card); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: .5rem; text-align: left; vertical-align: top; }}
    input[type=text], input[type=password] {{ width: 100%; padding: .45rem; border-radius: 8px; border: 1px solid var(--line); background: var(--bg); color: var(--fg); }}
    button {{ padding: .5rem .8rem; border-radius: 8px; border: 1px solid var(--line); background: var(--card); color: var(--fg); }}
    fieldset {{ border: 1px solid var(--line); border-radius: 12px; margin: .75rem 0; padding: .75rem; }}
    .toast {{ border:1px solid var(--line); border-radius:10px; padding:.55rem .7rem; margin:.5rem 0 1rem; background:var(--card); }}
  </style>
</head>
<body>
  <header class="topbar" id="globalTopbar">
    <nav>
      <a href="/">Overview</a>
      <a href="/indicators">Indicators</a>
      <a href="/admin">Admin</a>
      <a href="/logs">Logs</a>
    </nav>
    <button type="button" id="themeToggleGlobal">Toggle dark mode</button>
  </header>
  <h1>Admin Controls</h1>
  <p><strong>Stored settings:</strong> {settings_count}</p>
  <p><strong>Scheduler heartbeat:</strong> {_esc(scheduler_heartbeat or 'n/a')}</p>
  <div id="statusToast" class="toast" role="status" aria-live="polite">{_esc(status_msg)}</div>

  <div class="card">
    <h2>Configuration Panel (Global)</h2>
    <form method="post" action="/admin/global-config">
      <h3>Proxy Configuration</h3>
      <p><label>HTTP proxy <input type="text" name="proxy_http_url" value="{_esc(proxy_conf['proxy_http_url'])}" placeholder="http://proxy:8080"/></label></p>
      <p><label>HTTPS proxy <input type="text" name="proxy_https_url" value="{_esc(proxy_conf['proxy_https_url'])}" placeholder="http://proxy:8080"/></label></p>
      <p><label>No proxy list <input type="text" name="proxy_no_proxy" value="{_esc(proxy_conf['proxy_no_proxy'])}" placeholder="localhost,127.0.0.1,.internal"/></label></p>
      <p><label>Trusted proxy count <input type="text" name="trusted_proxy_count" value="{_esc(proxy_conf['trusted_proxy_count'])}" placeholder="0"/></label></p>
      <button type="submit">Save configuration</button>
    </form>
  </div>

  <div class="card">
    <h2>Manual Synchronization and Feed Management</h2>
    <h3>Add New Feed</h3>
    <form method="post" action="/admin/feed/new">
      <p><label>source_id <input type="text" name="source_id" placeholder="custom-feed-1" required></label></p>
      <p><label>display_name <input type="text" name="display_name" placeholder="Custom Feed" required></label></p>
      <p><label>source_type <input type="text" name="source_type" placeholder="misp|crowdsec|malwarebazaar|mwdb|abusech" required></label></p>
      <p><label>base_url <input type="text" name="base_url" placeholder="https://source.example.local"></label></p>
      <p><label>auth_type <input type="text" name="auth_type" placeholder="api_key"></label></p>
      <p><label>schedule_cron <input type="text" name="schedule_cron" value="*/15 * * * *"></label></p>
      <p><label><input type="checkbox" name="enabled" value="1" checked> enabled</label></p>
      <button type="submit">Add feed</button>
    </form>
    <form method="post" action="/admin/sync">
      <input type="hidden" name="source" value="all"/>
      <button type="submit">Sync all enabled sources</button>
    </form>
    <table>
      <thead><tr><th>Source</th><th>Enabled</th><th>Schedule</th><th>Config Readiness</th><th>Last Run Status</th><th>Last Run At</th><th>Actions</th></tr></thead>
      <tbody>{source_ctrl_html}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Feed Statistics</h2>
    <table>
      <thead><tr><th>Source</th><th>Source ID</th><th>Last Status</th><th>Last Update</th><th>Last Error</th></tr></thead>
      <tbody>{feed_rows_html}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Logs</h2>
    <p><a href="/logs">Open logs tab</a></p>
  </div>
  <script>
    const themeKey = 'ioc-theme';
    const preferredTheme = localStorage.getItem(themeKey);
    if (preferredTheme === 'dark' || preferredTheme === 'light') {{
      document.body.setAttribute('data-theme', preferredTheme);
    }}
    const themeToggle = document.getElementById('themeToggleGlobal');
    if (themeToggle) {{
      themeToggle.addEventListener('click', () => {{
        const curr = document.body.getAttribute('data-theme') || 'light';
        const next = curr === 'dark' ? 'light' : 'dark';
        document.body.setAttribute('data-theme', next);
        localStorage.setItem(themeKey, next);
      }});
    }}
    const toast = document.getElementById('statusToast');
    if (toast && !toast.textContent.trim()) {{
      toast.style.display = 'none';
    }}
  </script>
</body>
</html>
"""

    @app.post("/admin/global-config")
    @limiter.limit("20 per minute")
    def admin_save_global_config():
        db = _db()
        try:
            _set_setting(db, "proxy.http_url", (request.form.get("proxy_http_url") or "").strip())
            _set_setting(db, "proxy.https_url", (request.form.get("proxy_https_url") or "").strip())
            _set_setting(db, "proxy.no_proxy", (request.form.get("proxy_no_proxy") or "").strip())
            _set_setting(db, "proxy.trusted_proxy_count", (request.form.get("trusted_proxy_count") or "0").strip())

            db.commit()
            _write_proxy_env(db)
            _audit("admin_config_update", "app_settings", None, {"updated": True})
            return redirect(url_for("admin_panel", msg="Global configuration saved."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Configuration save failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed/new")
    @limiter.limit("20 per minute")
    def admin_add_feed():
        source_id = (request.form.get("source_id") or "").strip().lower()
        display_name = (request.form.get("display_name") or "").strip()
        source_type = (request.form.get("source_type") or "").strip().lower()
        base_url = (request.form.get("base_url") or "").strip() or None
        auth_type = (request.form.get("auth_type") or "").strip() or None
        schedule_cron = (request.form.get("schedule_cron") or "*/15 * * * *").strip()
        enabled = (request.form.get("enabled") or "").strip().lower() in {"1", "true", "yes", "on"}
        if not source_id or not display_name or source_type not in set(_source_templates().keys()):
            return redirect(url_for("admin_panel", msg="Invalid feed definition."))
        db = _db()
        try:
            _ensure_default_feeds(db)
            existing = db.scalar(select(Feed).where(Feed.source_id == source_id))
            if existing and not existing.deleted:
                return redirect(url_for("admin_panel", msg=f"Feed {source_id} already exists."))
            if existing and existing.deleted:
                existing.deleted = False
                existing.display_name = display_name
                existing.source_type = source_type
                existing.base_url = base_url
                existing.auth_type = auth_type
                existing.schedule_cron = schedule_cron
                existing.enabled = enabled
            else:
                db.add(
                    Feed(
                        source_id=source_id,
                        source_type=source_type,
                        display_name=display_name,
                        base_url=base_url,
                        auth_type=auth_type,
                        schedule_cron=schedule_cron,
                        enabled=enabled,
                        deleted=False,
                    )
                )
            db.commit()
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} added."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Add feed failed: {e}"))
        finally:
            db.close()

    @app.get("/admin/feed/<source_id>/configure")
    @limiter.limit("30 per minute")
    def admin_feed_configure(source_id: str):
        source_id = (source_id or "").strip().lower()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            state = _read_feed_config_state(db, feed)
        finally:
            db.close()
        fields_html = "".join(
            [
                (
                    f"<p><label>{_esc(str(f['label']))} "
                    f"<input type='{'password' if f.get('secret') else 'text'}' "
                    f"name='{_esc(str(f.get('input_name') or ''))}' "
                    f"value='{_esc(str(f.get('value') or ''))}' "
                    f"placeholder='{_esc(str(f.get('placeholder') or ''))}'/></label>"
                    + (f" Current: {_esc(str(f.get('current_masked') or ''))}" if f.get("secret") else "")
                    + "</p>"
                )
                for f in state["fields"]
            ]
        )
        return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/><title>Configure { _esc(source_id) }</title></head><body>
<h1>Configure feed: {_esc(source_id)}</h1>
<p>Status: {'OK' if state['ready'] else 'Incomplete: ' + _esc(', '.join(state['missing']))}</p>
<form method='post' action='/admin/feed/{_esc(source_id)}/configure'>
<p><label>Display name <input type='text' name='display_name' value='{_esc(feed.display_name)}' required/></label></p>
<p><label>Base URL <input type='text' name='base_url' value='{_esc(str(feed.base_url or ""))}'/></label></p>
<p><label>Schedule cron <input type='text' name='schedule_cron' value='{_esc(feed.schedule_cron)}'/></label></p>
{fields_html}
<button type='submit'>Save feed configuration</button> <a href='/admin'>Back</a>
</form></body></html>"""

    @app.post("/admin/feed/<source_id>/configure")
    @limiter.limit("20 per minute")
    def admin_feed_configure_save(source_id: str):
        source_id = (source_id or "").strip().lower()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            feed.display_name = (request.form.get("display_name") or feed.display_name).strip() or feed.display_name
            feed.base_url = (request.form.get("base_url") or "").strip() or None
            feed.schedule_cron = (request.form.get("schedule_cron") or "*/15 * * * *").strip()
            state = _read_feed_config_state(db, feed)
            missing: List[str] = []
            for f in state["fields"]:
                input_name = str(f["input_name"])
                incoming = (request.form.get(input_name) or "").strip()
                if f["key"] == "base_url":
                    continue
                if f.get("secret"):
                    if incoming:
                        _set_setting(db, _feed_secret_key(feed.source_id, str(f["key"])), incoming, secret=True)
                    elif f.get("required") and not _get_setting(db, _feed_secret_key(feed.source_id, str(f["key"])), "", secret=True):
                        missing.append(str(f["label"]))
                else:
                    _set_setting(db, _feed_value_key(feed.source_id, str(f["key"])), incoming, secret=False)
                    if f.get("required") and not incoming:
                        missing.append(str(f["label"]))
            if feed.source_type in {"misp", "mwdb"} and not (feed.base_url or "").strip():
                missing.append("Base URL")
            if missing:
                db.rollback()
                return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Missing required fields: {', '.join(missing)}"))
            db.commit()
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} configuration saved."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Configure feed failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed-toggle")
    @limiter.limit("20 per minute")
    def admin_feed_toggle():
        source_name = (request.form.get("source") or "").strip().lower()
        enabled = (request.form.get("enabled") or "").strip().lower() in {"1", "true", "yes", "on"}
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_name, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Invalid source for feed toggle."))
            feed.enabled = enabled
            db.commit()
            _audit("admin_feed_toggle", "feed", None, {"source": source_name, "enabled": enabled})
            return redirect(url_for("admin_panel", msg=f"Feed {source_name} {'enabled' if enabled else 'disabled'}"))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Feed toggle failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed/<source_id>/delete")
    @limiter.limit("20 per minute")
    def admin_feed_delete(source_id: str):
        source_id = (source_id or "").strip().lower()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            feed.deleted = True
            feed.enabled = False
            db.commit()
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} deleted (soft)."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Delete feed failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/sync")
    @limiter.limit("10 per minute")
    def admin_sync():
        source_name = (request.form.get("source") or "").strip().lower()
        if not source_name:
            return redirect(url_for("admin_panel", msg="Missing source for sync."))
        db = _db()
        try:
            _app_log("INFO", "scheduler", "manual_sync_requested", metadata={"source": source_name}, db=db)
            _ensure_default_feeds(db)
            feed_rows = _read_feed_rows(db)
            feed_map = {f.source_id: f for f in feed_rows}
            targets: List[Feed] = []
            if source_name == "all":
                targets = [f for f in feed_rows if f.enabled]
            elif source_name not in feed_map:
                return redirect(url_for("admin_panel", msg="Invalid source for sync."))
            else:
                targets = [feed_map[source_name]]

            blocked: List[str] = []
            queued: List[str] = []
            reused: List[str] = []
            for feed in targets:
                state = _read_feed_config_state(db, feed)
                if not state["ready"]:
                    blocked.append(f"{feed.source_id} (missing: {', '.join(state['missing'])})")
                    continue
                job, created = _enqueue_sync_job(feed, trigger_type="manual", db=db)
                if created:
                    queued.append(job.job_id)
                else:
                    reused.append(job.job_id)

            if source_name != "all" and not queued and not reused:
                return redirect(url_for("admin_panel", msg=f"Cannot sync {source_name}: configuration incomplete."))

            _audit("manual_sync", "feed", None, {"source": source_name, "queued": queued, "reused": reused, "blocked": blocked})
            _app_log("INFO", "scheduler", "manual_sync_queued", metadata={"source": source_name, "queued": queued, "reused": reused, "blocked": blocked}, db=db)
            msg = f"Sync queued for {source_name}."
            if queued:
                msg += f" New jobs: {', '.join(queued)}."
            if reused:
                msg += f" Already queued/running: {', '.join(reused)}."
            if blocked:
                msg += f" Skipped incomplete feeds: {', '.join(blocked)}."
            return redirect(url_for("admin_panel", msg=msg))
        except Exception as e:
            logger.exception("admin_sync_failed")
            _app_log("ERROR", "scheduler", "manual_sync_failed", metadata={"source": source_name, "error": str(e)}, db=db)
            return redirect(url_for("admin_panel", msg=f"Sync failed: {e}"))
        finally:
            db.close()

    @app.post("/api/sync")
    @limiter.limit("20 per minute")
    def api_sync():
        payload = request.get_json(silent=True) or {}
        source_name = str(payload.get("source") or request.args.get("source") or "").strip().lower()
        if not source_name:
            return jsonify({"error": "Missing source"}), 400
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed_rows = _read_feed_rows(db)
            feed_map = {f.source_id: f for f in feed_rows}
            if source_name == "all":
                targets = [f for f in feed_rows if f.enabled]
            elif source_name in feed_map:
                targets = [feed_map[source_name]]
            else:
                return jsonify({"error": "Invalid source"}), 400

            blocked: List[str] = []
            queued: List[Dict[str, Any]] = []
            for feed in targets:
                state = _read_feed_config_state(db, feed)
                if not state["ready"]:
                    blocked.append(feed.source_id)
                    continue
                job, created = _enqueue_sync_job(feed, trigger_type="manual", db=db)
                queued.append({"feed_source_id": feed.source_id, "job_id": job.job_id, "created": created})

            if source_name != "all" and not queued:
                return jsonify({"error": "Configuration incomplete", "source": source_name, "blocked": blocked}), 400
            return jsonify({"source": source_name, "jobs": queued, "blocked": blocked}), 202
        finally:
            db.close()

    @app.get("/api/logs")
    @limiter.limit("60 per minute")
    def api_logs():
        db = _db(read_only=True)
        try:
            stmt = select(AppLog).order_by(AppLog.created_at.desc())
            feed = (request.args.get("feed") or "").strip()
            job_id = (request.args.get("job_id") or request.args.get("run_id") or "").strip()
            level = (request.args.get("level") or "").strip().upper()
            component = (request.args.get("component") or "").strip()
            since = (request.args.get("since") or "").strip()
            until = (request.args.get("until") or "").strip()
            if feed:
                stmt = stmt.where(AppLog.feed_source_id == feed)
            if job_id:
                stmt = stmt.where(AppLog.run_id == job_id)
            if level:
                stmt = stmt.where(AppLog.level == level)
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
            limit = min(500, max(1, int(request.args.get("limit", "200"))))
            rows = list(db.scalars(stmt.limit(limit)).all())
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

    @app.get("/api/runs/current")
    @limiter.limit("60 per minute")
    def api_runs_current():
        db = _db(read_only=True)
        try:
            running = list(db.scalars(select(FeedRun).where(FeedRun.status == "running").order_by(FeedRun.started_at.desc()).limit(20)).all())
            latest = list(db.scalars(select(FeedRun).order_by(FeedRun.started_at.desc()).limit(20)).all())
            queued_jobs = list(db.scalars(select(SyncJob).where(SyncJob.status.in_(["queued", "running"])).order_by(SyncJob.created_at.asc()).limit(50)).all())
            heartbeat = _get_setting(db, "scheduler.heartbeat", "")
            return jsonify(
                {
                    "scheduler_heartbeat": heartbeat,
                    "active_run_id": scheduler_state.get("active_run_id"),
                    "active_job_id": scheduler_state.get("active_job_id"),
                    "queued_jobs": [
                        {
                            "job_id": j.job_id,
                            "feed_source_id": j.feed_source_id,
                            "status": j.status,
                            "trigger_type": j.trigger_type,
                            "created_at": str(j.created_at),
                            "started_at": str(j.started_at),
                        }
                        for j in queued_jobs
                    ],
                    "running": [
                        {"feed_source_id": r.feed_source_id, "run_id": r.run_id, "status": r.status, "started_at": str(r.started_at)}
                        for r in running
                    ],
                    "latest": [
                        {
                            "feed_source_id": r.feed_source_id,
                            "run_id": r.run_id,
                            "status": r.status,
                            "started_at": str(r.started_at),
                            "finished_at": str(r.finished_at),
                            "error": r.error,
                            "fetched_count": r.fetched_count,
                        }
                        for r in latest
                    ],
                }
            )
        finally:
            db.close()

    @app.get("/logs")
    @limiter.limit("30 per minute")
    def logs_page():
        return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>Logs</title></head><body>
<h1>Logs</h1><p><a href="/admin">Back to admin</a></p>
<form id="filters">
  <label>Feed <input name="feed" /></label>
  <label>Job ID <input name="job_id" /></label>
  <label>Level <input name="level" placeholder="INFO|WARN|ERROR" /></label>
  <label>Component <input name="component" placeholder="scheduler|fetcher|parser|exporter" /></label>
  <label>Since <input name="since" placeholder="2026-02-26T00:00:00Z" /></label>
  <label>Until <input name="until" placeholder="2026-02-26T23:59:59Z" /></label>
  <label><input type="checkbox" id="autorefresh" checked/> auto-refresh</label>
  <button type="submit">Apply</button>
  <button type="button" id="copyBtn">Copy visible logs</button>
</form>
<pre id="out" style="white-space: pre-wrap; border:1px solid #ccc; padding:10px; min-height:300px;"></pre>
<script>
function buildQuery(){const fd=new FormData(document.getElementById('filters'));const p=new URLSearchParams();for(const [k,v] of fd.entries()){if((v||'').trim())p.set(k,v);}p.set('limit','200');return p.toString();}
async function refreshLogs(){const q=buildQuery();const r=await fetch('/api/logs?'+q);const d=await r.json();const lines=(d.items||[]).map(x=>`[${x.created_at}] ${x.level} ${x.component} ${x.feed_source_id||'-'} ${x.run_id||'-'} ${x.message} ${JSON.stringify(x.metadata||{})}`);document.getElementById('out').textContent=lines.length ? lines.join('\\n') : 'No logs found for current filters.';}
document.getElementById('filters').addEventListener('submit',(e)=>{e.preventDefault();refreshLogs();});
document.getElementById('copyBtn').addEventListener('click',async()=>{await navigator.clipboard.writeText(document.getElementById('out').textContent||'');});
setInterval(()=>{if(document.getElementById('autorefresh').checked)refreshLogs();},5000);refreshLogs();
</script></body></html>"""

    if cfg.ENABLE_BACKGROUND_JOBS and not app.config.get("TESTING"):
        Thread(target=_scheduler_loop, daemon=True).start()

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
    :root {{ color-scheme: light dark; }}
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }}
    body[data-theme="light"] {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
    body[data-theme="dark"] {{ --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }}
    body:not([data-theme]) {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }}
    .topbar nav a {{ margin-right:.8rem; }}
    .card {{ border: 1px solid var(--line); border-radius: 16px; padding: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,.06); margin-bottom: 1rem; background: var(--card); }}
    a {{ color: #0b5; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 0.5rem; text-align: left; }}
    .skip-link {{ position: absolute; left: -9999px; top: auto; width: 1px; height: 1px; overflow: hidden; }}
    .skip-link:focus {{ left: 1rem; top: 1rem; width: auto; height: auto; background: #fff; padding: .5rem; border: 1px solid #000; }}
  </style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<header class="topbar" id="globalTopbar">
  <nav>
    <a href="/">Overview</a>
    <a href="/indicators">Indicators</a>
    <a href="/admin">Admin</a>
    <a href="/logs">Logs</a>
  </nav>
</header>
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
    def _query_escape(value: str) -> str:
        return (value or "").replace("\\", "\\\\").replace('"', '\\"')

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
            q_row = f'value:"{_query_escape(ind.value)}" AND source:"{_query_escape(ind.source)}"'
            exports = " ".join([
                f"<a href='/indicators/{fmt}?{_esc(urlencode({'q': q_row}))}' aria-label='Export indicator in {fmt} format'>{fmt.upper()}</a>"
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

    active_query: Dict[str, str] = {}
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

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Indicators</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }}
    body[data-theme="light"] {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --muted: #64748b; --line: #dbe1ea; }}
    body[data-theme="dark"] {{ --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --muted: #94a3b8; --line: #334155; }}
    body:not([data-theme]) {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --muted: #64748b; --line: #dbe1ea; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }}
    .topbar nav a {{ margin-right:.8rem; }}
    .toolbar {{ display: grid; grid-template-columns: 1fr; gap: .75rem; margin-bottom: 1rem; }}
    .filter-summary {{ position: sticky; top: 0; z-index: 2; padding: .5rem .75rem; border: 1px solid var(--line); border-radius: 10px; background: var(--card); margin-bottom: .75rem; }}
    .row {{ display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }}
    input[type=text] {{ width: 100%; padding: .6rem; border-radius: 12px; border: 1px solid var(--line); background: var(--bg); color: var(--fg); }}
    select {{ padding: .5rem; border-radius: 12px; border: 1px solid var(--line); background: var(--bg); color: var(--fg); }}
    button {{ padding: .55rem .8rem; border-radius: 12px; border: 1px solid var(--line); background: var(--card); color: var(--fg); cursor: pointer; }}
    button:focus, a:focus, input:focus, select:focus {{ outline: 3px solid #000; outline-offset: 2px; }}
    .card {{ border: 1px solid var(--line); border-radius: 16px; padding: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,.06); margin-bottom: 1rem; background: var(--card); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 0.5rem; text-align: left; vertical-align: top; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 999px; border: 1px solid var(--line); font-size: .85rem; }}
    .tag {{ display: inline-block; padding: .1rem .45rem; border-radius: 999px; border: 1px solid var(--line); font-size: .8rem; margin-right: .25rem; margin-bottom: .15rem; }}
    .confbar {{ width: 140px; height: 12px; border: 1px solid var(--line); border-radius: 999px; overflow: hidden; }}
    .confbar-in {{ height: 100%; background: var(--muted); }}
    .b-ip{{}} .b-domain{{}} .b-url{{}} .b-hash{{}} .b-email{{}} .b-other{{}}
    .b-white{{}} .b-green{{}} .b-amber{{}} .b-red{{}}
    .help {{ font-size: .95rem; }}
    .subtle {{ color: var(--muted); font-size: .9rem; }}
    .pager {{ display:flex; gap:.6rem; align-items:center; flex-wrap:wrap; margin: .75rem 0; }}
    .pager a, .pager span {{ padding:.35rem .6rem; border:1px solid var(--line); border-radius:8px; }}
    .status-live {{ min-height: 1.2rem; }}
    .skip-link {{ position: absolute; left: -9999px; top: auto; width: 1px; height: 1px; overflow: hidden; }}
    .skip-link:focus {{ left: 1rem; top: 1rem; width: auto; height: auto; background: var(--card); padding: .5rem; border: 1px solid var(--line); }}
    @media (prefers-reduced-motion: reduce) {{
      * {{ scroll-behavior: auto !important; transition: none !important; animation: none !important; }}
    }}
    @media (max-width: 760px) {{
      .row label {{ width: 100%; }}
      th:nth-child(7), td:nth-child(7), th:nth-child(8), td:nth-child(8) {{ display: none; }}
      .card {{ padding: .65rem; }}
    }}
  </style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<header class="topbar" id="globalTopbar">
  <nav>
    <a href="/">Overview</a>
    <a href="/indicators">Indicators</a>
    <a href="/admin">Admin</a>
    <a href="/logs">Logs</a>
  </nav>
  <button type="button" id="themeToggleGlobal">Toggle dark mode</button>
</header>
<main id="main-content" role="main">
  <div class="card">
    <h1>Unified Indicators</h1>
    <p class="subtle">
      <a href="/indicators" aria-label="Reset filters and show unfiltered results">Reset filters</a>
    </p>
    <div class="filter-summary" role="status" aria-live="polite">
      {"<p><strong>Active filters:</strong> yes</p>" if has_filters else "<p class='subtle'>Active filters: none</p>"}
      <p class="subtle">Results: <strong>{total_count}</strong> | Page <strong>{page}</strong> of <strong>{total_pages}</strong> | Limit <strong>{limit}</strong></p>
    </div>
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
          {"".join([f"<option value='{_esc(s)}' {'selected' if source==s else ''}>{_esc(s)}</option>" for s in source_options])}
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
        <a href="/indicators" aria-label="Return to unfiltered indicators view">Back to all indicators</a>
      </div>
    </form>

    {search_help}

    <p>Quick exports:
      <a href="/indicators/txt{_esc(filter_suffix)}" aria-label="Export current filtered results as TXT">TXT</a> ·
      <a href="/indicators/csv{_esc(filter_suffix)}" aria-label="Export current filtered results as CSV">CSV</a> ·
      <a href="/indicators/json{_esc(filter_suffix)}" aria-label="Export current filtered results as JSON">JSON</a> ·
      <a href="/indicators/fortigate{_esc(filter_suffix)}" aria-label="Export current filtered results as FortiGate list">FortiGate</a>
    </p>
  </div>

  <div class="card">
    <div class="pager" aria-label="Pagination controls">
      <a href="{_esc(prev_link)}" {"aria-disabled='true'" if offset <= 0 else ""}>Prev</a>
      <span>Page {page}/{total_pages}</span>
      <a href="{_esc(next_link)}" {"aria-disabled='true'" if next_offset >= total_count else ""}>Next</a>
    </div>
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
    <div class="pager" aria-label="Pagination controls (bottom)">
      <a href="{_esc(prev_link)}" {"aria-disabled='true'" if offset <= 0 else ""}>Prev</a>
      <span>Page {page}/{total_pages}</span>
      <a href="{_esc(next_link)}" {"aria-disabled='true'" if next_offset >= total_count else ""}>Next</a>
    </div>
  </div>
</main>

<script>
  const themeKey = 'ioc-theme';
  const preferredTheme = localStorage.getItem(themeKey);
  if (preferredTheme === 'dark' || preferredTheme === 'light') {{
    document.body.setAttribute('data-theme', preferredTheme);
  }} else {{
    const systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.body.setAttribute('data-theme', systemDark ? 'dark' : 'light');
  }}

  const themeToggle = document.getElementById('themeToggleGlobal');
  if (themeToggle) {{
    themeToggle.addEventListener('click', () => {{
      const curr = document.body.getAttribute('data-theme') || 'light';
      const next = curr === 'dark' ? 'light' : 'dark';
      document.body.setAttribute('data-theme', next);
      localStorage.setItem(themeKey, next);
    }});
  }}

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
