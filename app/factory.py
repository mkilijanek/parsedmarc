from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Dict, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, Response, jsonify, make_response, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.orm import Session
from werkzeug.exceptions import HTTPException

from .audit_integrity import signed_audit_hash, verify_audit_chain
from .cache import get_redis
from .config import Config
from .db import SessionLocal, get_session
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
    export_jobs_pending,
    generate_latest,
    request_count,
    request_duration,
    sync_job_retries_total,
    sync_jobs_queued,
    sync_jobs_running,
)
from .models import (
    AppLog,
    AppSetting,
    AuditLog,
    ExportJob,
    Feed,
    FeedRun,
    FeedStats,
    Indicator,
    SyncJob,
    tags_contains,
)
from .runtime_env import push_runtime_env_overrides, update_proxy_settings_from_mapping
from .query_parser import Term, Token, parse_kibana_query
from .routes import (
    register_api_v1_routes,
    register_auth_routes,
    register_health_blueprint,
    register_logs_routes,
    register_ops_routes,
    register_public_routes,
)
from .routes.auth import auth_surface_request_is_secure, canonical_https_url
from .security import enforce_allowed_hosts, get_client_ip, validate_search_query
from .services.common import (
    build_feed_session,
    configure_requests_tls_verify_from_env,
    redact_proxy_credentials,
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
            logger.warning("security_admin_auth_disabled", extra={"message": "ADMIN_AUTH_ENABLED is false. Admin panel is open to anyone. Use only in development/test environments."})
    if is_production and not cfg.SECURITY_ALLOW_PERMISSIVE_DEFAULTS:
        if cfg.ALLOWED_HOSTS == "*":
            raise RuntimeError("SECURITY ERROR: ALLOWED_HOSTS cannot be '*' in production. Set explicit hosts or SECURITY_ALLOW_PERMISSIVE_DEFAULTS=true.")
        if cfg.CORS_ORIGINS == "*":
            raise RuntimeError("SECURITY ERROR: CORS_ORIGINS cannot be '*' in production. Set explicit origins or SECURITY_ALLOW_PERMISSIVE_DEFAULTS=true.")

    app = Flask(__name__)
    app.config["SECRET_KEY"] = cfg.SECRET_KEY

    # SECURITY: Secure session cookie configuration
    app.config["SESSION_COOKIE_SECURE"] = bool(cfg.SESSION_COOKIE_SECURE_ENABLED)
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
        if read_only and cfg.DATABASE_READ_URL:
            return get_session(read_only=True)
        return get_session(read_only=False)

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
            retry_hint = f"<p>Retry-After: about {retry_after} seconds.</p>" if retry_after else ""
            html_body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login Temporarily Blocked</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 42rem; }}
    code {{ background: #f3f3f3; padding: .1rem .25rem; }}
  </style>
</head>
<body>
  <h1>Too Many Login Attempts</h1>
  <p>Admin login is temporarily rate-limited after repeated attempts from your IP address.</p>
  <p>Wait about {wait_minutes} minutes and try again with the currently configured <code>ADMIN_API_TOKEN</code>.</p>
  {retry_hint}
  {secure_hint}
  <p>Correlation ID: <code>{_esc(corr)}</code></p>
</body>
</html>"""
            response = make_response(html_body, 429)
            response.headers["Content-Type"] = "text/html; charset=utf-8"
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

    def _secret_enc_key_v2() -> bytes:
        return hashlib.blake2b(cfg.SECRET_KEY.encode("utf-8"), digest_size=32).digest()

    def _secret_enc_key_v1() -> bytes:
        return hashlib.sha256(cfg.SECRET_KEY.encode("utf-8")).digest()

    def _secret_encrypt(value: str) -> str:
        raw = (value or "").encode("utf-8")
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(_secret_enc_key_v2()).encrypt(nonce, raw, None)
        return "v2:" + base64.urlsafe_b64encode(nonce + cipher).decode("ascii")

    def _secret_decrypt(value: str) -> str:
        if not value:
            return ""
        if value.startswith("v2:"):
            try:
                blob = base64.urlsafe_b64decode(value[3:].encode("ascii"))
                if len(blob) < 13:
                    return ""
                nonce = blob[:12]
                cipher = blob[12:]
                plain = AESGCM(_secret_enc_key_v2()).decrypt(nonce, cipher, None)
                return plain.decode("utf-8")
            except Exception:
                return ""
        if not value.startswith("v1:"):
            return value
        try:
            blob = base64.urlsafe_b64decode(value[3:].encode("ascii"))
            if len(blob) < 48:
                return ""
            nonce = blob[:16]
            mac = blob[16:48]
            cipher = blob[48:]
            key = _secret_enc_key_v1()
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
        except Exception:
            return ""

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

    def _runtime_override_or_env(
        db: Session,
        *,
        setting_key: str,
        env_key: str,
        secret: bool = False,
    ) -> str:
        row = db.scalar(select(AppSetting).where(AppSetting.key == setting_key))
        if row is None:
            return str(os.environ.get(env_key) or "")
        if secret:
            return _secret_decrypt(row.value)
        return str(row.value or "")

    def _mask_secret(value: str) -> str:
        if not value:
            return ""
        tail = value[-4:] if len(value) >= 4 else value
        return "*" * max(4, len(value) - len(tail)) + tail

    def _read_feed_enabled(db: Session, source_name: str) -> bool:
        raw = _get_setting(db, f"feed.{source_name}.enabled", "1")
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _write_proxy_env(db: Session) -> None:
        update_proxy_settings_from_mapping(
            {
                "proxy.http_url": _get_setting(db, "proxy.http_url", ""),
                "proxy.https_url": _get_setting(db, "proxy.https_url", ""),
                "proxy.no_proxy": _get_setting(db, "proxy.no_proxy", ""),
                "proxy.ca_bundle_path": _get_setting(db, "proxy.ca_bundle_path", ""),
                "proxy.skip_tls_verify": _get_setting(db, "proxy.skip_tls_verify", "0"),
            }
        )

    def _bootstrap_runtime_settings() -> None:
        db = _db()
        try:
            _write_proxy_env(db)
        except Exception:
            logger.warning("runtime_settings_bootstrap_failed", exc_info=True)
        finally:
            db.close()

    def _extract_title_from_html(body: str) -> str:
        if not body:
            return ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
        if m:
            return html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())[:200]
        m2 = re.search(
            r"<meta[^>]+property=[\"']og:title[\"'][^>]+content=[\"']([^\"']+)[\"'][^>]*>",
            body,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if m2:
            return html.unescape(re.sub(r"\s+", " ", m2.group(1)).strip())[:200]
        return ""

    def _proxy_test_expected_match(target_key: str, title: str) -> bool:
        t = (title or "").lower()
        if target_key == "mwdb":
            return ("mwdb" in t) or ("malware" in t)
        if target_key == "abusech":
            return "abuse.ch" in t
        if target_key == "certpl":
            return ("cert" in t) or ("cert.pl" in t)
        return True

    def _run_proxy_test() -> List[Dict[str, Any]]:
        targets = [
            {"key": "mwdb", "name": "MWDB", "url": "https://mwdb.cert.pl"},
            {"key": "abusech", "name": "abuse.ch", "url": "https://abuse.ch"},
            {"key": "certpl", "name": "CERT.PL", "url": "https://cert.pl"},
        ]
        out: List[Dict[str, Any]] = []
        for target in targets:
            t0 = time.time()
            row: Dict[str, Any] = {
                "target": target["name"],
                "url": target["url"],
                "status": "ERROR",
                "http": None,
                "latency_ms": None,
                "title": "",
                "notes": "",
                "error": "",
            }
            try:
                with build_feed_session(source="admin_proxy_test") as session:
                    resp = session.get(target["url"], timeout=(5, 10))
                row["http"] = int(resp.status_code)
                row["latency_ms"] = int((time.time() - t0) * 1000)
                content_type = str(resp.headers.get("Content-Type") or "")
                title = _extract_title_from_html(resp.text or "")
                row["title"] = title
                title_ok = _proxy_test_expected_match(target["key"], title)
                status_code_ok = int(resp.status_code) < 400
                content_type_ok = bool(content_type.strip())
                if status_code_ok and title_ok and content_type_ok:
                    row["status"] = "OK"
                elif status_code_ok:
                    row["status"] = "WARNING"
                else:
                    row["status"] = "ERROR"
                notes = []
                if not content_type_ok:
                    notes.append("missing Content-Type")
                if not title_ok:
                    notes.append("title mismatch")
                row["notes"] = ", ".join(notes) if notes else "ok"
            except Exception as exc:
                row["latency_ms"] = int((time.time() - t0) * 1000)
                row["status"] = "ERROR"
                row["error"] = redact_proxy_credentials(str(exc))
                row["notes"] = "request failed"
            out.append(row)
        return out

    def _source_templates() -> Dict[str, Dict[str, Any]]:
        return {
            "misp": {
                "display_name": "MISP",
                "fields": [
                    {"key": "base_url", "label": "MISP URL", "secret": False, "required": True, "env": "MISP_URL", "placeholder": "https://misp.example.local"},
                    {"key": "api_key", "label": "MISP API key", "secret": True, "required": True, "env": "MISP_API_KEY", "placeholder": "Leave blank to keep current"},
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "MISP_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                ],
            },
            "crowdsec": {
                "display_name": "CrowdSec",
                "fields": [
                    {"key": "api_key", "label": "CrowdSec API key", "secret": True, "required": True, "env": "CROWDSEC_API_KEY", "placeholder": "Leave blank to keep current"},
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "CROWDSEC_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                ],
            },
            "malwarebazaar": {
                "display_name": "MalwareBazaar",
                "fields": [
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "MALWAREBAZAAR_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                ],
            },
            "mwdb": {
                "display_name": "MWDB",
                "fields": [
                    {"key": "base_url", "label": "MWDB URL", "secret": False, "required": True, "env": "MWDB_URL", "placeholder": "https://mwdb.example.local"},
                    {"key": "api_key", "label": "MWDB auth key", "secret": True, "required": True, "env": "MWDB_AUTH_KEY", "placeholder": "Leave blank to keep current"},
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "MWDB_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                    {"key": "tags", "label": "MWDB tags (comma-separated)", "secret": False, "required": False, "env": "MWDB_TAGS", "placeholder": "apt, malware"},
                    {"key": "days", "label": "MWDB days", "secret": False, "required": False, "env": "MWDB_DAYS", "placeholder": "30"},
                    {"key": "no_time_limit", "label": "No time limit", "secret": False, "required": False, "env": "MWDB_NO_TIME_LIMIT", "type": "checkbox"},
                ],
            },
            "abusech": {
                "display_name": "abuse.ch",
                "fields": [
                    {"key": "api_key", "label": "abuse.ch auth key", "secret": True, "required": False, "env": "ABUSECH_AUTH_KEY", "placeholder": "Leave blank to keep current"},
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "ABUSECH_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                    {"key": "threatfox_enabled", "label": "ThreatFox", "secret": False, "required": False, "env": "THREATFOX_ENABLED", "type": "checkbox"},
                    {"key": "urlhaus_enabled", "label": "URLhaus", "secret": False, "required": False, "env": "URLHAUS_ENABLED", "type": "checkbox"},
                    {"key": "feodotracker_enabled", "label": "FeodoTracker", "secret": False, "required": False, "env": "FEODOTRACKER_ENABLED", "type": "checkbox"},
                    {"key": "yaraify_enabled", "label": "YARAify", "secret": False, "required": False, "env": "YARAIFY_ENABLED", "type": "checkbox"},
                    {"key": "yaraify_auth_key", "label": "YARAify auth key", "secret": True, "required": False, "env": "YARAIFY_AUTH_KEY", "placeholder": "Leave blank to use abuse.ch auth key"},
                    {"key": "yaraify_identifier", "label": "YARAify identifier", "secret": False, "required": False, "env": "YARAIFY_IDENTIFIER", "placeholder": "Optional YARAify task identifier"},
                    {"key": "yaraify_lookup_hashes", "label": "YARAify lookup hashes", "secret": False, "required": False, "env": "YARAIFY_LOOKUP_HASHES", "placeholder": "Optional comma-separated hashes"},
                    {"key": "hunting_fplist_enabled", "label": "Hunting FPList", "secret": False, "required": False, "env": "HUNTING_FPLIST_ENABLED", "type": "checkbox"},
                    {"key": "hunting_auth_key", "label": "Hunting auth key", "secret": True, "required": False, "env": "HUNTING_AUTH_KEY", "placeholder": "Leave blank to use abuse.ch auth key"},
                    {"key": "hunting_fplist_format", "label": "Hunting FPList format", "secret": False, "required": False, "env": "HUNTING_FPLIST_FORMAT", "placeholder": "csv"},
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
                    enabled=(source_id != "misp"),
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
            input_type = str(field_def.get("type") or ("password" if secret else "text"))
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
                    "type": input_type,
                    "placeholder": str(field_def.get("placeholder") or ""),
                    "value": "" if secret else str(val),
                    "checked": (str(val).strip().lower() in {"1", "true", "yes", "on"}) if input_type == "checkbox" else False,
                    "current_masked": _mask_secret(str(val)) if secret else "",
                    "input_name": _field_input_name(key),
                    "env": str(field_def.get("env") or ""),
                }
            )
        if feed.source_type == "malwarebazaar":
            shared_key = _get_setting(db, _feed_secret_key("abusech", "api_key"), "", secret=True)
            if not (shared_key or cfg.ABUSECH_AUTH_KEY):
                missing.append("abuse.ch auth key (ABUSECH_AUTH_KEY)")
        return {
            "source_id": feed.source_id,
            "source_type": feed.source_type,
            "display_name": feed.display_name,
            "ready": len(missing) == 0,
            "missing": missing,
            "enabled": bool(feed.enabled),
            "fields": normalized_fields,
        }

    def _is_valid_http_url(value: str) -> bool:
        v = (value or "").strip().lower()
        return v.startswith("http://") or v.startswith("https://")

    def _validate_feed_form(feed: Feed, form_data: Any, state: Dict[str, Any], db: Session) -> List[str]:
        errors: List[str] = []
        schedule_cron = (form_data.get("schedule_cron") or "*/15 * * * *").strip()
        if len(schedule_cron.split()) != 5:
            errors.append("Invalid cron expression (expected 5 fields).")
        if feed.source_type in {"misp", "mwdb"}:
            base_url = (form_data.get("base_url") or "").strip()
            if not base_url:
                errors.append("Base URL is required.")
            elif not _is_valid_http_url(base_url):
                errors.append("Base URL must start with http:// or https://.")

        for f in state["fields"]:
            key = str(f["key"])
            input_name = str(f["input_name"])
            incoming = (form_data.get(input_name) or "").strip()
            if str(f.get("type") or "") == "checkbox":
                incoming = "1" if incoming.lower() in {"1", "true", "yes", "on"} else "0"
            if key in {"base_url"}:
                continue
            if bool(f.get("required")) and not incoming:
                current = _get_setting(
                    db,
                    _feed_secret_key(feed.source_id, key) if bool(f.get("secret")) else _feed_value_key(feed.source_id, key),
                    "",
                    secret=bool(f.get("secret")),
                )
                if not current:
                    errors.append(f"Missing required field: {f['label']}")

        if feed.source_type == "mwdb":
            days_raw = (form_data.get(_field_input_name("days")) or "").strip()
            no_limit = (form_data.get(_field_input_name("no_time_limit")) or "").strip().lower() in {"1", "true", "yes", "on"}
            if days_raw:
                try:
                    days_val = int(days_raw)
                    if days_val < 1 or days_val > 3650:
                        errors.append("MWDB days must be between 1 and 3650.")
                except ValueError:
                    errors.append("MWDB days must be an integer.")
            elif not no_limit:
                errors.append("Set MWDB days or enable No time limit.")

            tags_raw = (form_data.get(_field_input_name("tags")) or "").strip()
            if not tags_raw:
                errors.append("MWDB tags are required.")

        if feed.source_type == "abusech":
            toggles = {
                "threatfox_enabled": (form_data.get(_field_input_name("threatfox_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "urlhaus_enabled": (form_data.get(_field_input_name("urlhaus_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "feodotracker_enabled": (form_data.get(_field_input_name("feodotracker_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "yaraify_enabled": (form_data.get(_field_input_name("yaraify_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "hunting_fplist_enabled": (form_data.get(_field_input_name("hunting_fplist_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
            }
            if not any(toggles.values()):
                errors.append("Select at least one abuse.ch service.")
            if toggles["yaraify_enabled"]:
                has_identifier = bool((form_data.get(_field_input_name("yaraify_identifier")) or "").strip())
                has_hashes = bool((form_data.get(_field_input_name("yaraify_lookup_hashes")) or "").strip())
                if not has_identifier and not has_hashes:
                    current_identifier = _get_setting(db, _feed_value_key(feed.source_id, "yaraify_identifier"), "", secret=False)
                    current_hashes = _get_setting(db, _feed_value_key(feed.source_id, "yaraify_lookup_hashes"), "", secret=False)
                    if not current_identifier and not current_hashes:
                        errors.append("YARAify requires an identifier or lookup hashes.")

        return errors

    def _fetch_mwdb_orgs(base_url: str, api_key: str) -> List[Dict[str, str]]:
        if not base_url or not api_key:
            return []
        from .services.mwdb import fetch_mwdb_organizations
        try:
            return fetch_mwdb_organizations(base_url=base_url, auth_key=api_key, timeout_s=10)
        except Exception:
            return []

    def _get_feed_field_value(
        db: Session,
        feed: Feed,
        field: Dict[str, Any],
        form_data: Any | None = None,
    ) -> str:
        key = str(field.get("key") or "")
        input_name = str(field.get("input_name") or "")
        input_type = str(field.get("type") or "text")
        secret = bool(field.get("secret"))
        if key == "base_url":
            incoming = (form_data.get("base_url") if form_data is not None else None) or ""
            val = str(incoming).strip() or str(feed.base_url or "")
            return val
        stored = _get_setting(
            db,
            _feed_secret_key(feed.source_id, key) if secret else _feed_value_key(feed.source_id, key),
            "",
            secret=secret,
        )
        if form_data is None:
            return str(stored or "")
        if input_type == "checkbox":
            return "1" if str(form_data.get(input_name) or "").strip().lower() in {"1", "true", "yes", "on"} else "0"
        incoming = str(form_data.get(input_name) or "").strip()
        if secret and not incoming:
            return str(stored or "")
        return incoming

    def _test_feed_connection(feed: Feed, field_values: Dict[str, str]) -> tuple[bool, str]:
        source_type = (feed.source_type or "").strip().lower()
        timeout_s = 10
        if source_type == "mwdb":
            from .services.mwdb import test_mwdb_connection
            data = test_mwdb_connection(
                base_url=field_values.get("base_url", ""),
                auth_key=field_values.get("api_key", ""),
                timeout_s=timeout_s,
            )
            return True, f"MWDB connection OK. Organizations visible: {len(data.get('organizations', []))}."
        if source_type == "abusech":
            api_key = field_values.get("api_key", "")
            if not api_key:
                return False, "abuse.ch API key is required for connection test."
            with build_feed_session(source="abusech") as session:
                resp = session.post(
                    cfg.THREATFOX_API_URL,
                    headers={"Auth-Key": api_key, "User-Agent": "ioc-threat-platform/1.0"},
                    json={"query": "get_iocs", "days": 1},
                    timeout=timeout_s,
                )
                resp.raise_for_status()
            data = resp.json() if resp.content else {}
            status = str(data.get("query_status") or "ok")
            if status.lower() not in {"ok", "no_result"}:
                return False, f"abuse.ch test failed (query_status={status})."
            return True, f"abuse.ch connection OK (query_status={status})."
        if source_type == "misp":
            base_url = field_values.get("base_url", "").rstrip("/")
            api_key = field_values.get("api_key", "")
            if not base_url or not api_key:
                return False, "MISP URL and API key are required."
            with build_feed_session(source="misp") as session:
                resp = session.get(
                    f"{base_url}/users/view/me",
                    headers={"Authorization": api_key, "Accept": "application/json"},
                    timeout=timeout_s,
                    verify=cfg.MISP_VERIFY_SSL,
                )
                resp.raise_for_status()
            return True, "MISP connection OK."
        if source_type == "malwarebazaar":
            api_key = (cfg.ABUSECH_AUTH_KEY or "").strip()
            if not api_key:
                return False, "ABUSECH_AUTH_KEY is required for MalwareBazaar connection test."
            with build_feed_session(source="malwarebazaar") as session:
                resp = session.post(
                    cfg.MALWAREBAZAAR_API_URL,
                    headers={"Auth-Key": api_key, "User-Agent": "ioc-threat-platform/1.0"},
                    data={"query": "get_taginfo", "tag": "exe", "limit": "1"},
                    timeout=timeout_s,
                )
                resp.raise_for_status()
            data = resp.json() if resp.content else {}
            status = str(data.get("query_status") or "ok")
            if status.lower() not in {"ok", "no_result"}:
                return False, f"MalwareBazaar test failed (query_status={status})."
            return True, f"MalwareBazaar connection OK (query_status={status})."
        if source_type == "crowdsec":
            api_key = field_values.get("api_key", "")
            if not api_key:
                return False, "CrowdSec API key is required."
            list_ids = [x.strip() for x in (cfg.CROWDSEC_LISTS or "").split(",") if x.strip()]
            if not list_ids:
                return False, "Set CROWDSEC_LISTS to test CrowdSec connectivity."
            with build_feed_session(source="crowdsec") as session:
                resp = session.get(
                    f"https://api.crowdsec.net/v2/blocklists/{list_ids[0]}",
                    headers={"X-Api-Key": api_key},
                    timeout=timeout_s,
                )
                resp.raise_for_status()
            return True, "CrowdSec connection OK."
        return False, f"No connection test handler for source_type={source_type}."

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
                int(params.get("min_conf")) if params.get("min_conf") is not None else None,
                int(params.get("max_conf")) if params.get("max_conf") is not None else None,
                limit=int(params.get("limit", 100000)),
                offset=int(params.get("offset", 0)),
            )
            out_path: Path
            if fmt == "sentinel_graph":
                from .services.sentinel_graph import push_indicators_to_graph

                auth_mode = str(params.get("auth_mode") or _get_setting(db, "sentinel.auth_mode", cfg.AZURE_SENTINEL_AUTH_MODE)).strip() or "client_secret"
                result = push_indicators_to_graph(
                    indicators=rows,
                    tenant_id=str(params.get("tenant_id") or _get_setting(db, "sentinel.tenant_id", cfg.AZURE_SENTINEL_TENANT_ID)),
                    client_id=str(params.get("client_id") or _get_setting(db, "sentinel.client_id", cfg.AZURE_SENTINEL_CLIENT_ID)),
                    scope=str(params.get("scope") or _get_setting(db, "sentinel.scope", cfg.AZURE_SENTINEL_SCOPE)),
                    auth_mode=auth_mode,
                    client_secret=str(_get_setting(db, "sentinel.client_secret", cfg.AZURE_SENTINEL_CLIENT_SECRET, secret=True)),
                    cert_private_key_pem=str(_get_setting(db, "sentinel.cert_private_key_pem", cfg.AZURE_SENTINEL_CERT_PRIVATE_KEY_PEM, secret=True)),
                    cert_thumbprint=str(params.get("cert_thumbprint") or _get_setting(db, "sentinel.cert_thumbprint", cfg.AZURE_SENTINEL_CERT_THUMBPRINT)),
                    endpoint_url=str(params.get("endpoint_url") or _get_setting(db, "sentinel.endpoint_url", cfg.AZURE_SENTINEL_ENDPOINT_URL)),
                    chunk_size=int(params.get("chunk_size") or _get_setting(db, "sentinel.chunk_size", str(cfg.AZURE_SENTINEL_CHUNK_SIZE)) or cfg.AZURE_SENTINEL_CHUNK_SIZE),
                    timeout_s=max(1, int(cfg.FEED_HTTP_TIMEOUT_S)),
                )
                out_path = out_dir / f"{job_id}.json"
                out_path.write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
            else:
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
    scheduler_state: Dict[str, Any] = {
        "active_run_id": None,
        "active_job_id": None,
        "last_minute": {},
        "last_audit_integrity_check_at": None,
    }

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
            or (request.args.get("admin_token") or "").strip()
        )
        return bool(token) and hmac.compare_digest(token, expected)

    _bootstrap_runtime_settings()
    configure_requests_tls_verify_from_env()

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
        from .adapters import build_feed_registry

        registry = build_feed_registry()
        adapter = registry.get(str(feed.source_type))
        return {"source": feed.source_id, "result": adapter.execute()}

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
                max_retries=max(0, int(cfg.SYNC_JOB_MAX_RETRIES)),
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

    def _classify_sync_failure(exc: Exception) -> str:
        text = str(exc).lower()
        permanent_markers = (
            "incomplete config",
            "feed not found",
            "unknown source_type",
            "requires threatfox_auth_key",
            "requires yaraify_auth_key",
            "requires hunting_auth_key",
            "authentication failed",
            "invalid api key",
            "unauthorized",
            "forbidden",
        )
        if any(marker in text for marker in permanent_markers):
            return "permanent"
        return "transient"

    def _sync_retry_delay_s(retry_count: int) -> int:
        base = max(1, int(cfg.SYNC_JOB_RETRY_BASE_DELAY_S))
        max_delay = max(base, int(cfg.SYNC_JOB_RETRY_MAX_DELAY_S))
        return min(max_delay, base * (2 ** max(0, retry_count - 1)))

    def _execute_sync_job(job: SyncJobRef) -> Dict[str, Any]:
        run_id = job.job_id
        feed_source_id = str(job.feed_source_id or "")
        scheduler_state["active_job_id"] = job.job_id
        scheduler_state["active_run_id"] = run_id
        updates: Dict[str, str | None] = {}
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
                row.failure_class = None
                row.started_at = now
            db.commit()

            _app_log("INFO", "scheduler", "feed_sync_started", feed_source_id=feed_source_id, run_id=run_id, metadata={"trigger": job.trigger_type}, db=db)

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
                    updates[env_key] = _runtime_override_or_env(
                        db,
                        setting_key=_feed_secret_key(feed.source_id, str(f["key"])),
                        env_key=env_key,
                        secret=True,
                    )
                else:
                    updates[env_key] = _runtime_override_or_env(
                        db,
                        setting_key=_feed_value_key(feed.source_id, str(f["key"])),
                        env_key=env_key,
                        secret=False,
                    )
            if feed.source_type == "mwdb":
                updates["MWDB_ORGANIZATIONS"] = _runtime_override_or_env(
                    db,
                    setting_key=_feed_value_key(feed.source_id, "organizations"),
                    env_key="MWDB_ORGANIZATIONS",
                    secret=False,
                )
                updates["MWDB_MY_GROUP"] = _runtime_override_or_env(
                    db,
                    setting_key=_feed_value_key(feed.source_id, "my_group"),
                    env_key="MWDB_MY_GROUP",
                    secret=False,
                )
            if feed.source_type == "malwarebazaar":
                shared_key = _runtime_override_or_env(
                    db,
                    setting_key=_feed_secret_key("abusech", "api_key"),
                    env_key="ABUSECH_AUTH_KEY",
                    secret=True,
                )
                if shared_key:
                    updates["ABUSECH_AUTH_KEY"] = shared_key

            started = time.time()
            with push_runtime_env_overrides(updates):
                if feed.source_type == "misp":
                    timeout_s = max(1, int(cfg.MISP_SYNC_TIMEOUT_S))
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(_run_sync_worker_for_feed, feed)
                        try:
                            result = future.result(timeout=timeout_s)
                        except FuturesTimeoutError as e:
                            future.cancel()
                            raise TimeoutError(f"MISP sync timeout after {timeout_s}s") from e
                else:
                    result = _run_sync_worker_for_feed(feed)
            result_data = result.get("result")
            fetched_count = _aggregate_fetched_count(result_data)
            dur_ms = int((time.time() - started) * 1000)

            cancel_row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if cancel_row and cancel_row.status == "cancel_requested":
                run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
                if run:
                    run.status = "cancelled"
                    run.error = "cancelled by admin"
                    run.finished_at = datetime.now(timezone.utc)
                cancel_row.status = "cancelled"
                cancel_row.error = "cancelled by admin"
                cancel_row.finished_at = datetime.now(timezone.utc)
                cancel_row.result_json = {"cancelled": True, "duration_ms": dur_ms}
                db.commit()
                _app_log(
                    "WARNING",
                    "scheduler",
                    "feed_sync_cancelled",
                    feed_source_id=feed_source_id,
                    run_id=run_id,
                    metadata={"duration_ms": dur_ms},
                    db=db,
                )
                return {"source": feed_source_id, "cancelled": 1}

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
            _app_log("INFO", "scheduler", "feed_sync_completed", feed_source_id=feed_source_id, run_id=run_id, metadata={"duration_ms": dur_ms, "fetched_count": fetched_count}, db=db)
            return result
        except Exception as e:
            db.rollback()
            elapsed_s = 0
            try:
                elapsed_s = int(time.time() - started)  # type: ignore[name-defined]
            except Exception:
                elapsed_s = 0
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == run_id))
            if run:
                run.status = "failed"
                run.error = str(e)
                run.finished_at = datetime.now(timezone.utc)
            row = db.scalar(select(SyncJob).where(SyncJob.id == job.id))
            if row:
                failure_class = _classify_sync_failure(e)
                retry_count = int(row.retry_count or 0)
                max_retries = max(0, int(row.max_retries if row.max_retries is not None else cfg.SYNC_JOB_MAX_RETRIES))
                should_retry = failure_class == "transient" and retry_count < max_retries
                row.retry_count = retry_count + 1 if should_retry else retry_count
                row.failure_class = failure_class
                row.error = str(e)
                if should_retry:
                    delay_s = _sync_retry_delay_s(row.retry_count)
                    row.status = "queued"
                    row.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=delay_s)
                    row.finished_at = None
                    row.result_json = {
                        "retry_scheduled": True,
                        "retry_count": row.retry_count,
                        "max_retries": max_retries,
                        "delay_s": delay_s,
                        "failure_class": failure_class,
                    }
                    sync_job_retries_total.labels(source=str(job.feed_source_id), failure_class=failure_class).inc()
                    _app_log(
                        "WARNING",
                        "scheduler",
                        "sync_job_retry_scheduled",
                        feed_source_id=job.feed_source_id,
                        run_id=run_id,
                        metadata={
                            "error": str(e),
                            "retry_count": row.retry_count,
                            "max_retries": max_retries,
                            "delay_s": delay_s,
                            "next_attempt_at": str(row.next_attempt_at),
                        },
                        db=db,
                    )
                else:
                    row.status = "failed"
                    row.next_attempt_at = None
                    row.finished_at = datetime.now(timezone.utc)
                    row.result_json = {
                        "retry_scheduled": False,
                        "retry_count": retry_count,
                        "max_retries": max_retries,
                        "failure_class": failure_class,
                    }
            if job.feed_source_id == "misp":
                err_text = str(e).lower()
                timeout_hit = ("timeout" in err_text and elapsed_s >= max(1, int(cfg.MISP_SYNC_TIMEOUT_S)))
                connect_hit = ("connection" in err_text or "connect" in err_text)
                if timeout_hit or connect_hit:
                    misp_feed = db.scalar(select(Feed).where(Feed.source_id == "misp", Feed.deleted == False))  # noqa: E712
                    if misp_feed and misp_feed.enabled:
                        misp_feed.enabled = False
                        _app_log(
                            "WARNING",
                            "scheduler",
                            "misp_auto_disabled_after_connectivity_failure",
                            feed_source_id="misp",
                            run_id=run_id,
                            metadata={"elapsed_s": elapsed_s, "error": str(e), "timeout_s": int(cfg.MISP_SYNC_TIMEOUT_S)},
                            db=db,
                        )
            db.commit()
            _app_log("ERROR", "scheduler", "feed_sync_failed", feed_source_id=job.feed_source_id, run_id=run_id, metadata={"error": str(e)}, db=db)
            return {"source": job.feed_source_id, "error": str(e)}
        finally:
            scheduler_state["active_run_id"] = None
            scheduler_state["active_job_id"] = None
            db.close()

    def _dequeue_next_sync_job() -> SyncJobRef | None:
        db = _db()
        try:
            now = datetime.now(timezone.utc)
            stmt = (
                select(SyncJob)
                .where(
                    SyncJob.status == "queued",
                    or_(SyncJob.next_attempt_at.is_(None), SyncJob.next_attempt_at <= now),
                )
                .order_by(SyncJob.created_at.asc())
                .limit(1)
            )
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
            return SyncJobRef(
                id=int(job.id),
                job_id=str(job.job_id),
                feed_source_id=str(job.feed_source_id),
                trigger_type=str(job.trigger_type),
            )
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

    def _run_log_retention_if_due(now: datetime) -> None:
        retention_days = int(getattr(cfg, "LOG_RETENTION_DAYS", 90))
        if retention_days <= 0:
            return
        interval_s = 86400  # run at most once per day
        last = scheduler_state.get("last_log_retention_at")
        if isinstance(last, datetime) and (now - last).total_seconds() < interval_s:
            return
        cutoff = now.replace(tzinfo=None) - timedelta(days=retention_days)
        db = _db()
        try:
            deleted = db.execute(
                AppLog.__table__.delete().where(AppLog.created_at < cutoff)
            ).rowcount
            db.commit()
        except Exception:
            db.rollback()
            deleted = 0
        finally:
            db.close()
        scheduler_state["last_log_retention_at"] = now
        _app_log("INFO", "maintenance", "log_retention_cleanup", metadata={"deleted": deleted, "retention_days": retention_days})

    def _run_audit_integrity_check_if_due(now: datetime) -> None:
        interval_s = max(60, int(cfg.AUDIT_INTEGRITY_VERIFY_INTERVAL_S))
        last = scheduler_state.get("last_audit_integrity_check_at")
        if isinstance(last, datetime) and (now - last).total_seconds() < interval_s:
            return
        db = _db(read_only=True)
        try:
            rows = list(db.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all())
            result = verify_audit_chain(rows, secret_key=cfg.SECRET_KEY)
        finally:
            db.close()
        scheduler_state["last_audit_integrity_check_at"] = now
        _app_log(
            "INFO" if result["valid"] else "ERROR",
            "audit",
            "audit_integrity_verified" if result["valid"] else "audit_integrity_failed",
            metadata=result,
        )

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
                        _run_audit_integrity_check_if_due(now)
                        _run_log_retention_if_due(now)
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

    def _refresh_job_backlog_metrics() -> None:
        db = _db(read_only=True)
        try:
            queued = db.scalar(select(func.count()).select_from(SyncJob).where(SyncJob.status == "queued")) or 0
            running = db.scalar(select(func.count()).select_from(SyncJob).where(SyncJob.status == "running")) or 0
            pending = db.scalar(
                select(func.count()).select_from(ExportJob).where(ExportJob.status.in_(["queued", "running"]))
            ) or 0
            sync_jobs_queued.set(int(queued))
            sync_jobs_running.set(int(running))
            export_jobs_pending.set(int(pending))
        except Exception:
            logger.warning("metrics_job_backlog_refresh_failed", exc_info=True)
        finally:
            db.close()

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

    register_api_v1_routes(
        app,
        limiter=limiter,
        cfg=cfg,
        logger=logger,
        scheduler_state=scheduler_state,
        deps={
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
            "ADMIN_FEED_METRICS_WIDGET_HTML": ADMIN_FEED_METRICS_WIDGET_HTML,
            "ADMIN_FEED_METRICS_WIDGET_SCRIPT": ADMIN_FEED_METRICS_WIDGET_SCRIPT,
        },
    )

    if cfg.ENABLE_BACKGROUND_JOBS and not app.config.get("TESTING"):
        Thread(target=_scheduler_loop, daemon=True).start()

    return app

ADMIN_FEED_METRICS_WIDGET_HTML = """
  <div class="card" id="feedMetricsCard">
    <h2>Feed Statistics (Operational View)</h2>
    <form id="feedMetricsFilters" style="display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:.5rem;align-items:end">
      <label>Window
        <select id="feedMetricsWindow">
          <option value="24h">24h</option>
          <option value="7d" selected>7d</option>
          <option value="30d">30d</option>
        </select>
      </label>
      <label>Datasource
        <select id="feedMetricsDatasource">
          <option value="all">all</option>
          <option value="abusech">abusech</option>
          <option value="malwarebazaar">malwarebazaar</option>
          <option value="mwdb">mwdb</option>
          <option value="misp">misp</option>
          <option value="crowdsec">crowdsec</option>
        </select>
      </label>
      <label>Status
        <select id="feedMetricsStatusFilter">
          <option value="all">all</option>
          <option value="OK">OK</option>
          <option value="WARNING">WARNING</option>
          <option value="ERROR">ERROR</option>
          <option value="DISABLED">DISABLED</option>
          <option value="NOT_CONFIGURED">NOT_CONFIGURED</option>
        </select>
      </label>
      <label>Search
        <input type="text" id="feedMetricsSearch" placeholder="source id / display name"/>
      </label>
      <label>Per page
        <select id="feedMetricsPageSize">
          <option value="10" selected>10</option>
          <option value="25">25</option>
          <option value="50">50</option>
        </select>
      </label>
      <div style="display:flex;gap:.5rem">
        <button type="button" id="feedMetricsRefreshBtn">Refresh</button>
        <button type="button" id="feedMetricsCsvBtn">CSV visible</button>
      </div>
    </form>
    <div id="feedMetricsSummary" class="metrics-grid" aria-live="polite"></div>
    <div class="mini-chart-wrap">
      <svg id="feedMetricsChart" viewBox="0 0 800 120" role="img" aria-label="Feed fetched volume trend"></svg>
    </div>
    <div class="mini-chart-wrap">
      <svg id="feedAvailabilityChart" viewBox="0 0 800 120" role="img" aria-label="Feed availability trend"></svg>
    </div>
    <table>
      <thead>
        <tr>
          <th>Status</th>
          <th>Feed</th>
          <th>Runs</th>
          <th>Err rate</th>
          <th>Fetched</th>
          <th>Avg dur ms</th>
          <th>P95 ms</th>
        </tr>
      </thead>
      <tbody id="feedMetricsBody"><tr><td colspan="7">Loading...</td></tr></tbody>
    </table>
    <p id="feedMetricsPager">Page 1/1</p>
    <p id="feedMetricsStatus" role="status" aria-live="polite"></p>
  </div>
"""

ADMIN_FEED_METRICS_WIDGET_SCRIPT = """
(function () {
  const root = document.getElementById('feedMetricsCard');
  if (!root) { return; }
  const state = {
    items: [],
    filtered: [],
    page: 1,
    pageSize: 10,
    summary: {},
    timeseries: []
  };

  function esc(v) {
    return String(v || '').replace(/[&<>\"']/g, function (ch) {
      if (ch === '&') return '&amp;';
      if (ch === '<') return '&lt;';
      if (ch === '>') return '&gt;';
      if (ch === '\"') return '&quot;';
      return '&#39;';
    });
  }
  function num(v, fallback) {
    const n = Number(v);
    if (!Number.isFinite(n)) return fallback;
    return n;
  }
  function fmtPct(v) {
    const n = num(v, null);
    return n === null ? '-' : n.toFixed(2) + '%';
  }
  function fmtNum(v) {
    const n = num(v, null);
    return n === null ? '-' : String(Math.round(n));
  }
  function statusChip(status) {
    const val = String(status || 'UNKNOWN').toUpperCase();
    const cls = val.toLowerCase();
    return '<span class=\"status-chip ' + esc(cls) + '\">' + esc(val) + '</span>';
  }
  function setStatus(msg, isError) {
    const el = document.getElementById('feedMetricsStatus');
    if (!el) return;
    el.textContent = msg || '';
    el.style.color = isError ? '#991b1b' : '#166534';
  }

  function currentFilters() {
    return {
      window: (document.getElementById('feedMetricsWindow') || {}).value || '7d',
      datasource: (document.getElementById('feedMetricsDatasource') || {}).value || 'all',
      status: (document.getElementById('feedMetricsStatusFilter') || {}).value || 'all',
      q: ((document.getElementById('feedMetricsSearch') || {}).value || '').trim().toLowerCase(),
      pageSize: Math.max(1, parseInt(((document.getElementById('feedMetricsPageSize') || {}).value || '10'), 10) || 10)
    };
  }

  function applyFilters() {
    const f = currentFilters();
    state.pageSize = f.pageSize;
    state.filtered = (state.items || []).filter(function (item) {
      if (f.status !== 'all' && String(item.status || '').toUpperCase() !== f.status.toUpperCase()) return false;
      if (f.q) {
        const hay = (String(item.source_id || '') + ' ' + String(item.display_name || '') + ' ' + String(item.source_type || '')).toLowerCase();
        if (hay.indexOf(f.q) < 0) return false;
      }
      return true;
    });
    const pages = Math.max(1, Math.ceil(state.filtered.length / state.pageSize));
    if (state.page > pages) state.page = pages;
  }

  function renderSummary() {
    const s = state.summary || {};
    const cards = [
      ['Runs', fmtNum(s.runs_total)],
      ['Availability', fmtPct(s.availability_pct)],
      ['Error rate', fmtPct(s.error_rate_pct)],
      ['Fetched total', fmtNum(s.fetched_total)]
    ];
    const html = cards.map(function (it) {
      return '<div class=\"metric-card\"><div class=\"label\">' + esc(it[0]) + '</div><div class=\"value\">' + esc(it[1]) + '</div></div>';
    }).join('');
    const out = document.getElementById('feedMetricsSummary');
    if (out) out.innerHTML = html || '';
  }

  function renderChart() {
    const svg = document.getElementById('feedMetricsChart');
    if (!svg) return;
    const points = (state.timeseries || []).map(function (x) { return num(x.fetched_total, 0); });
    if (!points.length) {
      svg.innerHTML = '<text x=\"8\" y=\"20\" font-size=\"12\">No data for selected window.</text>';
      return;
    }
    let maxV = 1;
    for (let i = 0; i < points.length; i += 1) {
      if (points[i] > maxV) maxV = points[i];
    }
    const w = 800;
    const h = 120;
    const pad = 8;
    const dx = points.length > 1 ? (w - 2 * pad) / (points.length - 1) : 0;
    const coords = points.map(function (v, i) {
      const x = pad + (i * dx);
      const y = h - pad - ((v / maxV) * (h - 2 * pad));
      return x.toFixed(2) + ',' + y.toFixed(2);
    }).join(' ');
    svg.innerHTML = '<polyline fill=\"none\" stroke=\"#0ea5e9\" stroke-width=\"2\" points=\"' + coords + '\" />'
      + '<text x=\"8\" y=\"16\" font-size=\"11\">Fetched trend (window)</text>'
      + '<text x=\"8\" y=\"112\" font-size=\"11\">0</text>'
      + '<text x=\"760\" y=\"16\" font-size=\"11\">' + esc(String(maxV)) + '</text>';
  }
  function renderAvailabilityChart() {
    const svg = document.getElementById('feedAvailabilityChart');
    if (!svg) return;
    const points = (state.timeseries || []).map(function (x) {
      const runs = num(x.runs, 0);
      const ok = num(x.success_runs, 0);
      if (runs <= 0) return 0;
      return (ok / runs) * 100.0;
    });
    if (!points.length) {
      svg.innerHTML = '<text x=\"8\" y=\"20\" font-size=\"12\">No availability data for selected window.</text>';
      return;
    }
    const w = 800;
    const h = 120;
    const pad = 8;
    const dx = points.length > 1 ? (w - 2 * pad) / (points.length - 1) : 0;
    const coords = points.map(function (v, i) {
      const x = pad + (i * dx);
      const y = h - pad - ((v / 100.0) * (h - 2 * pad));
      return x.toFixed(2) + ',' + y.toFixed(2);
    }).join(' ');
    svg.innerHTML = '<polyline fill=\"none\" stroke=\"#22c55e\" stroke-width=\"2\" points=\"' + coords + '\" />'
      + '<text x=\"8\" y=\"16\" font-size=\"11\">Availability trend (%)</text>'
      + '<text x=\"8\" y=\"112\" font-size=\"11\">0%</text>'
      + '<text x=\"752\" y=\"16\" font-size=\"11\">100%</text>';
  }

  function visibleRows() {
    const start = (state.page - 1) * state.pageSize;
    return state.filtered.slice(start, start + state.pageSize);
  }

  function renderTable() {
    const rows = visibleRows();
    const body = document.getElementById('feedMetricsBody');
    if (!body) return;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan=\"7\">No feed metrics for current filters.</td></tr>';
    } else {
      body.innerHTML = rows.map(function (item) {
        const feed = esc(item.display_name || item.source_id || '-') + '<br/><small>' + esc(item.source_id || '-') + ' / ' + esc(item.source_type || '-') + '</small>';
        return '<tr>'
          + '<td>' + statusChip(item.status) + '</td>'
          + '<td>' + feed + '</td>'
          + '<td>' + esc(fmtNum(item.runs)) + '</td>'
          + '<td>' + esc(fmtPct(item.error_rate_pct)) + '</td>'
          + '<td>' + esc(fmtNum(item.fetched_total)) + '</td>'
          + '<td>' + esc(fmtNum(item.duration_avg_ms)) + '</td>'
          + '<td>' + esc(fmtNum(item.duration_p95_ms)) + '</td>'
          + '</tr>';
      }).join('');
    }
    const pages = Math.max(1, Math.ceil(state.filtered.length / state.pageSize));
    const pager = document.getElementById('feedMetricsPager');
    if (pager) {
      pager.innerHTML = 'Page ' + state.page + '/' + pages
        + ' <button type=\"button\" id=\"feedMetricsPrevBtn\"' + (state.page <= 1 ? ' disabled' : '') + '>Prev</button>'
        + ' <button type=\"button\" id=\"feedMetricsNextBtn\"' + (state.page >= pages ? ' disabled' : '') + '>Next</button>'
        + ' <small>(' + state.filtered.length + ' feeds)</small>';
      const prev = document.getElementById('feedMetricsPrevBtn');
      const next = document.getElementById('feedMetricsNextBtn');
      if (prev) prev.addEventListener('click', function () { state.page = Math.max(1, state.page - 1); renderTable(); });
      if (next) next.addEventListener('click', function () { state.page = Math.min(pages, state.page + 1); renderTable(); });
    }
  }

  function toCsv(rows) {
    const headers = ['status', 'source_id', 'display_name', 'source_type', 'runs', 'error_rate_pct', 'fetched_total', 'duration_avg_ms', 'duration_p95_ms'];
    const lines = [headers.join(',')];
    rows.forEach(function (r) {
      const cols = [
        r.status, r.source_id, r.display_name, r.source_type, r.runs,
        r.error_rate_pct, r.fetched_total, r.duration_avg_ms, r.duration_p95_ms
      ].map(function (v) {
        const raw = String(v == null ? '' : v);
        return '\"' + raw.replace(/\"/g, '\"\"') + '\"';
      });
      lines.push(cols.join(','));
    });
    return lines.join('\\n');
  }

  function downloadVisibleCsv() {
    const rows = visibleRows();
    if (!rows.length) {
      setStatus('No visible rows to export.', true);
      return;
    }
    const blob = new Blob([toCsv(rows) + '\\n'], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'feed-metrics-visible.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setStatus('Exported CSV for ' + rows.length + ' visible rows.', false);
  }

  async function loadMetrics() {
    const f = currentFilters();
    const query = new URLSearchParams();
    query.set('window', f.window);
    query.set('datasource', f.datasource);
    try {
      const resp = await fetch('/api/feeds/metrics?' + query.toString(), { cache: 'no-store' });
      const data = await resp.json();
      state.items = data.items || [];
      state.summary = data.summary || {};
      state.timeseries = data.timeseries || [];
      state.page = 1;
      applyFilters();
      renderSummary();
      renderChart();
      renderAvailabilityChart();
      renderTable();
      setStatus('Metrics loaded for window=' + f.window + '.', false);
    } catch (err) {
      state.items = [];
      state.filtered = [];
      state.summary = {};
      state.timeseries = [];
      renderSummary();
      renderChart();
      renderAvailabilityChart();
      renderTable();
      setStatus('Failed to load feed metrics.', true);
    }
  }

  ['feedMetricsWindow', 'feedMetricsDatasource', 'feedMetricsStatusFilter', 'feedMetricsSearch', 'feedMetricsPageSize'].forEach(function (id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('change', function () {
      applyFilters();
      renderTable();
    });
    if (id === 'feedMetricsSearch') {
      el.addEventListener('input', function () {
        applyFilters();
        renderTable();
      });
    }
  });
  const refreshBtn = document.getElementById('feedMetricsRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadMetrics);
  const csvBtn = document.getElementById('feedMetricsCsvBtn');
  if (csvBtn) csvBtn.addEventListener('click', downloadVisibleCsv);

  loadMetrics();
})();
"""

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
