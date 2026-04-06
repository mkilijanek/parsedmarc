from __future__ import annotations

import logging
import json
import html
import os
import base64
import hashlib
import hmac
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import requests
from collections import deque
from datetime import datetime, timezone, timedelta
from threading import Lock
from pathlib import Path
from threading import Thread
from urllib.parse import urlencode
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, Response, jsonify, request, make_response, redirect, url_for, stream_with_context, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from sqlalchemy import select, func, and_, or_, text, delete
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
from .services.common import (
    configure_requests_tls_verify_from_env,
    standardized_update_result,
    sum_update_result,
    redact_proxy_credentials,
)
from .routes import register_health_blueprint, register_logs_routes, register_ops_routes, register_public_routes

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
    sync_jobs_queued,
    sync_jobs_running,
    export_jobs_pending,
)

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
    if is_production and not cfg.SECURITY_ALLOW_PERMISSIVE_DEFAULTS:
        if cfg.ALLOWED_HOSTS == "*":
            raise RuntimeError("SECURITY ERROR: ALLOWED_HOSTS cannot be '*' in production. Set explicit hosts or SECURITY_ALLOW_PERMISSIVE_DEFAULTS=true.")
        if cfg.CORS_ORIGINS == "*":
            raise RuntimeError("SECURITY ERROR: CORS_ORIGINS cannot be '*' in production. Set explicit origins or SECURITY_ALLOW_PERMISSIVE_DEFAULTS=true.")

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
    fallback_rps_window: deque[float] = deque()
    fallback_rps_lock = Lock()

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
        proxy_ca_bundle_path = _get_setting(db, "proxy.ca_bundle_path", "")
        proxy_skip_tls_verify = _get_setting(db, "proxy.skip_tls_verify", "0")
        if proxy_http:
            os.environ["HTTP_PROXY"] = proxy_http
            os.environ["http_proxy"] = proxy_http
        else:
            os.environ.pop("HTTP_PROXY", None)
            os.environ.pop("http_proxy", None)
        if proxy_https:
            os.environ["HTTPS_PROXY"] = proxy_https
            os.environ["https_proxy"] = proxy_https
        else:
            os.environ.pop("HTTPS_PROXY", None)
            os.environ.pop("https_proxy", None)
        if proxy_no:
            os.environ["NO_PROXY"] = proxy_no
            os.environ["no_proxy"] = proxy_no
        else:
            os.environ.pop("NO_PROXY", None)
            os.environ.pop("no_proxy", None)
        if proxy_ca_bundle_path:
            os.environ["REQUESTS_CA_BUNDLE"] = proxy_ca_bundle_path
        else:
            os.environ.pop("REQUESTS_CA_BUNDLE", None)
        if str(proxy_skip_tls_verify).strip().lower() in {"1", "true", "yes", "on"}:
            os.environ["REQUESTS_SKIP_TLS_VERIFY"] = "true"
        else:
            os.environ.pop("REQUESTS_SKIP_TLS_VERIFY", None)
        configure_requests_tls_verify_from_env()

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
                resp = requests.get(target["url"], timeout=(5, 10))
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
            }
            if not any(toggles.values()):
                errors.append("Select at least one abuse.ch service.")

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
            resp = requests.post(
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
            resp = requests.get(
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
            resp = requests.post(
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
            resp = requests.get(
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

    def _feed_operational_status(*, enabled: bool, ready: bool, latest_run: FeedRun | None) -> str:
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

    def _feed_last_error_at(latest_run: FeedRun | None, feed_stats_row: FeedStats | None) -> datetime | None:
        if latest_run is not None and str(latest_run.status or "").lower() in {"failed", "cancelled"}:
            return latest_run.finished_at or latest_run.started_at
        if feed_stats_row is not None and feed_stats_row.last_fetch_error:
            return feed_stats_row.last_update
        return None

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
            status = _feed_operational_status(enabled=bool(state["enabled"]), ready=bool(state["ready"]), latest_run=latest)
            last_error_at = _feed_last_error_at(latest, stats_row)
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

    def _apply_feed_filters_and_sort(
        items: List[Dict[str, Any]],
        *,
        status_filter: str,
        datasource: str,
        configured: str,
        query_text: str,
        problems_only: bool,
        sort_by: str,
        sort_order: str,
    ) -> List[Dict[str, Any]]:
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
            filtered = sorted(
                filtered,
                key=lambda item: (
                    status_rank.get(str(item["status"]), 0),
                    str(item["source_id"]).lower(),
                ),
                reverse=reverse,
            )
        elif sort_by == "last_run_at":
            filtered = sorted(
                filtered,
                key=lambda item: (
                    _sort_dt_key(item.get("last_run_at")),
                    str(item["source_id"]).lower(),
                ),
                reverse=reverse,
            )
        elif sort_by == "last_error_at":
            filtered = sorted(
                filtered,
                key=lambda item: (
                    _sort_dt_key(item.get("last_error_at")),
                    str(item["source_id"]).lower(),
                ),
                reverse=reverse,
            )
        elif sort_by == "fetched_count":
            filtered = sorted(
                filtered,
                key=lambda item: (
                    int(item.get("fetched_count", 0)),
                    str(item["source_id"]).lower(),
                ),
                reverse=reverse,
            )
        else:
            filtered = sorted(
                filtered,
                key=lambda item: (str(item["source_id"]).lower(),),
                reverse=reverse,
            )
        return filtered

    def _parse_feed_table_params() -> Dict[str, Any]:
        def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(request.args.get(name, str(default)))
            except ValueError:
                value = default
            return max(minimum, min(maximum, value))

        return {
            "limit": _int_arg("feeds_limit", 25, 1, 100),
            "offset": _int_arg("feeds_offset", 0, 0, 1000000),
            "sort": (request.args.get("feeds_sort", "source") or "source").strip().lower(),
            "order": (request.args.get("feeds_order", "asc") or "asc").strip().lower(),
            "status": (request.args.get("feeds_status", "all") or "all").strip().upper(),
            "datasource": (request.args.get("feeds_datasource", "all") or "all").strip().lower(),
            "configured": (request.args.get("feeds_configured", "all") or "all").strip().lower(),
            "q": (request.args.get("feeds_q", "") or "").strip(),
            "problems_only": (request.args.get("feeds_problems_only", "0") or "0").strip().lower() in {"1", "true", "yes", "on"},
        }

    def _resolve_metrics_window_hours() -> tuple[int, str]:
        window = (request.args.get("window") or "").strip().lower()
        if window in {"24h", "24"}:
            return 24, "24h"
        if window in {"7d", "168h", "168"}:
            return 24 * 7, "7d"
        if window in {"30d", "720h", "720"}:
            return 24 * 30, "30d"
        try:
            hours = int(request.args.get("hours", "24"))
        except ValueError:
            hours = 24
        hours = max(1, min(24 * 30, hours))
        if hours == 24:
            return 24, "24h"
        if hours == 24 * 7:
            return 24 * 7, "7d"
        if hours == 24 * 30:
            return 24 * 30, "30d"
        return hours, f"{hours}h"

    def _percentile(values: List[int], p: float) -> float | None:
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

    def _execute_sync_job(job: SyncJobRef) -> Dict[str, Any]:
        run_id = job.job_id
        feed_source_id = str(job.feed_source_id or "")
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
                    updates[env_key] = _get_setting(db, _feed_secret_key(feed.source_id, str(f["key"])), "", secret=True)
                else:
                    updates[env_key] = _get_setting(db, _feed_value_key(feed.source_id, str(f["key"])), "", secret=False)
            if feed.source_type == "mwdb":
                updates["MWDB_ORGANIZATIONS"] = _get_setting(db, _feed_value_key(feed.source_id, "organizations"), "", secret=False)
                updates["MWDB_MY_GROUP"] = _get_setting(db, _feed_value_key(feed.source_id, "my_group"), "", secret=False)
            if feed.source_type == "malwarebazaar":
                shared_key = _get_setting(db, _feed_secret_key("abusech", "api_key"), "", secret=True)
                if shared_key:
                    updates["ABUSECH_AUTH_KEY"] = shared_key

            previous = {k: os.environ.get(k) for k in updates.keys()}
            for k, v in updates.items():
                if v:
                    os.environ[k] = str(v)
                else:
                    os.environ.pop(k, None)

            started = time.time()
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
                row.status = "failed"
                row.error = str(e)
                row.finished_at = datetime.now(timezone.utc)
                row.result_json = {}
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
            for k, v in updates.items():
                prev = previous.get(k)
                if prev is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = prev
            scheduler_state["active_run_id"] = None
            scheduler_state["active_job_id"] = None
            db.close()

    def _dequeue_next_sync_job() -> SyncJobRef | None:
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
            "_apply_feed_filters_and_sort": _apply_feed_filters_and_sort,
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
            "_parse_feed_table_params": _parse_feed_table_params,
            "_percentile": _percentile,
            "_read_feed_config_state": _read_feed_config_state,
            "_read_feed_rows": _read_feed_rows,
            "_resolve_metrics_window_hours": _resolve_metrics_window_hours,
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

# ---------- HTML rendering (no external templates, minimal dependencies) ----------

STARTUP_LOADER_STYLE = """
    .startup-loader { position: fixed; inset: 0; z-index: 9999; background: radial-gradient(circle at 20% 20%, #103040 0%, rgba(16,48,64,.55) 35%, transparent 70%), radial-gradient(circle at 80% 0%, #2a1f3f 0%, rgba(42,31,63,.45) 35%, transparent 70%), #05090f; display: flex; align-items: center; justify-content: center; padding: 20px; transition: opacity .35s ease, visibility .35s ease; }
    .startup-loader.done { opacity: 0; visibility: hidden; }
    .startup-loader-card { position: relative; overflow: hidden; width: min(560px, 94vw); border: 1px solid #224b63; background: linear-gradient(180deg, #071523 0%, #0a1520 100%); border-radius: 16px; padding: 22px 20px; box-shadow: 0 20px 50px rgba(0,0,0,.45); }
    .startup-loader-card h2 { margin: 0 0 8px; color: #9cecff; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: .08em; text-transform: uppercase; }
    .startup-loader-card p { margin: 0 0 14px; color: #b5d7e8; font-size: 14px; }
    .startup-loader-grid { position: absolute; inset: -200% -50% auto -50%; height: 220%; background: repeating-linear-gradient(90deg, rgba(40,176,255,.08) 0, rgba(40,176,255,.08) 1px, transparent 1px, transparent 22px), repeating-linear-gradient(0deg, rgba(40,176,255,.06) 0, rgba(40,176,255,.06) 1px, transparent 1px, transparent 22px); transform: perspective(380px) rotateX(68deg); opacity: .65; }
    .startup-loader-scan { position: absolute; left: 0; right: 0; top: -40%; height: 38%; background: linear-gradient(180deg, rgba(76,208,255,0), rgba(76,208,255,.22), rgba(76,208,255,0)); animation: loader-scan 2.1s linear infinite; }
    .startup-loader-progress { position: relative; height: 8px; border: 1px solid #2d6486; background: #05131d; border-radius: 999px; overflow: hidden; }
    .startup-loader-progress span { display: block; height: 100%; width: 0; background: linear-gradient(90deg, #37dcff, #7effc8); box-shadow: 0 0 16px rgba(55,220,255,.8); transition: width .16s ease; }
    @keyframes loader-scan { 0% { transform: translateY(0); } 100% { transform: translateY(300%); } }
"""

STARTUP_LOADER_MARKUP = """
<div id="startupLoader" class="startup-loader" aria-live="polite" aria-label="Application startup in progress">
  <div class="startup-loader-card">
    <div class="startup-loader-grid" aria-hidden="true"></div>
    <div class="startup-loader-scan" aria-hidden="true"></div>
    <h2>IOC Service</h2>
    <p>Booting modules, validating feeds, preparing data plane...</p>
    <div class="startup-loader-progress"><span id="startupLoaderBar"></span></div>
  </div>
</div>
"""

STARTUP_LOADER_SCRIPT = """
(function () {
  const loader = document.getElementById('startupLoader');
  const bar = document.getElementById('startupLoaderBar');
  if (!loader || !bar) { return; }
  const startedAt = Date.now();
  let done = false;
  let width = 10;
  const tick = window.setInterval(function () {
    if (done) { return; }
    width = Math.min(92, width + Math.random() * 7);
    bar.style.width = width.toFixed(1) + '%';
  }, 120);
  function finish() {
    if (done) { return; }
    done = true;
    const minVisibleMs = 400;
    const remaining = Math.max(0, minVisibleMs - (Date.now() - startedAt));
    window.setTimeout(function () {
      bar.style.width = '100%';
      loader.classList.add('done');
      window.setTimeout(function () { loader.remove(); }, 450);
      window.clearInterval(tick);
    }, remaining);
  }
  const timeout = window.setTimeout(finish, 3500);
  fetch('/health', { cache: 'no-store' })
    .then(function () { finish(); })
    .catch(function () { finish(); })
    .finally(function () { window.clearTimeout(timeout); });
  window.addEventListener('load', finish, { once: true });
})();
"""

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
{STARTUP_LOADER_STYLE}
  </style>
</head>
<body>
{STARTUP_LOADER_MARKUP}
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
  {STARTUP_LOADER_SCRIPT}
</script>
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
{STARTUP_LOADER_STYLE}
  </style>
</head>
<body>
{STARTUP_LOADER_MARKUP}
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
  {STARTUP_LOADER_SCRIPT}
</script>
</body>
</html>
"""
