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
from .routes import register_health_blueprint

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
                    {"key": "bazaar_enabled", "label": "Bazaar", "secret": False, "required": False, "env": "ABUSECH_BAZAAR_ENABLED", "type": "checkbox"},
                    {"key": "bazaar_tags", "label": "Bazaar tags (comma-separated)", "secret": False, "required": False, "env": "MALWAREBAZAAR_TAGS", "placeholder": "exe, stealer"},
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
                "bazaar_enabled": (form_data.get(_field_input_name("bazaar_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "feodotracker_enabled": (form_data.get(_field_input_name("feodotracker_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "yaraify_enabled": (form_data.get(_field_input_name("yaraify_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
            }
            if not any(toggles.values()):
                errors.append("Select at least one abuse.ch service.")
            if toggles["bazaar_enabled"]:
                bazaar_tags = (form_data.get(_field_input_name("bazaar_tags")) or "").strip()
                if not bazaar_tags:
                    errors.append("Bazaar tags are required when Bazaar is enabled.")

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

    register_health_blueprint(
        app,
        limiter=limiter,
        cfg=cfg,
        db_factory=_db,
        cache_key_fn=_cache_key,
    )

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
            base_result: Dict[str, Any] = dict(update_abusech_indicators() or {})
            if str(os.getenv("ABUSECH_BAZAAR_ENABLED", "0")).strip().lower() in {"1", "true", "yes", "on"}:
                from .services.malwarebazaar import update_malwarebazaar_indicators
                bazaar_result = update_malwarebazaar_indicators()
                rolled = sum_update_result([base_result, bazaar_result])
                details = dict(rolled.get("details") or {})
                details["abusech"] = base_result
                details["malwarebazaar"] = bazaar_result
                base_result = standardized_update_result(
                    fetched=int(rolled.get("fetched", 0) or 0),
                    deactivated=int(rolled.get("deactivated", 0) or 0),
                    errors=int(rolled.get("errors", 0) or 0),
                    details=details,
                )
            return {"source": feed.source_id, "result": base_result}
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
        except Exception:
            db.close()
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
        q = request.args.get("q", "").strip() or None
        type_filter = (request.args.get("type") or "all").lower()
        tlp = (request.args.get("tlp") or "all").upper()
        source = (request.args.get("source") or "all").lower()
        min_conf = request.args.get("min_conf", type=int)
        max_conf = request.args.get("max_conf", type=int)
        limit, offset = _parse_limit_offset(default_limit=10000, max_limit=max(1, cfg.EXPORT_RESULT_LIMIT_MAX))
        if limit is None or offset is None:
            return jsonify({"error": "limit/offset must be integers"}), 400

        auth_mode = (request.args.get("auth_mode") or "").strip().lower()
        if auth_mode and auth_mode not in {"client_secret", "certificate"}:
            return jsonify({"error": "auth_mode must be client_secret or certificate"}), 400

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
            "auth_mode": auth_mode or None,
            "tenant_id": (request.args.get("tenant_id") or "").strip() or None,
            "client_id": (request.args.get("client_id") or "").strip() or None,
            "scope": (request.args.get("scope") or "").strip() or None,
            "endpoint_url": (request.args.get("endpoint_url") or "").strip() or None,
            "cert_thumbprint": (request.args.get("cert_thumbprint") or "").strip() or None,
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
        table_params = _parse_feed_table_params()
        db = _db()
        try:
            _ensure_default_feeds(db)
            all_feed_items = _build_feed_items(db)
            filtered_items = _apply_feed_filters_and_sort(
                all_feed_items,
                status_filter=str(table_params["status"]),
                datasource=str(table_params["datasource"]),
                configured=str(table_params["configured"]),
                query_text=str(table_params["q"]),
                problems_only=bool(table_params["problems_only"]),
                sort_by=str(table_params["sort"]),
                sort_order=str(table_params["order"]),
            )
            total_feeds = len(filtered_items)
            limit = int(table_params["limit"])
            offset = int(table_params["offset"])
            if offset >= total_feeds and total_feeds > 0:
                offset = max(0, ((total_feeds - 1) // max(1, limit)) * max(1, limit))
            page_feed_items = filtered_items[offset : offset + limit]
            datasource_options = sorted({str(item["source_type"]) for item in all_feed_items})
            feed_rows = db.scalars(select(FeedStats).order_by(FeedStats.source.asc(), FeedStats.source_id.asc())).all()
            settings_count = int(db.scalar(select(func.count()).select_from(AppSetting)) or 0)
            proxy_conf = {
                "proxy_http_url": _get_setting(db, "proxy.http_url", os.getenv("HTTP_PROXY", "")),
                "proxy_https_url": _get_setting(db, "proxy.https_url", os.getenv("HTTPS_PROXY", "")),
                "proxy_no_proxy": _get_setting(db, "proxy.no_proxy", os.getenv("NO_PROXY", "")),
                "proxy_ca_bundle_path": _get_setting(db, "proxy.ca_bundle_path", os.getenv("REQUESTS_CA_BUNDLE", "")),
                "proxy_skip_tls_verify": _get_setting(db, "proxy.skip_tls_verify", os.getenv("REQUESTS_SKIP_TLS_VERIFY", "0")),
                "trusted_proxy_count": _get_setting(db, "proxy.trusted_proxy_count", os.getenv("TRUSTED_PROXY_COUNT", "0")),
                "sentinel_tenant_id": _get_setting(db, "sentinel.tenant_id", cfg.AZURE_SENTINEL_TENANT_ID),
                "sentinel_client_id": _get_setting(db, "sentinel.client_id", cfg.AZURE_SENTINEL_CLIENT_ID),
                "sentinel_auth_mode": _get_setting(db, "sentinel.auth_mode", cfg.AZURE_SENTINEL_AUTH_MODE),
                "sentinel_scope": _get_setting(db, "sentinel.scope", cfg.AZURE_SENTINEL_SCOPE),
                "sentinel_endpoint_url": _get_setting(db, "sentinel.endpoint_url", cfg.AZURE_SENTINEL_ENDPOINT_URL),
                "sentinel_chunk_size": _get_setting(db, "sentinel.chunk_size", str(cfg.AZURE_SENTINEL_CHUNK_SIZE)),
                "sentinel_cert_thumbprint": _get_setting(db, "sentinel.cert_thumbprint", cfg.AZURE_SENTINEL_CERT_THUMBPRINT),
                "sentinel_client_secret_masked": _mask_secret(_get_setting(db, "sentinel.client_secret", cfg.AZURE_SENTINEL_CLIENT_SECRET, secret=True)),
                "sentinel_cert_private_key_masked": _mask_secret(_get_setting(db, "sentinel.cert_private_key_pem", cfg.AZURE_SENTINEL_CERT_PRIVATE_KEY_PEM, secret=True)),
            }
            proxy_test_raw = _get_setting(db, "proxy.last_test_result", "")
            proxy_test_results: List[Dict[str, Any]] = []
            if proxy_test_raw:
                try:
                    parsed = json.loads(proxy_test_raw)
                    if isinstance(parsed, list):
                        proxy_test_results = [p for p in parsed if isinstance(p, dict)]
                except Exception:
                    proxy_test_results = []
            scheduler_heartbeat = _get_setting(db, "scheduler.heartbeat", "")
            recent_sync_jobs = list(
                db.scalars(
                    select(SyncJob).order_by(SyncJob.created_at.desc()).limit(40)
                ).all()
            )
        finally:
            db.close()

        status_msg = request.args.get("msg", "")
        proxy_test_rows_html = "".join(
            [
                (
                    "<tr>"
                    f"<td>{_esc(str(row.get('target') or ''))}</td>"
                    f"<td>{_esc(str(row.get('status') or ''))}</td>"
                    f"<td>{_esc(str(row.get('http') if row.get('http') is not None else '-'))}</td>"
                    f"<td>{_esc(str(row.get('latency_ms') if row.get('latency_ms') is not None else '-'))}</td>"
                    f"<td>{_esc(str(row.get('title') or ''))}</td>"
                    f"<td>{_esc(str(row.get('notes') or ''))}</td>"
                    "</tr>"
                )
                for row in proxy_test_results
            ]
        )
        if not proxy_test_rows_html:
            proxy_test_rows_html = "<tr><td colspan='6'>No proxy test results yet.</td></tr>"
        proxy_test_raw_json = _esc(json.dumps(proxy_test_results, ensure_ascii=True))
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

        def _admin_query(**kwargs: Any) -> str:
            q = {
                "feeds_limit": int(table_params["limit"]),
                "feeds_offset": int(offset),
                "feeds_sort": str(table_params["sort"]),
                "feeds_order": str(table_params["order"]),
                "feeds_status": str(table_params["status"]).lower(),
                "feeds_datasource": str(table_params["datasource"]),
                "feeds_configured": str(table_params["configured"]),
                "feeds_q": str(table_params["q"]),
                "feeds_problems_only": "1" if bool(table_params["problems_only"]) else "0",
            }
            for k, v in kwargs.items():
                q[str(k)] = v
            return urlencode(q)

        source_ctrl_html = "".join(
            [
                (
                    "<tr>"
                    f"<td><code>{_esc(item['source_id'])}</code><br/>{_esc(item['display_name'])}<br/><small>{_esc(item['source_type'])}</small></td>"
                    f"<td>{'enabled' if item['enabled'] else 'disabled'}</td>"
                    f"<td>{_esc(item['schedule_cron'])}</td>"
                    f"<td>{'OK' if item['ready'] else 'Incomplete: ' + _esc(', '.join(item['missing']))}</td>"
                    f"<td>{_esc(item['last_run_status'])}</td>"
                    f"<td>{_esc(str(item['last_run_at'] or 'n/a'))}</td>"
                    f"<td><form method='post' action='/admin/feed-toggle' style='display:inline'>"
                    f"<input type='hidden' name='source' value='{_esc(item['source_id'])}'/>"
                    f"<input type='hidden' name='enabled' value='{'0' if item['enabled'] else '1'}'/>"
                    f"<button type='submit'>{'Disable' if item['enabled'] else 'Enable'}</button>"
                    "</form> "
                    f"<a href='/admin/feed/{_esc(item['source_id'])}/configure'>Configure</a> "
                    f"<form method='post' action='/admin/sync' style='display:inline'>"
                    f"<input type='hidden' name='source' value='{_esc(item['source_id'])}'/>"
                    f"<button type='submit' {'disabled' if not item['ready'] else ''}>Sync now</button>"
                    "</form> "
                    f"<form method='post' action='/admin/feed/{_esc(item['source_id'])}/delete' style='display:inline' onsubmit='return confirm(\"Delete feed {_esc(item['source_id'])}?\")'>"
                    "<button type='submit'>Delete</button>"
                    "</form></td>"
                    "</tr>"
                )
                for item in page_feed_items
            ]
        )
        if not source_ctrl_html:
            source_ctrl_html = "<tr><td colspan='7'>No feeds match current filters.</td></tr>"

        prev_offset = max(0, int(offset) - int(table_params["limit"]))
        next_offset = int(offset) + int(table_params["limit"])
        has_prev = int(offset) > 0
        has_next = next_offset < total_feeds
        page_start = (int(offset) + 1) if total_feeds > 0 else 0
        page_end = min(int(offset) + int(table_params["limit"]), total_feeds)
        prev_link_html = f"<a href='/admin?{_admin_query(feeds_offset=prev_offset)}'>Previous</a>" if has_prev else "Previous"
        next_link_html = f"<a href='/admin?{_admin_query(feeds_offset=next_offset)}'>Next</a>" if has_next else "Next"

        feed_filter_controls = f"""
        <form method='get' action='/admin' style='display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.5rem;align-items:end;margin:.7rem 0 1rem'>
          <label>Status
            <select name='feeds_status'>
              <option value='all' {'selected' if str(table_params['status']) == 'ALL' else ''}>all</option>
              <option value='ok' {'selected' if str(table_params['status']) == 'OK' else ''}>OK</option>
              <option value='warning' {'selected' if str(table_params['status']) == 'WARNING' else ''}>WARNING</option>
              <option value='error' {'selected' if str(table_params['status']) == 'ERROR' else ''}>ERROR</option>
              <option value='disabled' {'selected' if str(table_params['status']) == 'DISABLED' else ''}>DISABLED</option>
              <option value='not_configured' {'selected' if str(table_params['status']) == 'NOT_CONFIGURED' else ''}>NOT_CONFIGURED</option>
            </select>
          </label>
          <label>Datasource
            <select name='feeds_datasource'>
              <option value='all' {'selected' if str(table_params['datasource']) in {'', 'all'} else ''}>all</option>
              {''.join([f"<option value='{_esc(src)}' {'selected' if str(table_params['datasource']) == src else ''}>{_esc(src)}</option>" for src in datasource_options])}
            </select>
          </label>
          <label>Configured
            <select name='feeds_configured'>
              <option value='all' {'selected' if str(table_params['configured']) == 'all' else ''}>all</option>
              <option value='configured' {'selected' if str(table_params['configured']) == 'configured' else ''}>configured</option>
              <option value='not_configured' {'selected' if str(table_params['configured']) == 'not_configured' else ''}>not configured</option>
            </select>
          </label>
          <label>Search
            <input type='text' name='feeds_q' value='{_esc(str(table_params['q']))}' placeholder='feed name / source id'/>
          </label>
          <label>Sort
            <select name='feeds_sort'>
              <option value='source' {'selected' if str(table_params['sort']) == 'source' else ''}>source</option>
              <option value='status' {'selected' if str(table_params['sort']) == 'status' else ''}>status</option>
              <option value='last_run_at' {'selected' if str(table_params['sort']) == 'last_run_at' else ''}>last_run_at</option>
              <option value='last_error_at' {'selected' if str(table_params['sort']) == 'last_error_at' else ''}>last_error_at</option>
              <option value='fetched_count' {'selected' if str(table_params['sort']) == 'fetched_count' else ''}>fetched_count</option>
            </select>
          </label>
          <label>Order
            <select name='feeds_order'>
              <option value='asc' {'selected' if str(table_params['order']) == 'asc' else ''}>asc</option>
              <option value='desc' {'selected' if str(table_params['order']) == 'desc' else ''}>desc</option>
            </select>
          </label>
          <label>Per page
            <select name='feeds_limit'>
              <option value='25' {'selected' if int(table_params['limit']) == 25 else ''}>25</option>
              <option value='50' {'selected' if int(table_params['limit']) == 50 else ''}>50</option>
              <option value='100' {'selected' if int(table_params['limit']) == 100 else ''}>100</option>
            </select>
          </label>
          <label style='display:flex;align-items:center;gap:.5rem'>
            <input type='checkbox' name='feeds_problems_only' value='1' {'checked' if bool(table_params['problems_only']) else ''}/> Problems only
          </label>
          <input type='hidden' name='feeds_offset' value='0'/>
          <div style='display:flex;gap:.5rem'>
            <button type='submit'>Apply filters</button>
            <a href='/admin'>Clear</a>
          </div>
        </form>
        <p><strong>Feeds:</strong> showing {page_start}-{page_end} of {total_feeds} (server-side)</p>
        <p>
          {prev_link_html} |
          {next_link_html}
        </p>
        """

        recent_jobs_html = "".join(
            [
                (
                    "<tr>"
                    f"<td><code>{_esc(j.job_id)}</code></td>"
                    f"<td>{_esc(j.feed_source_id)}</td>"
                    f"<td>{_esc(j.trigger_type)}</td>"
                    f"<td>{_esc(j.status)}</td>"
                    f"<td>{_esc(str(j.created_at or ''))}</td>"
                    f"<td>{_esc(str(j.started_at or ''))}</td>"
                    f"<td>{_esc(str(j.finished_at or ''))}</td>"
                    "<td>"
                    f"<a href='/admin/sync-jobs/{_esc(j.job_id)}'>Details</a> "
                    + (
                        f"<form method='post' action='/admin/sync-jobs/{_esc(j.job_id)}/retry' style='display:inline'>"
                        "<button type='submit'>Retry</button></form> "
                        if str(j.status or "").lower() in {"failed", "cancelled"}
                        else ""
                    )
                    + (
                        f"<form method='post' action='/admin/sync-jobs/{_esc(j.job_id)}/cancel' style='display:inline'>"
                        "<button type='submit'>Cancel</button></form>"
                        if str(j.status or "").lower() in {"queued", "running", "cancel_requested"}
                        else ""
                    )
                    + "</td>"
                    "</tr>"
                )
                for j in recent_sync_jobs
            ]
        )
        if not recent_jobs_html:
            recent_jobs_html = "<tr><td colspan='8'>No sync jobs yet.</td></tr>"

        if _admin_dangerous_ops_enabled():
            danger_zone_html = f"""
  <div class="card">
    <h2>Danger Zone</h2>
    <p>High-risk operations. Requires admin token, confirmation phrase and instance name.</p>
    <form method="post" action="/admin/danger/wipe">
      <p><label>Operation
        <select name="operation">
          <option value="soft">Soft reset (indicators, runs, logs, stats, jobs, cache)</option>
          <option value="factory">Factory reset (all dynamic + feeds/settings)</option>
          <option value="selected">Selected tables</option>
        </select>
      </label></p>
      <fieldset>
        <legend>Selected tables (used when operation=selected)</legend>
        <label><input type="checkbox" name="tables" value="indicators"/> indicators</label>
        <label><input type="checkbox" name="tables" value="feed_stats"/> feed_stats</label>
        <label><input type="checkbox" name="tables" value="feed_runs"/> feed_runs</label>
        <label><input type="checkbox" name="tables" value="sync_jobs"/> sync_jobs</label>
        <label><input type="checkbox" name="tables" value="app_logs"/> app_logs</label>
        <label><input type="checkbox" name="tables" value="export_jobs"/> export_jobs</label>
        <label><input type="checkbox" name="tables" value="feeds"/> feeds</label>
        <label><input type="checkbox" name="tables" value="app_settings"/> app_settings</label>
      </fieldset>
      <p><label>Admin token <input type="password" name="admin_token" placeholder="ADMIN_API_TOKEN" required/></label></p>
      <p><label>Type confirmation <input type="text" name="confirm_phrase" placeholder="WIPE" required/></label></p>
      <p><label>Instance name <input type="text" name="confirm_instance" placeholder="{_esc(cfg.INSTANCE_NAME)}" required/></label></p>
      <button type="submit">Execute wipe</button>
    </form>
  </div>
            """
        else:
            danger_zone_html = """
  <div class="card">
    <h2>Danger Zone</h2>
    <p>Disabled. Set <code>ADMIN_DANGEROUS_OPS=true</code> and configure <code>ADMIN_API_TOKEN</code> to enable controlled wipe operations.</p>
  </div>
            """

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
    input[type=text], input[type=password], select {{ width: 100%; padding: .45rem; border-radius: 8px; border: 1px solid var(--line); background: var(--bg); color: var(--fg); }}
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
      <p><label>Organization CA bundle path <input type="text" name="proxy_ca_bundle_path" value="{_esc(proxy_conf['proxy_ca_bundle_path'])}" placeholder="/etc/ssl/certs/org-ca.pem"/></label></p>
      <p><label><input type="checkbox" name="proxy_skip_tls_verify" value="1" {"checked" if str(proxy_conf['proxy_skip_tls_verify']).strip().lower() in {"1","true","yes","on"} else ""}/> Skip TLS certificate verification for outbound HTTP requests (insecure, curl -k equivalent)</label></p>
      <p><label>Trusted proxy count <input type="text" name="trusted_proxy_count" value="{_esc(proxy_conf['trusted_proxy_count'])}" placeholder="0"/></label></p>
      <h3>Azure Sentinel (Microsoft Graph)</h3>
      <p><label>Tenant ID <input type="text" name="sentinel_tenant_id" value="{_esc(proxy_conf['sentinel_tenant_id'])}" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/></label></p>
      <p><label>Client ID <input type="text" name="sentinel_client_id" value="{_esc(proxy_conf['sentinel_client_id'])}" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/></label></p>
      <p><label>Auth mode
        <select name="sentinel_auth_mode">
          <option value="client_secret" {"selected" if str(proxy_conf['sentinel_auth_mode']).strip().lower() != "certificate" else ""}>client_secret</option>
          <option value="certificate" {"selected" if str(proxy_conf['sentinel_auth_mode']).strip().lower() == "certificate" else ""}>certificate</option>
        </select>
      </label></p>
      <p><label>Client secret (leave blank to keep current: {_esc(proxy_conf['sentinel_client_secret_masked'])}) <input type="password" name="sentinel_client_secret" value="" placeholder="Leave blank to keep current"/></label></p>
      <p><label>Certificate private key PEM (leave blank to keep current: {_esc(proxy_conf['sentinel_cert_private_key_masked'])}) <input type="password" name="sentinel_cert_private_key_pem" value="" placeholder="-----BEGIN PRIVATE KEY-----"/></label></p>
      <p><label>Certificate thumbprint <input type="text" name="sentinel_cert_thumbprint" value="{_esc(proxy_conf['sentinel_cert_thumbprint'])}" placeholder="hex thumbprint"/></label></p>
      <p><label>Graph scope <input type="text" name="sentinel_scope" value="{_esc(proxy_conf['sentinel_scope'])}" placeholder="https://graph.microsoft.com/.default"/></label></p>
      <p><label>Graph endpoint URL <input type="text" name="sentinel_endpoint_url" value="{_esc(proxy_conf['sentinel_endpoint_url'])}" placeholder="https://graph.microsoft.com/beta/security/tiIndicators/submitTiIndicators"/></label></p>
      <p><label>Chunk size <input type="text" name="sentinel_chunk_size" value="{_esc(proxy_conf['sentinel_chunk_size'])}" placeholder="100"/></label></p>
      <button type="submit">Save configuration</button>
    </form>
    <form method="post" action="/admin/proxy-test" style="margin-top:.8rem">
      <button type="submit">Test proxy</button>
    </form>
    <h3>Proxy Test Results</h3>
    <table>
      <thead><tr><th>Target</th><th>Status</th><th>HTTP</th><th>Latency ms</th><th>Title</th><th>Notes</th></tr></thead>
      <tbody>{proxy_test_rows_html}</tbody>
    </table>
    <details style="margin-top:.6rem">
      <summary>Raw results</summary>
      <pre id="proxyTestRaw">{proxy_test_raw_json}</pre>
    </details>
    <button type="button" id="copyProxyResultsBtn">Copy results</button>
    <p><strong>Sentinel quick export:</strong>
      <code>curl -X POST /api/sentinel/export?q=source:mwdb&amp;type=all&amp;tlp=all</code>
    </p>
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
    {feed_filter_controls}
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
    <h2>Recent Sync Jobs</h2>
    <table>
      <thead><tr><th>Job ID</th><th>Source</th><th>Trigger</th><th>Status</th><th>Created</th><th>Started</th><th>Finished</th><th>Actions</th></tr></thead>
      <tbody>{recent_jobs_html}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Logs</h2>
    <p><a href="/logs">Open logs tab</a></p>
  </div>
  {danger_zone_html}
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
    document.querySelectorAll('form').forEach((form) => {{
      form.addEventListener('submit', (evt) => {{
        const submitter = evt.submitter;
        const buttons = form.querySelectorAll('button[type="submit"]');
        buttons.forEach((btn) => btn.disabled = true);
        if (submitter) {{
          submitter.dataset.originalText = submitter.textContent || '';
          submitter.textContent = 'Processing...';
        }}
      }});
    }});
    const copyProxyResultsBtn = document.getElementById('copyProxyResultsBtn');
    if (copyProxyResultsBtn) {{
      copyProxyResultsBtn.addEventListener('click', async () => {{
        const raw = document.getElementById('proxyTestRaw');
        const txt = raw ? raw.textContent || '' : '';
        try {{
          if (navigator.clipboard && window.isSecureContext) {{
            await navigator.clipboard.writeText(txt);
          }} else {{
            const ta = document.createElement('textarea');
            ta.value = txt;
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
          }}
          alert('Proxy test results copied.');
        }} catch (e) {{
          alert('Copy failed.');
        }}
      }});
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
            _set_setting(db, "proxy.ca_bundle_path", (request.form.get("proxy_ca_bundle_path") or "").strip())
            _set_setting(
                db,
                "proxy.skip_tls_verify",
                "1" if (request.form.get("proxy_skip_tls_verify") or "").strip().lower() in {"1", "true", "yes", "on"} else "0",
            )
            _set_setting(db, "proxy.trusted_proxy_count", (request.form.get("trusted_proxy_count") or "0").strip())
            _set_setting(db, "sentinel.tenant_id", (request.form.get("sentinel_tenant_id") or "").strip())
            _set_setting(db, "sentinel.client_id", (request.form.get("sentinel_client_id") or "").strip())
            _set_setting(db, "sentinel.auth_mode", (request.form.get("sentinel_auth_mode") or "client_secret").strip().lower())
            _set_setting(db, "sentinel.scope", (request.form.get("sentinel_scope") or "").strip())
            _set_setting(db, "sentinel.endpoint_url", (request.form.get("sentinel_endpoint_url") or "").strip())
            _set_setting(db, "sentinel.chunk_size", (request.form.get("sentinel_chunk_size") or str(cfg.AZURE_SENTINEL_CHUNK_SIZE)).strip())
            _set_setting(db, "sentinel.cert_thumbprint", (request.form.get("sentinel_cert_thumbprint") or "").strip())
            sentinel_client_secret = (request.form.get("sentinel_client_secret") or "").strip()
            if sentinel_client_secret:
                _set_setting(db, "sentinel.client_secret", sentinel_client_secret, secret=True)
            sentinel_cert_private_key_pem = (request.form.get("sentinel_cert_private_key_pem") or "").strip()
            if sentinel_cert_private_key_pem:
                _set_setting(db, "sentinel.cert_private_key_pem", sentinel_cert_private_key_pem, secret=True)

            db.commit()
            _write_proxy_env(db)
            _audit("admin_config_update", "app_settings", None, {"updated": True})
            return redirect(url_for("admin_panel", msg="Global configuration saved."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Configuration save failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/proxy-test")
    @limiter.limit("10 per minute")
    def admin_proxy_test():
        db = _db()
        try:
            _write_proxy_env(db)
            results = _run_proxy_test()
            _set_setting(db, "proxy.last_test_result", json.dumps(results, separators=(",", ":")))
            db.commit()
            _audit("admin_proxy_test", "app_settings", None, {"targets": len(results)})
            status = "ok" if all(str(r.get("status")) == "OK" for r in results) else "warning"
            return redirect(url_for("admin_panel", msg=f"Proxy test completed ({status})."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Proxy test failed: {redact_proxy_credentials(str(e))}"))
        finally:
            db.close()

    @app.post("/admin/danger/wipe")
    @limiter.limit("5 per minute")
    def admin_danger_wipe():
        if not _admin_dangerous_ops_enabled():
            return redirect(url_for("admin_panel", msg="Dangerous operations are disabled."))
        if not _admin_token_authorized():
            return redirect(url_for("admin_panel", msg="Dangerous operation denied: invalid admin token."))
        confirm_phrase = (request.form.get("confirm_phrase") or "").strip().upper()
        confirm_instance = (request.form.get("confirm_instance") or "").strip()
        if confirm_phrase != "WIPE":
            return redirect(url_for("admin_panel", msg="Dangerous operation denied: confirmation phrase mismatch."))
        if confirm_instance != cfg.INSTANCE_NAME:
            return redirect(url_for("admin_panel", msg="Dangerous operation denied: instance name mismatch."))

        operation = (request.form.get("operation") or "soft").strip().lower()
        selected = [str(v).strip().lower() for v in request.form.getlist("tables") if str(v).strip()]
        table_models: Dict[str, Any] = {
            "indicators": Indicator,
            "feed_stats": FeedStats,
            "feed_runs": FeedRun,
            "sync_jobs": SyncJob,
            "app_logs": AppLog,
            "export_jobs": ExportJob,
            "feeds": Feed,
            "app_settings": AppSetting,
        }
        soft_tables = ["indicators", "feed_stats", "feed_runs", "sync_jobs", "app_logs", "export_jobs"]
        factory_tables = soft_tables + ["feeds", "app_settings"]
        if operation == "soft":
            target_tables = soft_tables
        elif operation == "factory":
            target_tables = factory_tables
        elif operation == "selected":
            target_tables = [t for t in selected if t in table_models]
            if not target_tables:
                return redirect(url_for("admin_panel", msg="Dangerous operation denied: no valid tables selected."))
        else:
            return redirect(url_for("admin_panel", msg="Dangerous operation denied: invalid operation."))

        db = _db()
        deleted: Dict[str, int] = {}
        cache_flushed = False
        try:
            for table_name in target_tables:
                model = table_models[table_name]
                count_stmt = select(func.count()).select_from(model)
                before_count = int(db.scalar(count_stmt) or 0)
                db.execute(delete(model))
                deleted[table_name] = before_count
            db.commit()
            try:
                r = get_redis()
                r.flushdb()
                cache_flushed = True
            except Exception:
                cache_flushed = False
            _audit(
                "admin_wipe",
                "system",
                None,
                {
                    "operation": operation,
                    "instance": cfg.INSTANCE_NAME,
                    "deleted": deleted,
                    "cache_flushed": cache_flushed,
                },
            )
            return redirect(
                url_for(
                    "admin_panel",
                    msg=f"Dangerous operation completed ({operation}). Deleted tables: {', '.join(sorted(deleted.keys()))}.",
                )
            )
        except Exception as e:
            db.rollback()
            logger.exception("admin_danger_wipe_failed")
            return redirect(url_for("admin_panel", msg=f"Dangerous operation failed: {e}"))
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
        msg = (request.args.get("msg") or "").strip()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            state = _read_feed_config_state(db, feed)
            mwdb_orgs: List[Dict[str, str]] = []
            mwdb_selected_orgs: List[str] = []
            mwdb_selected_group: str = ""
            if feed.source_type == "mwdb":
                mwdb_selected_orgs = [x.strip() for x in _get_setting(db, _feed_value_key(feed.source_id, "organizations"), "").split(",") if x.strip()]
                mwdb_selected_group = _get_setting(db, _feed_value_key(feed.source_id, "my_group"), "", secret=False)
                values = {str(f["key"]): _get_feed_field_value(db, feed, f) for f in state["fields"]}
                mwdb_orgs = _fetch_mwdb_orgs(values.get("base_url", ""), values.get("api_key", ""))
        finally:
            db.close()
        fields_html = "".join(
            [
                (
                    f"<p><label>{_esc(str(f['label']))} "
                    + (
                        f"<input type='checkbox' name='{_esc(str(f.get('input_name') or ''))}' value='1' {'checked' if f.get('checked') else ''}/>"
                        if str(f.get("type") or "") == "checkbox"
                        else (
                            f"<input type='{'password' if f.get('secret') else 'text'}' "
                            f"name='{_esc(str(f.get('input_name') or ''))}' "
                            f"value='{_esc(str(f.get('value') or ''))}' "
                            f"placeholder='{_esc(str(f.get('placeholder') or ''))}'/>"
                        )
                    )
                    + "</label>"
                    + (f" Current: {_esc(str(f.get('current_masked') or ''))}" if f.get("secret") else "")
                    + "</p>"
                )
                for f in state["fields"]
            ]
        )
        orgs_html = ""
        if state.get("source_type") == "mwdb":
            if mwdb_orgs:
                options = "".join(
                    [
                        (
                            f"<label style='display:block'>"
                            f"<input type='checkbox' name='mwdb_orgs' value='{_esc(str(o.get('id') or o.get('name') or ''))}' "
                            f"{'checked' if str(o.get('id') or o.get('name') or '') in mwdb_selected_orgs else ''}/> "
                            f"{_esc(str(o.get('name') or o.get('id') or ''))}</label>"
                        )
                        for o in mwdb_orgs
                    ]
                )
                group_options = "<option value=''>(none — use TLP:GREEN for all)</option>" + "".join(
                    f"<option value='{_esc(str(o.get('id') or o.get('name') or ''))}'"
                    f"{' selected' if str(o.get('id') or o.get('name') or '') == mwdb_selected_group else ''}>"
                    f"{_esc(str(o.get('name') or o.get('id') or ''))}</option>"
                    for o in mwdb_orgs
                )
                orgs_html = (
                    f"<fieldset><legend>MWDB organizations</legend>{options}</fieldset>"
                    f"<fieldset><legend>My MWDB group (TLP:AMBER for group-visible indicators)</legend>"
                    f"<p style='margin:.2rem 0 .5rem'>Indicators uploaded by this group will be tagged <strong>TLP:AMBER</strong>.</p>"
                    f"<select name='mwdb_my_group'>{group_options}</select>"
                    f"</fieldset>"
                )
            else:
                orgs_html = "<p>MWDB organizations list is unavailable. Use <strong>Test connection</strong> first.</p>"
        return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>Configure { _esc(source_id) }</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }}
  body[data-theme="light"] {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
  body[data-theme="dark"] {{ --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }}
  body:not([data-theme]) {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
  .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }}
  .topbar nav a {{ margin-right:.8rem; }}
  .card {{ border:1px solid var(--line); border-radius:12px; padding:1rem; background:var(--card); }}
  input, button {{ border:1px solid var(--line); border-radius:8px; padding:.4rem .5rem; background:var(--bg); color:var(--fg); }}
  fieldset {{ border:1px solid var(--line); border-radius:10px; margin:.8rem 0; padding:.6rem; }}
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
<div class='card'>
<h1>Configure feed: {_esc(source_id)}</h1>
<p>{_esc(msg)}</p>
<p>Status: {'OK' if state['ready'] else 'Incomplete: ' + _esc(', '.join(state['missing']))}</p>
<form method='post' action='/admin/feed/{_esc(source_id)}/configure' id='feedConfigForm'>
<p><label>Display name <input type='text' name='display_name' value='{_esc(feed.display_name)}' required/></label></p>
<p><label>Schedule cron <input type='text' name='schedule_cron' value='{_esc(feed.schedule_cron)}'/></label></p>
{fields_html}
{orgs_html}
<button type='submit' id='saveBtn'>Save settings</button>
<button type='submit' formaction='/admin/feed/{_esc(source_id)}/test' formmethod='post' id='testBtn'>Test connection</button>
<a href='/admin'>Back</a>
</form>
</div>
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
const form = document.getElementById('feedConfigForm');
if (form) {{
  form.addEventListener('submit', function (evt) {{
    const submitter = evt.submitter;
    const saveBtn = document.getElementById('saveBtn');
    const testBtn = document.getElementById('testBtn');
    if (saveBtn) saveBtn.disabled = true;
    if (testBtn) testBtn.disabled = true;
    if (submitter && submitter.id === 'testBtn') {{
      submitter.textContent = 'Testing...';
    }} else if (saveBtn) {{
      saveBtn.textContent = 'Saving...';
    }}
  }});
}}
</script>
</body></html>"""

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
            errors = _validate_feed_form(feed, request.form, state, db)
            for f in state["fields"]:
                input_name = str(f["input_name"])
                incoming = (request.form.get(input_name) or "").strip()
                if f["key"] == "base_url":
                    continue
                if f.get("secret"):
                    if incoming:
                        _set_setting(db, _feed_secret_key(feed.source_id, str(f["key"])), incoming, secret=True)
                    elif f.get("required") and not _get_setting(db, _feed_secret_key(feed.source_id, str(f["key"])), "", secret=True):
                        errors.append(f"Missing required field: {f['label']}")
                else:
                    normalized = incoming
                    if str(f.get("type") or "") == "checkbox":
                        normalized = "1" if incoming.lower() in {"1", "true", "yes", "on"} else "0"
                    _set_setting(db, _feed_value_key(feed.source_id, str(f["key"])), normalized, secret=False)
            if feed.source_type == "mwdb":
                orgs = [x.strip() for x in request.form.getlist("mwdb_orgs") if x.strip()]
                _set_setting(db, _feed_value_key(feed.source_id, "organizations"), ",".join(orgs), secret=False)
                my_grp = (request.form.get("mwdb_my_group") or "").strip()
                _set_setting(db, _feed_value_key(feed.source_id, "my_group"), my_grp, secret=False)
            if errors:
                db.rollback()
                return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Validation failed: {' '.join(errors)}"))
            db.commit()
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} configuration saved."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Configure feed failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed/<source_id>/test")
    @limiter.limit("20 per minute")
    def admin_feed_test_connection(source_id: str):
        source_id = (source_id or "").strip().lower()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            state = _read_feed_config_state(db, feed)
            field_values: Dict[str, str] = {}
            for f in state["fields"]:
                field_values[str(f["key"])] = _get_feed_field_value(db, feed, f, request.form)
            if feed.source_type == "mwdb":
                selected_orgs = [x.strip() for x in request.form.getlist("mwdb_orgs") if x.strip()]
                field_values["organizations"] = ",".join(selected_orgs)
            ok, msg = _test_feed_connection(feed, field_values)
            status = "OK" if ok else "FAILED"
            return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Connection test {status}: {msg}"))
        except Exception as e:
            return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Connection test failed: {e}"))
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

    @app.get("/admin/sync-jobs/<job_id>")
    @limiter.limit("30 per minute")
    def admin_sync_job_details(job_id: str):
        job_id = (job_id or "").strip()
        if not job_id:
            return redirect(url_for("admin_panel", msg="Missing job_id."))
        db = _db(read_only=True)
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Sync job not found: {job_id}"))
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == job_id))
            logs = list(
                db.scalars(
                    select(AppLog).where(AppLog.run_id == job_id).order_by(AppLog.created_at.desc()).limit(200)
                ).all()
            )
        finally:
            db.close()

        log_rows = "".join(
            [
                (
                    "<tr>"
                    f"<td>{_esc(str(item.created_at))}</td>"
                    f"<td>{_esc(item.level)}</td>"
                    f"<td>{_esc(item.component)}</td>"
                    f"<td>{_esc(item.message)}</td>"
                    f"<td><code>{_esc(json.dumps(item.metadata_ or {}, ensure_ascii=True))}</code></td>"
                    "</tr>"
                )
                for item in logs
            ]
        ) or "<tr><td colspan='5'>No logs for this job.</td></tr>"

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sync Job { _esc(job_id) }</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }}
  body[data-theme="light"] {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
  body[data-theme="dark"] {{ --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }}
  body:not([data-theme]) {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
  .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }}
  .card {{ border: 1px solid var(--line); border-radius: 12px; padding: 1rem; margin-bottom: 1rem; background: var(--card); }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ border-bottom:1px solid var(--line); padding:.45rem; text-align:left; vertical-align:top; }}
  button {{ padding: .5rem .8rem; border-radius: 8px; border: 1px solid var(--line); background: var(--card); color: var(--fg); }}
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
  <div class="card">
    <h1>Sync Job Details</h1>
    <p><strong>Job ID:</strong> <code>{_esc(job.job_id)}</code></p>
    <p><strong>Source:</strong> {_esc(job.feed_source_id)} | <strong>Trigger:</strong> {_esc(job.trigger_type)} | <strong>Status:</strong> {_esc(job.status)}</p>
    <p><strong>Created:</strong> {_esc(str(job.created_at or ''))} | <strong>Started:</strong> {_esc(str(job.started_at or ''))} | <strong>Finished:</strong> {_esc(str(job.finished_at or ''))}</p>
    <p><strong>Error:</strong> {_esc(str(job.error or ''))}</p>
    <p><strong>Result:</strong> <code>{_esc(json.dumps(job.result_json or {}, ensure_ascii=True))}</code></p>
    <p><strong>FeedRun status:</strong> {_esc(str(getattr(run, 'status', 'n/a')))} | <strong>Fetched:</strong> {_esc(str(getattr(run, 'fetched_count', 'n/a')))}</p>
    <p><a href="/api/logs?job_id={_esc(job.job_id)}&limit=200">Open JSON logs for this job</a></p>
  </div>
  <div class="card">
    <h2>Job Logs</h2>
    <table>
      <thead><tr><th>Time</th><th>Level</th><th>Component</th><th>Message</th><th>Metadata</th></tr></thead>
      <tbody>{log_rows}</tbody>
    </table>
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
  </script>
</body></html>"""

    @app.post("/admin/sync-jobs/<job_id>/retry")
    @limiter.limit("20 per minute")
    def admin_sync_job_retry(job_id: str):
        job_id = (job_id or "").strip()
        db = _db()
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Retry failed: job not found ({job_id})."))
            if str(job.status or "").lower() not in {"failed", "cancelled"}:
                return redirect(url_for("admin_panel", msg=f"Retry allowed only for failed/cancelled jobs (current: {job.status})."))
            feed = db.scalar(select(Feed).where(Feed.source_id == job.feed_source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg=f"Retry failed: feed not found ({job.feed_source_id})."))
            state = _read_feed_config_state(db, feed)
            if not state["ready"]:
                return redirect(url_for("admin_panel", msg=f"Retry blocked: configuration incomplete for {feed.source_id}."))
            new_job, created = _enqueue_sync_job(feed, trigger_type="retry", db=db)
            return redirect(
                url_for(
                    "admin_panel",
                    msg=f"Retry {'queued' if created else 'reused existing'} for {feed.source_id} (job_id={new_job.job_id}).",
                )
            )
        except Exception as e:
            logger.exception("admin_sync_job_retry_failed")
            return redirect(url_for("admin_panel", msg=f"Retry failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/sync-jobs/<job_id>/cancel")
    @limiter.limit("20 per minute")
    def admin_sync_job_cancel(job_id: str):
        job_id = (job_id or "").strip()
        db = _db()
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Cancel failed: job not found ({job_id})."))
            status = str(job.status or "").lower()
            if status in {"success", "failed", "cancelled"}:
                return redirect(url_for("admin_panel", msg=f"Cancel ignored: job already {status}."))
            now = datetime.now(timezone.utc)
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == job.job_id))
            if status == "queued":
                job.status = "cancelled"
                job.error = "cancelled by admin"
                job.finished_at = now
                job.result_json = {"cancelled": True}
                if run:
                    run.status = "cancelled"
                    run.error = "cancelled by admin"
                    run.finished_at = now
                db.commit()
                return redirect(url_for("admin_panel", msg=f"Job {job.job_id} cancelled."))
            job.status = "cancel_requested"
            if not job.error:
                job.error = "cancel requested by admin"
            if run and run.status == "running":
                run.error = "cancel requested by admin"
            db.commit()
            return redirect(url_for("admin_panel", msg=f"Cancellation requested for running job {job.job_id}."))
        except Exception as e:
            db.rollback()
            logger.exception("admin_sync_job_cancel_failed")
            return redirect(url_for("admin_panel", msg=f"Cancel failed: {e}"))
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

    @app.get("/api/feeds")
    @limiter.limit("60 per minute")
    def api_feeds():
        def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(request.args.get(name, str(default)))
            except ValueError:
                value = default
            return max(minimum, min(maximum, value))

        limit = _int_arg("limit", 25, 1, 100)
        offset = _int_arg("offset", 0, 0, 1000000)
        sort_by = (request.args.get("sort", "source") or "source").strip().lower()
        sort_order = (request.args.get("order", "asc") or "asc").strip().lower()
        status_filter = (request.args.get("status", "all") or "all").strip().upper()
        datasource = (request.args.get("datasource", "all") or "all").strip().lower()
        configured = (request.args.get("configured", "all") or "all").strip().lower()
        query_text = (request.args.get("q", "") or "").strip()
        problems_only = (request.args.get("problems_only", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}

        db = _db(read_only=True)
        try:
            all_items = _build_feed_items(db)
            filtered = _apply_feed_filters_and_sort(
                all_items,
                status_filter=status_filter,
                datasource=datasource,
                configured=configured,
                query_text=query_text,
                problems_only=problems_only,
                sort_by=sort_by,
                sort_order=sort_order,
            )
            total = len(filtered)
            if offset >= total and total > 0:
                offset = max(0, ((total - 1) // max(1, limit)) * max(1, limit))
            page = filtered[offset : offset + limit]
            return jsonify(
                {
                    "items": [
                        {
                            **item,
                            "last_run_at": item["last_run_at"].isoformat() if isinstance(item.get("last_run_at"), datetime) else None,
                            "last_error_at": item["last_error_at"].isoformat() if isinstance(item.get("last_error_at"), datetime) else None,
                        }
                        for item in page
                    ],
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "sort": sort_by,
                    "order": sort_order,
                    "filters": {
                        "status": status_filter,
                        "datasource": datasource,
                        "configured": configured,
                        "q": query_text,
                        "problems_only": problems_only,
                    },
                }
            )
        finally:
            db.close()

    @app.get("/api/feeds/metrics")
    @limiter.limit("60 per minute")
    def api_feeds_metrics():
        hours, window = _resolve_metrics_window_hours()
        datasource = (request.args.get("datasource") or "all").strip().lower()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        bucket_granularity = "hour" if hours <= 24 else "day"

        db = _db(read_only=True)
        try:
            feed_items = _build_feed_items(db)
            if datasource not in {"", "all"}:
                feed_items = [item for item in feed_items if str(item.get("source_type", "")).lower() == datasource]

            source_ids = [str(item["source_id"]) for item in feed_items]
            if not source_ids:
                return jsonify(
                    {
                        "window": window,
                        "hours": hours,
                        "bucket": bucket_granularity,
                        "datasource": datasource,
                        "total_feeds": 0,
                        "items": [],
                        "timeseries": [],
                        "summary": {},
                    }
                )

            runs = list(
                db.scalars(
                    select(FeedRun)
                    .where(FeedRun.feed_source_id.in_(source_ids), FeedRun.started_at >= cutoff)
                    .order_by(FeedRun.feed_source_id.asc(), FeedRun.started_at.asc())
                ).all()
            )
            by_feed: Dict[str, List[FeedRun]] = {sid: [] for sid in source_ids}
            for run in runs:
                by_feed.setdefault(str(run.feed_source_id), []).append(run)

            metric_items: List[Dict[str, Any]] = []
            aggregate_runs = 0
            aggregate_success = 0
            aggregate_errors = 0
            aggregate_fetched = 0
            aggregate_duration_total_ms = 0
            aggregate_duration_count = 0
            all_durations: List[int] = []
            all_buckets: Dict[str, Dict[str, Any]] = {}

            def _bucket_key(ts: datetime) -> str:
                if bucket_granularity == "hour":
                    return ts.replace(minute=0, second=0, microsecond=0).isoformat()
                return ts.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

            for item in feed_items:
                sid = str(item["source_id"])
                feed_runs = by_feed.get(sid, [])
                total_runs = len(feed_runs)
                success_runs = 0
                error_runs = 0
                total_fetched = 0
                duration_ms_total = 0
                duration_ms_count = 0
                durations: List[int] = []
                run_points: List[Dict[str, Any]] = []
                for run in feed_runs:
                    status = str(run.status or "").lower()
                    if status == "success":
                        success_runs += 1
                    if status in {"failed", "cancelled"}:
                        error_runs += 1
                    total_fetched += int(run.fetched_count or 0)
                    duration_ms = None
                    if run.finished_at is not None and run.started_at is not None:
                        duration_ms = max(0, int((run.finished_at - run.started_at).total_seconds() * 1000))
                        duration_ms_total += duration_ms
                        duration_ms_count += 1
                        durations.append(duration_ms)
                        all_durations.append(duration_ms)
                    if run.started_at is not None:
                        bk = _bucket_key(run.started_at)
                        point = all_buckets.setdefault(
                            bk,
                            {
                                "ts": bk,
                                "runs": 0,
                                "success_runs": 0,
                                "error_runs": 0,
                                "fetched_total": 0,
                                "duration_ms_total": 0,
                                "duration_ms_count": 0,
                            },
                        )
                        point["runs"] += 1
                        if status == "success":
                            point["success_runs"] += 1
                        if status in {"failed", "cancelled"}:
                            point["error_runs"] += 1
                        point["fetched_total"] += int(run.fetched_count or 0)
                        if duration_ms is not None:
                            point["duration_ms_total"] += int(duration_ms)
                            point["duration_ms_count"] += 1
                    run_points.append(
                        {
                            "run_id": run.run_id,
                            "status": run.status,
                            "started_at": run.started_at.isoformat() if run.started_at else None,
                            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                            "fetched_count": int(run.fetched_count or 0),
                            "duration_ms": duration_ms,
                            "details_url": f"/admin/sync-jobs/{run.run_id}",
                            "logs_url": f"/api/logs?run_id={run.run_id}&limit=200",
                        }
                    )
                availability = round((success_runs / total_runs) * 100, 2) if total_runs else None
                error_rate = round((error_runs / total_runs) * 100, 2) if total_runs else None
                avg_duration_ms = round(duration_ms_total / duration_ms_count, 2) if duration_ms_count else None
                avg_fetched = round(total_fetched / total_runs, 2) if total_runs else None

                aggregate_runs += total_runs
                aggregate_success += success_runs
                aggregate_errors += error_runs
                aggregate_fetched += total_fetched
                aggregate_duration_total_ms += duration_ms_total
                aggregate_duration_count += duration_ms_count

                metric_items.append(
                    {
                        "source_id": sid,
                        "display_name": item["display_name"],
                        "source_type": item["source_type"],
                        "status": item["status"],
                        "runs": total_runs,
                        "success_runs": success_runs,
                        "error_runs": error_runs,
                        "availability_pct": availability,
                        "error_rate_pct": error_rate,
                        "fetched_total": total_fetched,
                        "fetched_avg_per_run": avg_fetched,
                        "duration_avg_ms": avg_duration_ms,
                        "duration_p50_ms": _percentile(durations, 50.0),
                        "duration_p95_ms": _percentile(durations, 95.0),
                        "window_hours": hours,
                        "runs_timeseries": run_points[-200:],
                    }
                )

            timeseries = []
            for ts in sorted(all_buckets.keys()):
                bucket = all_buckets[ts]
                timeseries.append(
                    {
                        "ts": ts,
                        "runs": int(bucket["runs"]),
                        "success_runs": int(bucket["success_runs"]),
                        "error_runs": int(bucket["error_runs"]),
                        "fetched_total": int(bucket["fetched_total"]),
                        "duration_avg_ms": (
                            round(float(bucket["duration_ms_total"]) / float(bucket["duration_ms_count"]), 2)
                            if int(bucket["duration_ms_count"]) > 0
                            else None
                        ),
                    }
                )

            summary = {
                "runs_total": aggregate_runs,
                "availability_pct": round((aggregate_success / aggregate_runs) * 100, 2) if aggregate_runs else None,
                "error_rate_pct": round((aggregate_errors / aggregate_runs) * 100, 2) if aggregate_runs else None,
                "fetched_total": aggregate_fetched,
                "fetched_avg_per_run": round((aggregate_fetched / aggregate_runs), 2) if aggregate_runs else None,
                "duration_avg_ms": round((aggregate_duration_total_ms / aggregate_duration_count), 2) if aggregate_duration_count else None,
                "duration_p50_ms": _percentile(all_durations, 50.0),
                "duration_p95_ms": _percentile(all_durations, 95.0),
            }
            return jsonify(
                {
                    "window": window,
                    "hours": hours,
                    "bucket": bucket_granularity,
                    "datasource": datasource,
                    "total_feeds": len(metric_items),
                    "items": metric_items,
                    "timeseries": timeseries,
                    "summary": summary,
                }
            )
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
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>Logs</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }
  body[data-theme="light"] { --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }
  body[data-theme="dark"] { --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }
  body:not([data-theme]) { --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }
  .topbar { display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }
  .topbar nav a { margin-right:.8rem; }
  .card { border:1px solid var(--line); border-radius:12px; padding:1rem; background:var(--card); }
  input, button { border:1px solid var(--line); border-radius:8px; padding:.4rem .5rem; background:var(--bg); color:var(--fg); }
  label { display:inline-block; margin: .2rem .6rem .2rem 0; }
  pre { white-space: pre-wrap; border:1px solid var(--line); padding:10px; min-height:300px; background:var(--card); }
</style></head><body>
<header class="topbar" id="globalTopbar">
  <nav>
    <a href="/">Overview</a>
    <a href="/indicators">Indicators</a>
    <a href="/admin">Admin</a>
    <a href="/logs">Logs</a>
  </nav>
  <button type="button" id="themeToggleGlobal">Toggle dark mode</button>
</header>
<div class="card">
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
  <button type="button" id="copyBtn">Copy all visible logs</button>
  <button type="button" id="downloadBtn">Download visible .log</button>
</form>
<p id="copyStatus" role="status" aria-live="polite"></p>
<pre id="out"></pre>
</div>
<script>
const themeKey = 'ioc-theme';
const preferredTheme = localStorage.getItem(themeKey);
if (preferredTheme === 'dark' || preferredTheme === 'light') {
  document.body.setAttribute('data-theme', preferredTheme);
} else {
  const systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  document.body.setAttribute('data-theme', systemDark ? 'dark' : 'light');
}
const themeToggle = document.getElementById('themeToggleGlobal');
if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const curr = document.body.getAttribute('data-theme') || 'light';
    const next = curr === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', next);
    localStorage.setItem(themeKey, next);
  });
}
let visibleRows = [];
function setCopyStatus(message, kind){
  const el = document.getElementById('copyStatus');
  if (!el) return;
  el.textContent = message || '';
  el.style.color = kind === 'error' ? '#b91c1c' : '#047857';
}
function buildQuery(){const fd=new FormData(document.getElementById('filters'));const p=new URLSearchParams();for(const [k,v] of fd.entries()){if((v||'').trim())p.set(k,v);}p.set('limit','200');return p.toString();}
function formatLine(x){return `[${x.created_at}] ${x.level} ${x.component} ${x.feed_source_id||'-'} ${x.run_id||'-'} ${x.message} ${JSON.stringify(x.metadata||{})}`;}
function buildVisibleText(){
  const lines = (visibleRows || []).map(formatLine);
  return lines.join('\\n');
}
function fallbackCopyText(payload){
  const ta = document.createElement('textarea');
  ta.value = payload;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-9999px';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}
async function copyVisibleLogs(){
  const payload = buildVisibleText();
  const lineCount = payload ? payload.split('\\n').length : 0;
  if (!payload) {
    setCopyStatus('No visible logs to copy.', 'error');
    return;
  }
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(payload);
      setCopyStatus(`Copied ${lineCount} lines.`, 'ok');
      return;
    }
  } catch (err) {
    // continue to fallback
  }
  const copied = fallbackCopyText(payload);
  if (copied) {
    setCopyStatus(`Copied ${lineCount} lines (fallback).`, 'ok');
  } else {
    setCopyStatus('Copy failed. Use HTTPS/focused tab or copy manually.', 'error');
  }
}
function downloadVisibleLogs(){
  const payload = buildVisibleText();
  if (!payload) {
    setCopyStatus('No visible logs to download.', 'error');
    return;
  }
  const blob = new Blob([payload + '\\n'], {type: 'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const ts = new Date().toISOString().replace(/[:]/g, '-');
  a.href = url;
  a.download = `visible-logs-${ts}.log`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  setCopyStatus(`Downloaded ${(visibleRows || []).length} lines.`, 'ok');
}
async function refreshLogs(){
  const q=buildQuery();
  try {
    const r=await fetch('/api/logs?'+q);
    const d=await r.json();
    visibleRows = d.items || [];
    const lines=visibleRows.map(formatLine);
    document.getElementById('out').textContent=lines.length ? lines.join('\\n') : 'No logs found for current filters.';
  } catch (err) {
    visibleRows = [];
    document.getElementById('out').textContent='Failed to load logs.';
    setCopyStatus('Failed to refresh logs.', 'error');
  }
}
document.getElementById('filters').addEventListener('submit',(e)=>{e.preventDefault();refreshLogs();});
document.getElementById('copyBtn').addEventListener('click',copyVisibleLogs);
document.getElementById('downloadBtn').addEventListener('click',downloadVisibleLogs);
setInterval(()=>{if(document.getElementById('autorefresh').checked)refreshLogs();},5000);refreshLogs();
</script></body></html>"""

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
