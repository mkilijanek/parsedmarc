from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .config import Config
from .models import AppSetting


def _is_production(cfg: Config | None = None) -> bool:
    """Return True when APP_ENV is 'production'."""
    if cfg is not None:
        env = str(getattr(cfg.runtime, "APP_ENV", "") or "").strip().lower()
    else:
        env = os.getenv("APP_ENV", "development").strip().lower()
    return env == "production"


def _env_var_is_set(env_name: str) -> bool:
    """Return True when the env var is present and non-empty in the process environment."""
    return bool(os.environ.get(env_name, "").strip())


def _secret_enc_key_v2(cfg: Config | None = None) -> bytes:
    active_cfg = cfg or Config()
    return hashlib.sha256(("ioc-service:v2:" + active_cfg.SECRET_KEY).encode("utf-8")).digest()


def _secret_enc_key_v1(cfg: Config | None = None) -> bytes:
    active_cfg = cfg or Config()
    return hashlib.sha256(active_cfg.SECRET_KEY.encode("utf-8")).digest()


def decrypt_setting_value(value: str, cfg: Config | None = None) -> str:
    if not value:
        return ""
    if value.startswith("v2:"):
        try:
            blob = base64.urlsafe_b64decode(value[3:].encode("ascii"))
            if len(blob) < 13:
                return ""
            nonce = blob[:12]
            cipher = blob[12:]
            plain = AESGCM(_secret_enc_key_v2(cfg)).decrypt(nonce, cipher, None)
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
        key = _secret_enc_key_v1(cfg)
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


def get_app_setting(
    db: Session,
    key: str,
    default: str = "",
    *,
    secret: bool = False,
    cfg: Config | None = None,
) -> str:
    try:
        row: Optional[AppSetting] = db.scalar(select(AppSetting).where(AppSetting.key == key))
    except SQLAlchemyError:
        return default
    if row is None:
        return default
    if secret:
        return decrypt_setting_value(str(row.value or ""), cfg)
    return str(row.value or "")


def _db_value(
    db: Session,
    setting_key: str,
    *,
    secret: bool = False,
    cfg: Config | None = None,
) -> Optional[str]:
    """Return the raw DB value for *setting_key*, or None if absent / unreadable."""
    try:
        row: Optional[AppSetting] = db.scalar(select(AppSetting).where(AppSetting.key == setting_key))
    except SQLAlchemyError:
        return None
    if row is None:
        return None
    raw = str(row.value or "")
    if not raw:
        return None
    if secret:
        decrypted = decrypt_setting_value(raw, cfg)
        return decrypted if decrypted else None
    return raw


def get_setting_with_priority(
    db: Session,
    *,
    env_name: str,
    setting_key: str,
    default: str = "",
    secret: bool = False,
    cfg: Config | None = None,
) -> str:
    """Resolve a setting using environment-aware priority.

    DEV  (APP_ENV != 'production'): env var → DB → default
    PRD  (APP_ENV == 'production'): DB → env var → default

    The env var wins in DEV so operators can iterate with .env files without touching
    the database.  DB wins in PRD so live admin-panel changes survive container restarts
    without the compose env silently overwriting them.
    """
    env_raw = os.environ.get(env_name, "").strip()
    db_raw = _db_value(db, setting_key, secret=secret, cfg=cfg)

    if _is_production(cfg):
        # PRD: DB first
        if db_raw is not None:
            return db_raw
        return env_raw if env_raw else default
    else:
        # DEV: env first
        if env_raw:
            return env_raw
        if db_raw is not None:
            return db_raw
        return default


def runtime_override_or_env(
    db: Session,
    *,
    setting_key: str,
    env_value: str,
    secret: bool = False,
    cfg: Config | None = None,
) -> str:
    """Legacy helper kept for backward compatibility.

    Prefer get_setting_with_priority() for new callers — it respects APP_ENV.
    This wrapper preserves the old DB-first behaviour for existing callers that
    do not yet pass an env_name.
    """
    db_raw = _db_value(db, setting_key, secret=secret, cfg=cfg)
    if db_raw is not None:
        return db_raw
    return str(env_value or "")


def parse_bool_setting(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def admin_auth_disable_allowed_in_production(cfg: Config | None = None) -> bool:
    active_cfg = cfg or Config()
    return bool(getattr(active_cfg.security, "ADMIN_AUTH_ALLOW_DISABLED_IN_PRODUCTION", False))


def get_admin_login_rate_limit(
    db: Session,
    cfg: Config | None = None,
) -> str:
    """Resolve admin login rate limit respecting APP_ENV priority."""
    from .config import Config as ConfigClass
    active_cfg = cfg or ConfigClass()
    default = getattr(active_cfg.security, "ADMIN_LOGIN_RATE_LIMIT", "10 per 15 minute")
    return get_setting_with_priority(
        db,
        env_name="ADMIN_LOGIN_RATE_LIMIT",
        setting_key="feedcfg.security.admin_login_rate_limit",
        default=default,
        cfg=active_cfg,
    )


def get_admin_login_rate_limit_window(
    db: Session,
    cfg: Config | None = None,
) -> int:
    """Resolve admin login rate-limit window in minutes respecting APP_ENV priority."""
    from .config import Config as ConfigClass
    active_cfg = cfg or ConfigClass()
    default = str(getattr(active_cfg.security, "ADMIN_LOGIN_RATE_LIMIT_WINDOW_MINUTES", 15))
    value = get_setting_with_priority(
        db,
        env_name="ADMIN_LOGIN_RATE_LIMIT_WINDOW_MINUTES",
        setting_key="feedcfg.security.admin_login_rate_limit_window_minutes",
        default=default,
        cfg=active_cfg,
    )
    try:
        return int(value) if value else 15
    except (ValueError, TypeError):
        return 15


def get_admin_auth_enabled(
    db: Session,
    cfg: Config | None = None,
) -> bool:
    """Resolve ADMIN_AUTH_ENABLED respecting APP_ENV priority.

    DEV: env var wins — set ADMIN_AUTH_ENABLED=false in .env to skip login locally.
    PRD: DB wins — toggled live from the admin panel without container restart.
    """
    from .config import Config as ConfigClass
    active_cfg = cfg or ConfigClass()
    default = "true" if getattr(active_cfg.security, "ADMIN_AUTH_ENABLED", True) else "false"
    value = get_setting_with_priority(
        db,
        env_name="ADMIN_AUTH_ENABLED",
        setting_key="feedcfg.security.admin_auth_enabled",
        default=default,
        cfg=active_cfg,
    )
    enabled = parse_bool_setting(value)
    if _is_production(active_cfg) and not enabled and not admin_auth_disable_allowed_in_production(active_cfg):
        return True
    return enabled


def get_admin_panel_enabled(
    db: Session,
    cfg: Config | None = None,
) -> bool:
    """Resolve ADMIN_PANEL_ENABLED respecting APP_ENV priority.

    When False, all /admin/* routes return 404 — the panel is completely hidden.
    DEV: env var wins.  PRD: DB wins.
    """
    from .config import Config as ConfigClass
    active_cfg = cfg or ConfigClass()
    default = "true" if getattr(active_cfg.security, "ADMIN_PANEL_ENABLED", True) else "false"
    value = get_setting_with_priority(
        db,
        env_name="ADMIN_PANEL_ENABLED",
        setting_key="feedcfg.security.admin_panel_enabled",
        default=default,
        cfg=active_cfg,
    )
    return parse_bool_setting(value)


def get_admin_api_token(
    db: Session,
    cfg: Config | None = None,
) -> str:
    """Resolve ADMIN_API_TOKEN respecting APP_ENV priority.

    DEV: env var wins.  PRD: DB wins (stored encrypted as feedsecret.*).
    """
    from .config import Config as ConfigClass
    active_cfg = cfg or ConfigClass()
    default = getattr(active_cfg.security, "ADMIN_API_TOKEN", "") or ""
    return get_setting_with_priority(
        db,
        env_name="ADMIN_API_TOKEN",
        setting_key="feedsecret.security.admin_api_token",
        default=default,
        secret=True,
        cfg=active_cfg,
    )
