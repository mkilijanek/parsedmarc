from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .config import Config
from .models import AppSetting


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


def runtime_override_or_env(
    db: Session,
    *,
    setting_key: str,
    env_value: str,
    secret: bool = False,
    cfg: Config | None = None,
) -> str:
    try:
        row: Optional[AppSetting] = db.scalar(select(AppSetting).where(AppSetting.key == setting_key))
    except SQLAlchemyError:
        return str(env_value or "")
    if row is None:
        return str(env_value or "")
    if secret:
        return decrypt_setting_value(str(row.value or ""), cfg)
    return str(row.value or "")


def parse_bool_setting(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}
