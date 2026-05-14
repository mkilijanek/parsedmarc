"""
settings_svc — AppSetting CRUD + encryption + proxy bootstrap.

All functions are closures bound to the injected dependencies via
make_settings_service(). Nothing in this module imports from factory.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AppSetting
from ..runtime_env import update_proxy_settings_from_mapping

logger = logging.getLogger(__name__)


def make_settings_service(*, cfg, db_fn):
    """Return a namespace of settings-related functions bound to cfg and db_fn."""

    # ------------------------------------------------------------------ crypto

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

    # ------------------------------------------------------------------ CRUD

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

    # ------------------------------------------------------------------ utils

    def _mask_secret(value: str) -> str:
        if not value:
            return ""
        tail = value[-4:] if len(value) >= 4 else value
        return "*" * max(4, len(value) - len(tail)) + tail

    # ------------------------------------------------------------------ proxy / bootstrap

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
        db = db_fn()
        try:
            _write_proxy_env(db)
        except Exception:
            logger.warning("runtime_settings_bootstrap_failed", exc_info=True)
        finally:
            db.close()

    # ------------------------------------------------------------------ namespace

    from types import SimpleNamespace

    ns = SimpleNamespace(
        get_setting=_get_setting,
        set_setting=_set_setting,
        mask_secret=_mask_secret,
        runtime_override_or_env=_runtime_override_or_env,
        bootstrap_runtime_settings=_bootstrap_runtime_settings,
        write_proxy_env=_write_proxy_env,
        # expose decrypt so feed_config_svc can use it
        secret_decrypt=_secret_decrypt,
    )
    return ns
