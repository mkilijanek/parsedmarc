"""Tests for app/services/settings_svc.py.

Covers encrypt/decrypt round-trips, v1 fallback, CRUD helpers,
mask_secret, and runtime_override_or_env.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg(secret_key: str = "test-secret-key-32-bytes-long-ok!"):
    return SimpleNamespace(SECRET_KEY=secret_key)


def _make_service(secret_key: str = "test-secret-key-32-bytes-long-ok!"):
    from app.services.settings_svc import make_settings_service
    cfg = _make_cfg(secret_key)
    db_fn = MagicMock(return_value=MagicMock())
    return make_settings_service(cfg=cfg, db_fn=db_fn), db_fn


def _noop_db():
    m = MagicMock()
    m.scalar.return_value = None
    return m


# ---------------------------------------------------------------------------
# Encrypt / decrypt round-trip (v2)
# ---------------------------------------------------------------------------

class TestSecretEncryptDecrypt:
    def test_encrypt_produces_v2_prefix(self):
        svc, _ = _make_service()
        result = svc.secret_decrypt.__self__ if hasattr(svc.secret_decrypt, '__self__') else None
        # Access encrypt through the service by encrypting via set_setting and reading back
        db = _noop_db()
        row = MagicMock()
        db.scalar.return_value = None  # new row path
        svc.set_setting(db, "k", "myvalue", secret=True)
        added = db.add.call_args[0][0]
        assert added.value.startswith("v2:")

    def test_decrypt_empty_string_returns_empty(self):
        svc, _ = _make_service()
        assert svc.secret_decrypt("") == ""

    def test_decrypt_v2_round_trip(self):
        svc, _ = _make_service()
        db = _noop_db()
        svc.set_setting(db, "k", "supersecret", secret=True)
        encrypted = db.add.call_args[0][0].value
        assert svc.secret_decrypt(encrypted) == "supersecret"

    def test_decrypt_plaintext_passthrough(self):
        """A stored value with no v1:/v2: prefix is returned as-is."""
        svc, _ = _make_service()
        assert svc.secret_decrypt("plain-value") == "plain-value"

    def test_decrypt_truncated_v2_blob_returns_empty(self):
        """Blob shorter than 13 bytes must return empty string without raising."""
        import base64
        svc, _ = _make_service()
        bad = "v2:" + base64.urlsafe_b64encode(b"short").decode()
        assert svc.secret_decrypt(bad) == ""

    def test_decrypt_v2_wrong_key_returns_empty(self):
        """Ciphertext encrypted with key A must not decrypt under key B."""
        svc_a, _ = _make_service("key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        svc_b, _ = _make_service("key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        db = _noop_db()
        svc_a.set_setting(db, "k", "secret", secret=True)
        encrypted = db.add.call_args[0][0].value
        assert svc_b.secret_decrypt(encrypted) == ""

    def test_decrypt_bad_v2_payload_returns_empty(self):
        """Malformed v2: payload must return empty without raising."""
        svc, _ = _make_service()
        assert svc.secret_decrypt("v2:!!!notbase64!!!") == ""

    def test_decrypt_empty_v1_blob_returns_empty(self):
        """Short v1: blob must return empty."""
        import base64
        svc, _ = _make_service()
        bad = "v1:" + base64.urlsafe_b64encode(b"short").decode()
        assert svc.secret_decrypt(bad) == ""


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

class TestGetSetSetting:
    def test_get_setting_returns_default_when_missing(self):
        svc, _ = _make_service()
        db = _noop_db()
        assert svc.get_setting(db, "missing.key", "fallback") == "fallback"

    def test_get_setting_returns_value_when_present(self):
        svc, _ = _make_service()
        db = _noop_db()
        row = MagicMock()
        row.value = "hello"
        db.scalar.return_value = row
        assert svc.get_setting(db, "k") == "hello"

    def test_get_setting_decrypts_when_secret(self):
        svc, _ = _make_service()
        db_write = _noop_db()
        svc.set_setting(db_write, "k", "topsecret", secret=True)
        encrypted = db_write.add.call_args[0][0].value

        db_read = _noop_db()
        row = MagicMock()
        row.value = encrypted
        db_read.scalar.return_value = row
        assert svc.get_setting(db_read, "k", secret=True) == "topsecret"

    def test_set_setting_creates_new_row_when_absent(self):
        svc, _ = _make_service()
        db = _noop_db()
        svc.set_setting(db, "new.key", "newval")
        db.add.assert_called_once()
        added = db.add.call_args[0][0]
        assert added.key == "new.key"
        assert added.value == "newval"

    def test_set_setting_updates_existing_row(self):
        svc, _ = _make_service()
        db = _noop_db()
        existing = MagicMock()
        existing.value = "old"
        db.scalar.return_value = existing
        svc.set_setting(db, "k", "new")
        assert existing.value == "new"
        assert existing.is_secret is False
        db.add.assert_not_called()

    def test_set_setting_updates_existing_secret_row(self):
        svc, _ = _make_service()
        db = _noop_db()
        existing = MagicMock()
        db.scalar.return_value = existing
        svc.set_setting(db, "k", "newsecret", secret=True)
        assert existing.value.startswith("v2:")
        assert existing.is_secret is True


# ---------------------------------------------------------------------------
# mask_secret
# ---------------------------------------------------------------------------

class TestMaskSecret:
    def test_empty_returns_empty(self):
        svc, _ = _make_service()
        assert svc.mask_secret("") == ""

    def test_short_value_shows_full_tail(self):
        svc, _ = _make_service()
        result = svc.mask_secret("ab")
        assert result.endswith("ab")
        assert "****" in result or len(result) >= 2

    def test_long_value_masks_prefix(self):
        svc, _ = _make_service()
        result = svc.mask_secret("supersecretpassword")
        assert result.endswith("word")
        assert "*" in result

    def test_exactly_four_chars(self):
        svc, _ = _make_service()
        result = svc.mask_secret("abcd")
        assert result.endswith("abcd")


# ---------------------------------------------------------------------------
# runtime_override_or_env
# ---------------------------------------------------------------------------

class TestRuntimeOverrideOrEnv:
    def test_returns_env_when_no_db_row(self, monkeypatch):
        svc, _ = _make_service()
        db = _noop_db()
        monkeypatch.setenv("SOME_ENV_KEY", "from_env")
        result = svc.runtime_override_or_env(db, setting_key="missing", env_key="SOME_ENV_KEY")
        assert result == "from_env"

    def test_returns_db_value_when_row_exists(self):
        svc, _ = _make_service()
        db = _noop_db()
        row = MagicMock()
        row.value = "db_override"
        db.scalar.return_value = row
        result = svc.runtime_override_or_env(db, setting_key="k", env_key="IGNORED")
        assert result == "db_override"

    def test_returns_decrypted_when_secret(self):
        svc, _ = _make_service()
        db_write = _noop_db()
        svc.set_setting(db_write, "k", "mysecret", secret=True)
        encrypted = db_write.add.call_args[0][0].value

        db_read = _noop_db()
        row = MagicMock()
        row.value = encrypted
        db_read.scalar.return_value = row
        result = svc.runtime_override_or_env(db_read, setting_key="k", env_key="X", secret=True)
        assert result == "mysecret"

    def test_returns_empty_string_when_env_missing(self):
        svc, _ = _make_service()
        db = _noop_db()
        import os
        os.environ.pop("NONEXISTENT_VAR_12345", None)
        result = svc.runtime_override_or_env(db, setting_key="missing", env_key="NONEXISTENT_VAR_12345")
        assert result == ""
