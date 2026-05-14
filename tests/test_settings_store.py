from __future__ import annotations

import base64
import hashlib
import hmac
import os
from unittest.mock import MagicMock, patch

import pytest


class TestSettingsStoreCoverage2:

    def test_get_admin_api_token_default_empty(self, test_db):
        from app.settings_store import get_admin_api_token
        with patch.dict(os.environ, {"ADMIN_API_TOKEN": ""}, clear=False):
            result = get_admin_api_token(test_db)
        # Result should be string (empty or from env)
        assert isinstance(result, str)

    def test_get_admin_api_token_from_env(self, test_db):
        from app.settings_store import get_admin_api_token
        with patch.dict(os.environ, {"ADMIN_API_TOKEN": "token-from-env", "APP_ENV": "development"}, clear=False):
            result = get_admin_api_token(test_db)
        assert result == "token-from-env"

    def test_get_setting_with_priority_default_fallback(self, test_db):
        from app.settings_store import get_setting_with_priority
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=False):
            os.environ.pop("NONEXISTENT_TEST_VAR_XYZ", None)
            result = get_setting_with_priority(
                test_db,
                env_name="NONEXISTENT_TEST_VAR_XYZ",
                setting_key="nonexistent.setting.xyz",
                default="my_default",
            )
        assert result == "my_default"

    def test_decrypt_v1_valid_roundtrip(self):
        """Test v1 decrypt roundtrip using HMAC/SHA256 stream cipher."""
        from app.settings_store import _secret_enc_key_v1, decrypt_setting_value

        key = _secret_enc_key_v1()
        nonce = os.urandom(16)
        plaintext = b"test_secret_value"
        # Encrypt
        stream = bytearray()
        counter = 0
        while len(stream) < len(plaintext):
            block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
            stream.extend(block)
            counter += 1
        cipher = bytes(a ^ b for a, b in zip(plaintext, stream))
        mac = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
        blob = nonce + mac + cipher
        encoded = "v1:" + base64.urlsafe_b64encode(blob).decode("ascii")
        result = decrypt_setting_value(encoded)
        assert result == "test_secret_value"
