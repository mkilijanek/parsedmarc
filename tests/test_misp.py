from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


class TestMISPCoverage:

    def test_misp_health_check_not_configured(self):
        from app.services.misp import misp_health_check
        mock_cfg = MagicMock()
        mock_cfg.MISP_URL = ""
        mock_cfg.MISP_API_KEY = ""
        result = misp_health_check(mock_cfg)
        assert result["status"] == "down"
        assert "not_configured" in str(result.get("error", ""))

    def test_misp_health_check_circuit_open(self):
        from app.services.misp import misp_health_check
        from app.services.common import _circuit_breaker
        mock_cfg = MagicMock()
        mock_cfg.MISP_URL = "https://misp.example.com"
        mock_cfg.MISP_API_KEY = "test-key"

        # Force circuit open temporarily
        with patch.object(_circuit_breaker, "is_open", return_value=True):
            result = misp_health_check(mock_cfg)
        assert result["status"] == "down"

    def test_misp_health_check_success(self):
        from app.services.misp import misp_health_check
        mock_cfg = MagicMock()
        mock_cfg.MISP_URL = "https://misp.example.com"
        mock_cfg.MISP_API_KEY = "test-key"
        mock_cfg.MISP_HEALTH_TIMEOUT_S = 3
        mock_cfg.MISP_VERIFY_SSL = False

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"version": "2.4"}

        mock_session = MagicMock()
        mock_session.__enter__ = lambda s: s
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session.get = MagicMock(return_value=mock_resp)

        with patch("app.services.misp.build_feed_session", return_value=mock_session):
            result = misp_health_check(mock_cfg)
        assert result["status"] == "ok"

    def test_misp_health_check_failure(self):
        from app.services.misp import misp_health_check
        mock_cfg = MagicMock()
        mock_cfg.MISP_URL = "https://misp.example.com"
        mock_cfg.MISP_API_KEY = "test-key"
        mock_cfg.MISP_HEALTH_TIMEOUT_S = 3
        mock_cfg.MISP_VERIFY_SSL = False

        mock_session = MagicMock()
        mock_session.__enter__ = lambda s: s
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session.get.side_effect = ConnectionError("refused")

        with patch("app.services.misp.build_feed_session", return_value=mock_session):
            result = misp_health_check(mock_cfg)
        assert result["status"] == "down"
        assert "error" in result

    def test_normalize_value_compound(self):
        from app.services.misp import _normalize_value
        val, meta = _normalize_value("ip-src|port", "1.2.3.4|443")
        assert val == "1.2.3.4"
        assert "compound_raw" in meta

    def test_normalize_value_plain(self):
        from app.services.misp import _normalize_value
        val, meta = _normalize_value("ip-src", "1.2.3.4")
        assert val == "1.2.3.4"
        assert "raw" in meta
