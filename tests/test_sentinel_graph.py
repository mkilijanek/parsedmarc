from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from app.services.sentinel_graph import build_graph_indicator, graph_access_token, push_indicators_to_graph


def test_build_graph_indicator_ip():
    row = SimpleNamespace(value="1.2.3.4", type="ip", source="mwdb", confidence=70, tlp="GREEN")
    out = build_graph_indicator(row)
    assert out["networkIPv4"] == "1.2.3.4"
    assert out["targetProduct"] == "Azure Sentinel"


def test_graph_access_token_client_secret():
    with patch("app.services.sentinel_graph.requests.post") as m_post:
        resp = MagicMock()
        resp.content = b'{"access_token":"tok"}'
        resp.json.return_value = {"access_token": "tok"}
        resp.raise_for_status.return_value = None
        m_post.return_value = resp
        token = graph_access_token(
            tenant_id="tenant",
            client_id="client",
            scope="https://graph.microsoft.com/.default",
            auth_mode="client_secret",
            client_secret="secret",
            cert_private_key_pem="",
            cert_thumbprint="",
        )
    assert token == "tok"


def test_push_indicators_to_graph_skips_unknown_type():
    rows = [
        SimpleNamespace(value="example.org", type="domain", source="mwdb", confidence=50, tlp="GREEN"),
        SimpleNamespace(value="n/a", type="object_id", source="mwdb", confidence=50, tlp="GREEN"),
    ]
    with patch("app.services.sentinel_graph.graph_access_token", return_value="tok"), patch(
        "app.services.sentinel_graph.requests.post"
    ) as m_post:
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        m_post.return_value = resp
        result = push_indicators_to_graph(
            indicators=rows,
            tenant_id="tenant",
            client_id="client",
            client_secret="secret",
        )
    assert result["details"]["sent"] == 1
    assert result["details"]["skipped"] == 1


# ---------------------------------------------------------------------------
# TestSentinelGraphCoverage — migrated from test_coverage_boost.py
# ---------------------------------------------------------------------------

class TestSentinelGraphCoverage:

    def test_build_graph_indicator_single(self):
        from app.services.sentinel_graph import build_graph_indicator
        mock_ind = MagicMock()
        mock_ind.value = "1.2.3.4"
        mock_ind.type = "ip"
        mock_ind.source = "misp"
        mock_ind.tags = ["malware"]
        mock_ind.confidence = 80
        mock_ind.tlp = "GREEN"
        mock_ind.is_active = True
        mock_ind.first_seen = datetime.now(timezone.utc)
        mock_ind.last_seen = datetime.now(timezone.utc)
        result = build_graph_indicator(mock_ind, expiration_days=30)
        assert result is not None
        assert isinstance(result, dict)

    def test_build_graph_indicator_domain(self):
        from app.services.sentinel_graph import build_graph_indicator
        mock_ind = MagicMock()
        mock_ind.value = "evil.example.com"
        mock_ind.type = "domain"
        mock_ind.source = "crowdsec"
        mock_ind.tags = []
        mock_ind.confidence = 70
        mock_ind.tlp = "AMBER"
        mock_ind.is_active = True
        mock_ind.first_seen = datetime.now(timezone.utc)
        mock_ind.last_seen = datetime.now(timezone.utc)
        result = build_graph_indicator(mock_ind)
        assert result is not None

    def test_b64url(self):
        from app.services.sentinel_graph import _b64url
        result = _b64url(b"hello world")
        assert isinstance(result, str)
        assert "=" not in result  # URL-safe base64 strips padding


# ---------------------------------------------------------------------------
# TestSentinelGraphUtils — migrated from test_coverage_boost4.py
# ---------------------------------------------------------------------------

class TestSentinelGraphUtils:

    def test_thumbprint_to_x5t_valid_hex(self):
        from app.services.sentinel_graph import _thumbprint_to_x5t
        result = _thumbprint_to_x5t("AA:BB:CC:DD")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_thumbprint_to_x5t_empty_returns_empty(self):
        from app.services.sentinel_graph import _thumbprint_to_x5t
        assert _thumbprint_to_x5t("") == ""

    def test_thumbprint_to_x5t_invalid_returns_empty(self):
        from app.services.sentinel_graph import _thumbprint_to_x5t
        result = _thumbprint_to_x5t("not-hex!")
        assert result == ""

    def test_build_graph_indicator_ip(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "1.2.3.4"
        row.type = "ip"
        row.source = "misp"
        row.confidence = 80
        row.tlp = "GREEN"
        result = build_graph_indicator(row)
        assert result.get("networkIPv4") == "1.2.3.4"

    def test_build_graph_indicator_domain(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "evil.com"
        row.type = "domain"
        row.source = "misp"
        row.confidence = 70
        row.tlp = "AMBER"
        result = build_graph_indicator(row)
        assert result.get("domainName") == "evil.com"

    def test_build_graph_indicator_url(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "http://evil.com/path"
        row.type = "url"
        row.source = "misp"
        row.confidence = 60
        row.tlp = "WHITE"
        result = build_graph_indicator(row)
        assert result.get("url") == "http://evil.com/path"

    def test_build_graph_indicator_hash_md5(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "d" * 32
        row.type = "hash"
        row.source = "misp"
        row.confidence = 90
        row.tlp = "RED"
        result = build_graph_indicator(row)
        assert result.get("fileHashType") == "md5"
        assert result.get("fileHashValue") == "d" * 32

    def test_build_graph_indicator_hash_sha256(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "a" * 64
        row.type = "hash"
        row.source = "misp"
        row.confidence = 95
        row.tlp = "GREEN"
        result = build_graph_indicator(row)
        assert result.get("fileHashType") == "sha256"

    def test_build_graph_indicator_unknown_type_returns_empty(self):
        from app.services.sentinel_graph import build_graph_indicator
        row = MagicMock()
        row.value = "something"
        row.type = "unknown_type_xyz"
        row.source = "test"
        row.confidence = 50
        row.tlp = "WHITE"
        result = build_graph_indicator(row)
        assert result == {}
