from __future__ import annotations

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
