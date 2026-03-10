from __future__ import annotations

from unittest.mock import patch

from app.services.common import build_feed_session, get_feed_proxies, redact_proxy_credentials


def test_get_feed_proxies_supports_per_source_override():
    with patch.dict(
        "os.environ",
        {
            "FEED_PROXY_URL_ABUSECH": "http://proxy.local:8080",
        },
        clear=False,
    ):
        proxies = get_feed_proxies(source="abusech")
    assert proxies == {"http": "http://proxy.local:8080", "https": "http://proxy.local:8080"}


def test_build_feed_session_uses_override_proxy():
    with patch.dict(
        "os.environ",
        {
            "FEED_HTTP_PROXY_MWDB": "http://proxy-http.local:8080",
            "FEED_HTTPS_PROXY_MWDB": "http://proxy-https.local:8080",
        },
        clear=False,
    ):
        session = build_feed_session(source="mwdb")
    try:
        assert session.proxies.get("http") == "http://proxy-http.local:8080"
        assert session.proxies.get("https") == "http://proxy-https.local:8080"
    finally:
        session.close()


def test_redact_proxy_credentials_hides_user_pass():
    raw = "ProxyError: HTTPSConnectionPool(host='x',): http://user:secret@proxy.local:8080"
    redacted = redact_proxy_credentials(raw)
    assert "user:secret@" not in redacted
    assert "***:***@" in redacted
