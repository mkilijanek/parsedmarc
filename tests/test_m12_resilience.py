from __future__ import annotations

from unittest.mock import patch


class _BrokenRedis:
    def get(self, _key):
        raise RuntimeError("redis down")

    def setex(self, _key, _ttl, _value):
        raise RuntimeError("redis down")


def test_indicators_view_degrades_gracefully_when_cache_unavailable(client, sample_indicators):
    with patch("app.main.get_redis", return_value=_BrokenRedis()):
        response = client.get("/indicators?type=ip")
    assert response.status_code == 200
    assert "text/html" in response.content_type


def test_export_degrades_gracefully_when_cache_unavailable(client, sample_indicators):
    with patch("app.main.get_redis", return_value=_BrokenRedis()):
        response = client.get("/indicators/json?type=ip")
    assert response.status_code == 200
    assert "application/json" in response.content_type


def test_limiter_reference_is_kept_on_app(app):
    assert hasattr(app, "limiter")
