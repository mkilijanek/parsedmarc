from __future__ import annotations

from unittest.mock import patch


def test_correlations_response_is_cached(client, test_db, fake_redis):
    calls = {"n": 0}

    def _fake_query(*args, **kwargs):
        calls["n"] += 1
        return [
            {
                "value": "cached.example.org",
                "type": "domain",
                "source_count": 2,
                "max_confidence": 80,
                "last_seen": "2026-01-01T00:00:00+00:00",
                "sources": [],
                "tags": [],
                "enrichment": {},
            }
        ]

    with patch("app.main.get_redis", return_value=fake_redis), patch("app.main.query_correlations", side_effect=_fake_query):
        r1 = client.get("/correlations?min_sources=2&type=domain&limit=10")
        r2 = client.get("/correlations?min_sources=2&type=domain&limit=10")

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert calls["n"] == 1


def test_health_response_is_cached(client, fake_redis):
    with patch("app.main.get_redis", return_value=fake_redis):
        r1 = client.get("/health")
        r2 = client.get("/health")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.get_data() == r2.get_data()
