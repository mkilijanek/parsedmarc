from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.correlation_snapshot import refresh_correlation_snapshots


def test_refresh_correlation_snapshots_writes_cache(fake_redis):
    fake_db = MagicMock()

    with patch("app.services.correlation_snapshot.SessionLocal", return_value=fake_db), patch(
        "app.services.correlation_snapshot.get_redis", return_value=fake_redis
    ), patch(
        "app.services.correlation_snapshot.query_correlations",
        return_value=[
            {
                "value": "a.example",
                "type": "domain",
                "source_count": 2,
                "max_confidence": 90,
                "last_seen": "2026-01-01T00:00:00+00:00",
                "sources": [],
                "tags": [],
                "enrichment": {},
            }
        ],
    ):
        refresh_correlation_snapshots()

    key = "correlations|limit=1000|min_sources=2|type=all"
    assert fake_redis.get(key) is not None
