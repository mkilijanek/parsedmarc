"""
Test fixtures and configuration for comprehensive IOC service testing.

This module provides:
- Database fixtures with test data
- Redis mocking using fakeredis
- Flask app test client
- Sample indicator data
- Security validation helpers
"""
from __future__ import annotations

import os
import pytest
from datetime import datetime, timezone
from typing import Generator
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from fakeredis import FakeRedis

# Set test environment variables before importing app modules
os.environ.setdefault("SECRET_KEY", "test-secret-key-minimum-32-characters-long-for-security")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("LOG_LEVEL", "ERROR")
os.environ.setdefault("ALLOWED_HOSTS", "*")
os.environ.setdefault("TRUSTED_PROXY_COUNT", "0")
os.environ.setdefault("MISP_VERIFY_SSL", "true")
os.environ.setdefault("ENABLE_BACKGROUND_JOBS", "false")
os.environ.setdefault("ADMIN_API_TOKEN", "test-admin-token")

from app.db import Base
from app.models import Indicator, FeedStats, AuditLog
from app.main import create_app


@pytest.fixture(scope="function")
def test_engine():
    """Create a test database engine using SQLite in-memory."""
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        future=True,
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="function")
def test_db(test_engine):
    """Create a test database session."""
    Session = scoped_session(sessionmaker(bind=test_engine, autoflush=False, autocommit=False, future=True))
    session = Session()
    yield session
    session.rollback()
    session.close()
    Session.remove()


@pytest.fixture(scope="function")
def fake_redis():
    """Create a fake Redis instance for testing."""
    return FakeRedis()


@pytest.fixture(scope="function")
def app(test_db, fake_redis):
    """Create Flask app configured for testing."""
    with patch("app.db.SessionLocal") as mock_session, patch("app.main.SessionLocal") as mock_main_session:
        with patch("app.cache.get_redis") as mock_redis, patch("app.main.get_redis") as mock_main_redis:
            # Mock database session
            mock_session.return_value = test_db
            mock_main_session.return_value = test_db

            # Mock Redis
            mock_redis.return_value = fake_redis
            mock_main_redis.return_value = fake_redis

            # Create app
            app = create_app()
            app.config["TESTING"] = True
            app.config["WTF_CSRF_ENABLED"] = False

            yield app


@pytest.fixture(scope="function")
def client(app):
    """Create Flask test client."""
    return app.test_client()


@pytest.fixture(scope="function")
def admin_client(client):
    """Create an authenticated admin client using the configured admin token."""
    response = client.post(
        "/auth/login",
        data={"admin_token": os.environ["ADMIN_API_TOKEN"], "next": "/admin"},
        follow_redirects=False,
    )
    assert response.status_code in {301, 302}
    return client


@pytest.fixture(scope="function")
def admin_csrf_token(admin_client):
    """Return the admin CSRF token from the authenticated session."""
    with admin_client.session_transaction() as sess:
        token = sess.get("admin_csrf_token")
    assert token
    return token


@pytest.fixture(scope="function")
def sample_indicators(test_db) -> list[Indicator]:
    """Create sample indicators for testing."""
    indicators = [
        # High confidence IP indicators
        Indicator(
            value="192.168.1.100",
            type="ip",
            source="misp",
            source_id="event-123",
            confidence=95,
            tlp="RED",
            is_active=True,
            tags=["apt", "malware", "ransomware"],
            metadata_={"threat_actor": "APT28", "campaign": "test-campaign"},
            first_seen=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        ),
        Indicator(
            value="10.0.0.50",
            type="ip",
            source="crowdsec",
            source_id="list-abc",
            confidence=80,
            tlp="AMBER",
            is_active=True,
            tags=["scanner", "brute-force"],
            metadata_={"country": "CN"},
            first_seen=datetime(2025, 1, 2, 12, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2025, 1, 16, 12, 0, 0, tzinfo=timezone.utc),
        ),
        # Domain indicators
        Indicator(
            value="malicious.example.com",
            type="domain",
            source="misp",
            source_id="event-456",
            confidence=90,
            tlp="AMBER",
            is_active=True,
            tags=["phishing", "c2"],
            metadata_={"registrar": "evil-registrar"},
            first_seen=datetime(2025, 1, 3, 12, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2025, 1, 17, 12, 0, 0, tzinfo=timezone.utc),
        ),
        # URL indicator
        Indicator(
            value="http://evil.com/payload.exe",
            type="url",
            source="malwarebazaar",
            source_id="sample-789",
            confidence=85,
            tlp="GREEN",
            is_active=True,
            tags=["malware", "dropper"],
            metadata_={"file_type": "exe"},
            first_seen=datetime(2025, 1, 4, 12, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2025, 1, 18, 12, 0, 0, tzinfo=timezone.utc),
        ),
        # Hash indicator
        Indicator(
            value="a" * 64,  # SHA-256
            type="hash",
            source="mwdb",
            source_id="sample-xyz",
            confidence=100,
            tlp="WHITE",
            is_active=True,
            tags=["malware", "trojan"],
            metadata_={"family": "emotet"},
            first_seen=datetime(2025, 1, 5, 12, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2025, 1, 19, 12, 0, 0, tzinfo=timezone.utc),
        ),
        # Email indicator
        Indicator(
            value="phishing@evil.com",
            type="email",
            source="misp",
            source_id="event-999",
            confidence=75,
            tlp="GREEN",
            is_active=True,
            tags=["phishing"],
            metadata_={},
            first_seen=datetime(2025, 1, 6, 12, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2025, 1, 20, 12, 0, 0, tzinfo=timezone.utc),
        ),
        # Inactive indicator (for filtering tests)
        Indicator(
            value="172.16.0.1",
            type="ip",
            source="misp",
            source_id="event-old",
            confidence=50,
            tlp="WHITE",
            is_active=False,
            tags=["old"],
            metadata_={},
            first_seen=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc),
        ),
        # Low confidence indicator
        Indicator(
            value="8.8.8.8",
            type="ip",
            source="crowdsec",
            source_id="list-test",
            confidence=25,
            tlp="WHITE",
            is_active=True,
            tags=["low-confidence"],
            metadata_={},
            first_seen=datetime(2025, 1, 7, 12, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2025, 1, 21, 12, 0, 0, tzinfo=timezone.utc),
        ),
    ]

    for ind in indicators:
        test_db.add(ind)
    test_db.commit()

    # Refresh to get IDs
    for ind in indicators:
        test_db.refresh(ind)

    return indicators


@pytest.fixture(scope="function")
def sample_feed_stats(test_db) -> list[FeedStats]:
    """Create sample feed statistics for testing."""
    stats = [
        FeedStats(
            source="misp",
            source_id="server-1",
            total_indicators=1000,
            active_indicators=950,
            inactive_indicators=50,
            last_update=datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
            last_fetch_status="success",
            last_fetch_error=None,
            metadata_={"events_fetched": 100},
        ),
        FeedStats(
            source="crowdsec",
            source_id="blocklist-1",
            total_indicators=500,
            active_indicators=500,
            inactive_indicators=0,
            last_update=datetime(2025, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
            last_fetch_status="success",
            last_fetch_error=None,
            metadata_={},
        ),
        FeedStats(
            source="malwarebazaar",
            source_id=None,
            total_indicators=250,
            active_indicators=240,
            inactive_indicators=10,
            last_update=datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            last_fetch_status="partial",
            last_fetch_error="API rate limit reached",
            metadata_={},
        ),
    ]

    for stat in stats:
        test_db.add(stat)
    test_db.commit()

    return stats


@pytest.fixture(scope="function")
def mock_misp():
    """Mock PyMISP client for testing."""
    with patch("app.services.misp.PyMISP") as mock:
        instance = MagicMock()
        mock.return_value = instance

        # Mock search method
        instance.search.return_value = []

        # Mock server settings
        instance.server_settings.return_value = {"version": "2.4.180"}

        yield instance


@pytest.fixture(scope="function")
def mock_requests():
    """Mock requests library for external API calls."""
    with patch("requests.get") as mock_get, \
         patch("requests.post") as mock_post:
        yield {"get": mock_get, "post": mock_post}


# Security testing helpers

def assert_security_headers(response):
    """Assert that response has all required security headers."""
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Content-Security-Policy" in response.headers
    assert "Strict-Transport-Security" in response.headers
    assert "Permissions-Policy" in response.headers


def assert_no_sql_injection(query_string: str) -> bool:
    """Check that query string doesn't contain SQL injection patterns."""
    dangerous = ["--", ";", "/*", "*/", "DROP", "DELETE", "INSERT", "UPDATE", "ALTER"]
    upper = query_string.upper()
    return not any(d in upper for d in dangerous)


# Parametrized test data for export formats

EXPORT_FORMATS = [
    "txt", "csv", "json", "xml",
    "fortigate", "fortigate_ips", "checkpoint", "paloalto",
    "sentinel", "defender", "f5", "imperva",
    "arcsight", "elasticsearch", "cribl", "splunk", "fidelis"
]


INDICATOR_TYPES = ["ip", "domain", "url", "hash", "email"]


TLP_LEVELS = ["WHITE", "GREEN", "AMBER", "RED"]
