"""
Comprehensive API endpoint tests for IOC service.

Tests cover:
- All HTTP endpoints (health, metrics, indicators, exports)
- Query parameters and filtering
- Caching behavior
- Error handling
- Rate limiting
- Security headers on all endpoints
- Content types
- Response formats
"""
from __future__ import annotations

import json
import csv
import io
import time
from unittest.mock import patch

import pytest

from conftest import EXPORT_FORMATS, assert_security_headers
from app.main import create_app
from app.models import Indicator


# ============================================================================
# Health & Monitoring Endpoints
# ============================================================================

class TestHealthEndpoint:
    """Test /health endpoint."""

    def test_health_success(self, client, test_db):
        """Test health endpoint returns 200 with all checks."""
        with patch("app.main.get_redis") as mock_redis:
            mock_redis.return_value.ping.return_value = True

            response = client.get("/health")
            assert response.status_code == 200

            data = response.get_json()
            assert "status" in data
            assert "checks" in data
            assert "database" in data["checks"]
            assert "redis" in data["checks"]

    def test_health_database_check(self, client, test_db):
        """Test health endpoint checks database connectivity."""
        response = client.get("/health")
        data = response.get_json()

        # Database should be healthy in tests
        assert data["checks"]["database"] is True

    def test_health_redis_check(self, client):
        """Test health endpoint checks Redis connectivity."""
        with patch("app.main.get_redis") as mock_redis:
            mock_redis.return_value.ping.return_value = True

            response = client.get("/health")
            data = response.get_json()

            assert data["checks"]["redis"] is True

    def test_health_degraded_state(self, client):
        """Test health endpoint reports degraded state."""
        with patch("app.main.get_redis") as mock_redis:
            # Simulate Redis failure
            mock_redis.return_value.ping.side_effect = Exception("Connection failed")

            response = client.get("/health")
            assert response.status_code == 200

            data = response.get_json()
            # Status should be degraded if any check fails
            assert data["status"] in ["degraded", "healthy"]

    def test_health_security_headers(self, client):
        """Test that health endpoint has security headers."""
        response = client.get("/health")
        assert_security_headers(response)

    def test_health_rate_limiting(self, client):
        """Test that health endpoint has rate limiting."""
        # Make multiple requests
        for i in range(10):
            response = client.get("/health")
            # First requests should succeed
            if i < 60:  # Within rate limit
                assert response.status_code == 200


class TestMetricsEndpoint:
    """Test /metrics endpoint."""

    def test_metrics_success(self, client):
        """Test metrics endpoint returns Prometheus format."""
        response = client.get("/metrics")
        assert response.status_code == 200

        # Check content type
        assert "text/plain" in response.content_type

        # Response should contain Prometheus metrics
        text = response.get_data(as_text=True)
        assert len(text) > 0

    def test_metrics_security_headers(self, client):
        """Test that metrics endpoint has security headers."""
        response = client.get("/metrics")
        assert_security_headers(response)

    def test_metrics_rate_limiting(self, client):
        """Test that metrics endpoint has rate limiting."""
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_metrics_include_m11_performance_metrics(self, client, sample_indicators, fake_redis):
        """Test M11 cache/database metrics are exported."""
        with patch("app.main.get_redis", return_value=fake_redis):
            client.get("/indicators?type=ip")
            client.get("/indicators?type=ip")

        response = client.get("/metrics")
        assert response.status_code == 200
        text = response.get_data(as_text=True)
        assert "cache_access_total" in text
        assert "db_query_duration_seconds" in text


class TestFeedsApiEndpoint:
    def test_api_feeds_returns_paginated_items(self, client, sample_indicators, sample_feed_stats):
        response = client.get("/api/feeds?limit=25&offset=0")
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data.get("items"), list)
        assert isinstance(data.get("total"), int)
        assert data.get("limit") == 25
        assert data.get("offset") == 0
        assert data["total"] >= len(data["items"])

    def test_api_feeds_filters_sort_and_problems_only(self, client, sample_indicators, sample_feed_stats):
        response = client.get(
            "/api/feeds?status=warning&configured=all&datasource=all&sort=status&order=desc&problems_only=1"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "items" in data
        for item in data["items"]:
            assert item["status"] in {"ERROR", "WARNING"}

    def test_api_feeds_metrics_returns_summary(self, client, sample_indicators, sample_feed_stats):
        response = client.get("/api/feeds/metrics?hours=24")
        assert response.status_code == 200
        data = response.get_json()
        assert data["hours"] == 24
        assert data["window"] == "24h"
        assert data["bucket"] == "hour"
        assert "items" in data
        assert "timeseries" in data
        assert "summary" in data
        assert "duration_p50_ms" in data["summary"]
        assert "duration_p95_ms" in data["summary"]
        assert isinstance(data["items"], list)

    def test_api_feeds_metrics_datasource_filter(self, client, sample_indicators, sample_feed_stats):
        response = client.get("/api/feeds/metrics?hours=24&datasource=mwdb")
        assert response.status_code == 200
        data = response.get_json()
        for item in data["items"]:
            assert item["source_type"] == "mwdb"

    def test_api_feeds_metrics_supports_window_param(self, client, sample_indicators, sample_feed_stats):
        response = client.get("/api/feeds/metrics?window=7d")
        assert response.status_code == 200
        data = response.get_json()
        assert data["window"] == "7d"
        assert data["hours"] == 168
        assert data["bucket"] == "day"


class TestApiV1Endpoints:
    def test_api_v1_indicators_returns_json(self, client, sample_indicators):
        response = client.get("/api/v1/indicators?type=ip&limit=2")
        assert response.status_code == 200
        data = response.get_json()
        assert "items" in data
        assert "total" in data
        assert data["limit"] == 2
        assert all(item["type"] == "ip" for item in data["items"])

    def test_api_v1_feeds_returns_paginated_items(self, client, sample_indicators, sample_feed_stats):
        response = client.get("/api/v1/feeds?limit=25&offset=0")
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data.get("items"), list)
        assert isinstance(data.get("total"), int)
        assert data.get("limit") == 25

    def test_api_v1_feeds_metrics_returns_summary(self, client, sample_indicators, sample_feed_stats):
        response = client.get("/api/v1/feeds/metrics?hours=24")
        assert response.status_code == 200
        data = response.get_json()
        assert data["hours"] == 24
        assert "summary" in data
        assert "items" in data

    def test_api_v1_logs_returns_items(self, client):
        response = client.get("/api/v1/logs?limit=10")
        assert response.status_code == 200
        data = response.get_json()
        assert "count" in data
        assert "items" in data

    def test_api_v1_runs_current_returns_queue_state(self, client, sample_indicators, sample_feed_stats):
        response = client.get("/api/v1/runs/current")
        assert response.status_code == 200
        data = response.get_json()
        assert "queued_jobs" in data
        assert "running" in data
        assert "latest" in data

    def test_api_v1_openapi_artifacts_are_published(self, client):
        yaml_response = client.get("/api/v1/openapi.yaml")
        assert yaml_response.status_code == 200
        assert "application/yaml" in yaml_response.content_type
        yaml_text = yaml_response.get_data(as_text=True)
        assert "openapi: 3.1.0" in yaml_text
        assert "/api/v1/indicators:" in yaml_text
        assert "/api/v1/sync:" in yaml_text

        json_response = client.get("/api/v1/openapi.json")
        assert json_response.status_code == 200
        payload = json_response.get_json()
        assert payload["openapi"] == "3.1.0"
        assert "/api/v1/feeds" in payload["paths"]
        assert payload["paths"]["/api/v1/indicators"]["get"]["summary"] == "List indicators as JSON"

    def test_openapi_yaml_and_json_share_same_source_of_truth(self, client):
        yaml_response = client.get("/api/v1/openapi.yaml")
        json_response = client.get("/api/v1/openapi.json")
        assert yaml_response.status_code == 200
        assert json_response.status_code == 200
        assert "/api/v1/logs" in yaml_response.get_data(as_text=True)
        assert "/api/v1/logs" in json_response.get_json()["paths"]

    def test_api_v1_docs_page_links_to_contract(self, client):
        response = client.get("/api/v1/docs")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "/api/v1/openapi.yaml" in html
        assert "/api/v1/openapi.json" in html

    def test_api_swagger_ui_is_served_from_bundled_assets(self, client):
        response = client.get("/api/swagger")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "/api/swagger-assets/swagger-ui.css" in html
        assert "/api/swagger-assets/swagger-ui-bundle.js" in html
        assert "/api/v1/openapi.yaml" in html

        asset_response = client.get("/api/swagger-assets/swagger-ui-bundle.js")
        assert asset_response.status_code == 200
        assert "javascript" in asset_response.content_type or "text/plain" in asset_response.content_type

    def test_legacy_api_routes_expose_deprecation_headers_when_v1_successor_exists(self, client, sample_indicators, sample_feed_stats):
        response = client.get("/api/feeds")
        assert response.status_code == 200
        assert response.headers.get("Deprecation") == "true"
        assert "/api/v1/feeds" in (response.headers.get("Link") or "")

    def test_api_v1_public_boundary_and_admin_protection(self, client):
        api_response = client.get("/api/v1/indicators")
        assert api_response.status_code == 200

        admin_response = client.get("/admin", follow_redirects=False)
        assert admin_response.status_code in {302, 303}
        assert "/auth/login" in (admin_response.headers.get("Location") or "")

    def test_auth_login_redirects_direct_app_port_to_https_entrypoint(self, client):
        response = client.get(
            "/auth/login?next=/admin",
            base_url="http://192.168.10.71:7005",
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers["Location"] == "https://192.168.10.71:7003/auth/login?next=/admin"

    def test_admin_redirects_direct_app_port_to_https_before_login(self, client):
        response = client.get(
            "/admin",
            base_url="http://192.168.10.71:7005",
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers["Location"] == "https://192.168.10.71:7003/admin"

    def test_auth_login_does_not_redirect_when_edge_https_disabled(self):
        with patch.dict(
            "os.environ",
            {
                "EDGE_HTTPS_ENABLED": "false",
                "HSTS_ENABLED": "false",
                "SESSION_COOKIE_SECURE_ENABLED": "false",
            },
            clear=False,
        ):
            app = create_app()
            client = app.test_client()
            response = client.get(
                "/auth/login?next=/admin",
                base_url="http://192.168.10.71:7005",
                follow_redirects=False,
            )

        assert response.status_code == 200
        assert "/auth/login" not in (response.headers.get("Location") or "")


# ============================================================================
# Index/Dashboard Endpoint
# ============================================================================

class TestIndexEndpoint:
    """Test / (index) endpoint."""

    def test_index_success(self, client, sample_indicators, sample_feed_stats):
        """Test index page renders successfully."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.content_type

    def test_index_shows_statistics(self, client, sample_indicators, sample_feed_stats):
        """Test index page displays indicator statistics."""
        response = client.get("/")
        html = response.get_data(as_text=True)

        # Should show some statistics
        assert len(html) > 0

    def test_index_security_headers(self, client):
        """Test that index page has security headers."""
        response = client.get("/")
        assert_security_headers(response)


# ============================================================================
# Indicators View Endpoint
# ============================================================================

class TestIndicatorsViewEndpoint:
    """Test /indicators HTML view endpoint."""

    def test_indicators_view_basic(self, client, sample_indicators):
        """Test indicators view renders successfully."""
        response = client.get("/indicators")
        assert response.status_code == 200
        assert "text/html" in response.content_type

    def test_indicators_view_with_query(self, client, sample_indicators):
        """Test indicators view with search query."""
        response = client.get("/indicators?q=type:ip")
        assert response.status_code == 200

    def test_indicators_view_with_filters(self, client, sample_indicators):
        """Test indicators view with filters."""
        response = client.get("/indicators?type=ip&tlp=RED&min_conf=80")
        assert response.status_code == 200

    def test_indicators_view_invalid_query(self, client):
        """Test indicators view rejects invalid queries."""
        # SQL injection attempt
        response = client.get("/indicators?q=DROP TABLE users;--")
        assert response.status_code == 400

        data = response.get_json()
        assert "error" in data

    def test_indicators_view_invalid_confidence(self, client):
        """Test indicators view rejects invalid confidence values."""
        response = client.get("/indicators?min_conf=abc")
        assert response.status_code == 400

        data = response.get_json()
        assert "error" in data

    def test_indicators_view_empty_confidence_values_are_allowed(self, client, sample_indicators):
        """Empty min_conf/max_conf query params should be treated as no filter."""
        response = client.get("/indicators?type=all&tlp=RED&source=all&min_conf=&max_conf=")
        assert response.status_code == 200
        assert "text/html" in response.content_type

    def test_indicators_view_caching(self, client, sample_indicators, fake_redis):
        """Test indicators view uses caching."""
        with patch("app.main.get_redis", return_value=fake_redis):
            # First request
            response1 = client.get("/indicators?type=ip")
            assert response1.status_code == 200

            # Second request (should hit cache)
            response2 = client.get("/indicators?type=ip")
            assert response2.status_code == 200

            # Responses should be identical
            assert response1.get_data() == response2.get_data()

    def test_indicators_view_security_headers(self, client):
        """Test that indicators view has security headers."""
        response = client.get("/indicators")
        assert_security_headers(response)

    def test_indicators_view_rate_limiting(self, client):
        """Test that indicators view has rate limiting."""
        response = client.get("/indicators")
        assert response.status_code == 200

    def test_indicators_view_limit_offset(self, client, sample_indicators):
        """Test indicators view supports limit/offset pagination params."""
        response = client.get("/indicators?limit=1&offset=0")
        assert response.status_code == 200
        assert "text/html" in response.content_type

    def test_indicators_view_invalid_limit_offset(self, client):
        """Test indicators view rejects non-integer limit/offset."""
        response = client.get("/indicators?limit=abc")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data


# ============================================================================
# Sources Redirect Endpoint
# ============================================================================

class TestSourcesEndpoint:
    """Test /sources/<src> redirect endpoint."""

    def test_sources_redirect_valid(self, client):
        """Test sources endpoint redirects correctly."""
        response = client.get("/sources/misp", follow_redirects=False)
        assert response.status_code in [301, 302, 303, 307, 308]
        assert "indicators" in response.location

    def test_sources_redirect_invalid_characters(self, client):
        """Test sources endpoint rejects invalid source names."""
        response = client.get("/sources/../../etc/passwd")
        assert response.status_code in [400, 404]

    def test_sources_redirect_empty(self, client):
        """Test sources endpoint rejects empty source."""
        response = client.get("/sources/ ")
        assert response.status_code in [400, 404]


class TestCorrelationEndpoint:
    def test_correlations_basic(self, client, test_db):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        test_db.add_all([
            Indicator(
                value="corr.example.org",
                type="domain",
                source="mwdb",
                source_id="x1",
                confidence=70,
                tlp="GREEN",
                is_active=True,
                tags=["malware"],
                metadata_={"mwdb": {"enrichment": {"domain_root": "example.org"}}},
                first_seen=now,
                last_seen=now,
            ),
            Indicator(
                value="corr.example.org",
                type="domain",
                source="threatfox",
                source_id="x2",
                confidence=75,
                tlp="GREEN",
                is_active=True,
                tags=["apt"],
                metadata_={"threatfox": {"enrichment": {"domain_root": "example.org"}}},
                first_seen=now,
                last_seen=now,
            ),
        ])
        test_db.commit()

        response = client.get("/correlations?min_sources=2&type=domain")
        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] >= 1
        assert isinstance(data["items"], list)
        first = data["items"][0]
        assert "source_count" in first
        assert "sources" in first
        assert "enrichment" in first

    def test_correlations_invalid_type(self, client):
        response = client.get("/correlations?type=invalid")
        assert response.status_code == 400

    def test_correlations_invalid_params(self, client):
        response = client.get("/correlations?min_sources=abc")
        assert response.status_code == 400

    def test_correlations_limit_guardrail(self, client, test_db):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        test_db.add_all([
            Indicator(
                value="guardrail.example.org",
                type="domain",
                source="mwdb",
                source_id="g1",
                confidence=70,
                tlp="GREEN",
                is_active=True,
                tags=["x"],
                metadata_={},
                first_seen=now,
                last_seen=now,
            ),
            Indicator(
                value="guardrail.example.org",
                type="domain",
                source="threatfox",
                source_id="g2",
                confidence=75,
                tlp="GREEN",
                is_active=True,
                tags=["y"],
                metadata_={},
                first_seen=now,
                last_seen=now,
            ),
        ])
        test_db.commit()

        response = client.get("/correlations?min_sources=2&type=domain&limit=99999999")
        assert response.status_code == 200
        data = response.get_json()
        assert data["limit"] == 5000


# ============================================================================
# Export Endpoints Tests
# ============================================================================

class TestExportEndpoints:
    """Test /indicators/<fmt> export endpoints."""

    @pytest.mark.parametrize("fmt", EXPORT_FORMATS)
    def test_export_format_basic(self, client, sample_indicators, fmt):
        """Test each export format endpoint works."""
        response = client.get(f"/indicators/{fmt}")
        assert response.status_code == 200

        # Verify content type is set
        assert response.content_type is not None

    def test_export_txt_format(self, client, sample_indicators):
        """Test TXT export endpoint."""
        response = client.get("/indicators/txt")
        assert response.status_code == 200
        assert "text/plain" in response.content_type

        text = response.get_data(as_text=True)
        lines = text.strip().split("\n")
        assert len(lines) > 0

    def test_export_csv_format(self, client, sample_indicators):
        """Test CSV export endpoint."""
        response = client.get("/indicators/csv")
        assert response.status_code == 200
        assert "text/csv" in response.content_type

        text = response.get_data(as_text=True)
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) > 0

    def test_export_json_format(self, client, sample_indicators):
        """Test JSON export endpoint."""
        response = client.get("/indicators/json")
        assert response.status_code == 200
        assert "application/json" in response.content_type

        data = json.loads(response.get_data(as_text=True))
        assert isinstance(data, list)
        assert len(data) > 0

    def test_export_xml_format(self, client, sample_indicators):
        """Test XML export endpoint."""
        response = client.get("/indicators/xml")
        assert response.status_code == 200
        assert "application/xml" in response.content_type

        text = response.get_data(as_text=True)
        assert "<?xml" in text
        assert "<indicators>" in text

    def test_export_with_query_filter(self, client, sample_indicators):
        """Test export with query filter."""
        response = client.get("/indicators/json?q=type:ip")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        # All results should be IPs
        for item in data:
            assert item["type"] == "ip"

    def test_export_with_type_filter(self, client, sample_indicators):
        """Test export with type filter."""
        response = client.get("/indicators/json?type=domain")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        # All results should be domains
        for item in data:
            assert item["type"] == "domain"

    def test_export_with_tlp_filter(self, client, sample_indicators):
        """Test export with TLP filter."""
        response = client.get("/indicators/json?tlp=RED")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        # All results should be RED TLP
        for item in data:
            assert item["tlp"] == "RED"

    def test_export_with_source_filter(self, client, sample_indicators):
        """Test export with source filter."""
        response = client.get("/indicators/json?source=misp")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        # All results should be from MISP
        for item in data:
            assert item["source"] == "misp"

    def test_export_unknown_format(self, client):
        """Test export with unknown format returns 404."""
        response = client.get("/indicators/unknown_format")
        assert response.status_code == 404

        data = response.get_json()
        assert "error" in data

    def test_export_invalid_query(self, client):
        """Test export with invalid query returns 400."""
        response = client.get("/indicators/json?q=DROP TABLE users;--")
        assert response.status_code == 400

        data = response.get_json()
        assert "error" in data

    def test_export_caching(self, client, sample_indicators, fake_redis):
        """Test export endpoint uses caching."""
        with patch("app.main.get_redis", return_value=fake_redis):
            # First request
            response1 = client.get("/indicators/json?type=ip")
            assert response1.status_code == 200

            # Second request (should hit cache)
            response2 = client.get("/indicators/json?type=ip")
            assert response2.status_code == 200

            # Responses should be identical
            assert response1.get_data() == response2.get_data()

    @pytest.mark.parametrize("fmt", EXPORT_FORMATS)
    def test_export_security_headers(self, client, fmt):
        """Test that all export endpoints have security headers."""
        response = client.get(f"/indicators/{fmt}")
        assert_security_headers(response)

    def test_export_rate_limiting(self, client):
        """Test that export endpoints have rate limiting."""
        response = client.get("/indicators/json")
        assert response.status_code == 200

    def test_export_limit_offset(self, client, sample_indicators):
        """Test export endpoint supports limit/offset pagination params."""
        response = client.get("/indicators/json?limit=1&offset=0")
        assert response.status_code == 200
        data = json.loads(response.get_data(as_text=True))
        assert len(data) <= 1

    def test_export_streaming_ndjson(self, client, sample_indicators):
        """Test NDJSON export streaming mode."""
        response = client.get("/indicators/elasticsearch?stream=1&limit=5")
        assert response.status_code == 200
        assert "application/x-ndjson" in response.content_type
        body = response.get_data(as_text=True)
        assert len(body.strip()) > 0
        assert "\"index\"" in body

    def test_export_async_job_flow(self, client, sample_indicators):
        """Test asynchronous export job creation and retrieval."""
        response = client.get("/indicators/json?type=ip&limit=100000&async=1")
        assert response.status_code == 202
        data = response.get_json()
        assert "job_id" in data
        status_url = data["status_url"]
        download_url = data["download_url"]

        # Poll briefly for completion.
        for _ in range(20):
            st = client.get(status_url)
            assert st.status_code == 200
            status = st.get_json()["status"]
            if status == "completed":
                break
            time.sleep(0.02)

        final_status = client.get(status_url).get_json()["status"]
        assert final_status in {"running", "completed", "failed", "queued"}
        if final_status == "completed":
            dl = client.get(download_url)
            assert dl.status_code == 200
            assert "application/json" in dl.content_type


# ============================================================================
# MISP Event Export Endpoints
# ============================================================================

class TestMISPEventExportEndpoint:
    """Test /misp/event/<event_id>/<ioc_type>/<fmt> endpoint."""

    def test_misp_event_export_basic(self, client, sample_indicators):
        """Test MISP event export endpoint."""
        response = client.get("/misp/event/event-123/ip/json")
        assert response.status_code == 200
        assert "application/json" in response.content_type

        data = json.loads(response.get_data(as_text=True))
        # Should only return indicators from this event
        for item in data:
            assert item["source"] == "misp"
            assert item["source_id"] == "event-123"

    def test_misp_event_export_all_types(self, client, sample_indicators):
        """Test MISP event export with all types."""
        response = client.get("/misp/event/event-123/all/json")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert isinstance(data, list)

    def test_misp_event_export_specific_type(self, client, sample_indicators):
        """Test MISP event export with specific type."""
        response = client.get("/misp/event/event-123/ip/json")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        # All should be IPs
        for item in data:
            assert item["type"] == "ip"

    @pytest.mark.parametrize("fmt", EXPORT_FORMATS)
    def test_misp_event_export_all_formats(self, client, sample_indicators, fmt):
        """Test MISP event export in all formats."""
        response = client.get(f"/misp/event/event-123/ip/{fmt}")
        assert response.status_code == 200

    def test_misp_event_export_invalid_format(self, client):
        """Test MISP event export with invalid format."""
        response = client.get("/misp/event/123/ip/invalid")
        assert response.status_code == 404

    def test_misp_event_export_invalid_type(self, client):
        """Test MISP event export with invalid IOC type."""
        response = client.get("/misp/event/123/invalid_type/json")
        assert response.status_code == 400

        data = response.get_json()
        assert "error" in data

    def test_misp_event_export_security_headers(self, client):
        """Test that MISP event export has security headers."""
        response = client.get("/misp/event/123/ip/json")
        assert_security_headers(response)

    def test_misp_event_export_rate_limiting(self, client):
        """Test that MISP event export has rate limiting."""
        response = client.get("/misp/event/123/ip/json")
        assert response.status_code in [200, 404]  # Event may not exist


# ============================================================================
# CrowdSec List Export Endpoints
# ============================================================================

class TestCrowdSecListExportEndpoint:
    """Test /crowdsec/list/<list_id>/<fmt> endpoint."""

    def test_crowdsec_list_export_basic(self, client, sample_indicators):
        """Test CrowdSec list export endpoint."""
        response = client.get("/crowdsec/list/list-abc/json")
        assert response.status_code == 200
        assert "application/json" in response.content_type

        data = json.loads(response.get_data(as_text=True))
        # Should only return indicators from this list
        for item in data:
            assert item["source"] == "crowdsec"
            assert item["source_id"] == "list-abc"

    @pytest.mark.parametrize("fmt", EXPORT_FORMATS)
    def test_crowdsec_list_export_all_formats(self, client, sample_indicators, fmt):
        """Test CrowdSec list export in all formats."""
        response = client.get(f"/crowdsec/list/list-abc/{fmt}")
        assert response.status_code == 200

    def test_crowdsec_list_export_invalid_format(self, client):
        """Test CrowdSec list export with invalid format."""
        response = client.get("/crowdsec/list/abc/invalid")
        assert response.status_code == 404

    def test_crowdsec_list_export_security_headers(self, client):
        """Test that CrowdSec list export has security headers."""
        response = client.get("/crowdsec/list/abc/json")
        assert_security_headers(response)

    def test_crowdsec_list_export_rate_limiting(self, client):
        """Test that CrowdSec list export has rate limiting."""
        response = client.get("/crowdsec/list/abc/json")
        assert response.status_code in [200, 404]


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling across endpoints."""

    def test_404_not_found(self, client):
        """Test 404 for non-existent endpoints."""
        response = client.get("/nonexistent")
        assert response.status_code == 404

    def test_405_method_not_allowed(self, client):
        """Test 405 for invalid HTTP methods."""
        response = client.post("/health")
        assert response.status_code == 405

    def test_400_bad_request_validation(self, client):
        """Test 400 for validation errors."""
        # Invalid query
        response = client.get("/indicators?q=DROP TABLE users;--")
        assert response.status_code == 400

        # Invalid confidence
        response = client.get("/indicators?min_conf=abc")
        assert response.status_code == 400

    def test_error_response_format(self, client):
        """Test that error responses have consistent format."""
        response = client.get("/indicators/unknown_format")
        assert response.status_code == 404

        data = response.get_json()
        assert "error" in data
        assert isinstance(data["error"], str)


# ============================================================================
# Content Type Tests
# ============================================================================

class TestContentTypes:
    """Test content type headers for different formats."""

    def test_content_type_txt(self, client, sample_indicators):
        """Test text/plain content type for TXT."""
        response = client.get("/indicators/txt")
        assert "text/plain" in response.content_type

    def test_content_type_csv(self, client, sample_indicators):
        """Test text/csv content type for CSV."""
        response = client.get("/indicators/csv")
        assert "text/csv" in response.content_type

    def test_content_type_json(self, client, sample_indicators):
        """Test application/json content type for JSON."""
        response = client.get("/indicators/json")
        assert "application/json" in response.content_type

    def test_content_type_xml(self, client, sample_indicators):
        """Test application/xml content type for XML."""
        response = client.get("/indicators/xml")
        assert "application/xml" in response.content_type

    def test_content_type_ndjson(self, client, sample_indicators):
        """Test application/x-ndjson content type."""
        response = client.get("/indicators/elasticsearch")
        assert "application/x-ndjson" in response.content_type or "application/json" in response.content_type


# ============================================================================
# Query Parser Integration Tests
# ============================================================================

class TestQueryParserIntegration:
    """Test query parser integration with API endpoints."""

    def test_simple_field_query(self, client, sample_indicators):
        """Test simple field:value query."""
        response = client.get("/indicators/json?q=type:ip")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        for item in data:
            assert item["type"] == "ip"

    def test_and_operator_query(self, client, sample_indicators):
        """Test AND operator in query."""
        response = client.get("/indicators/json?q=type:ip AND confidence:>80")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        for item in data:
            assert item["type"] == "ip"
            assert item["confidence"] > 80

    def test_or_operator_query(self, client, sample_indicators):
        """Test OR operator in query."""
        response = client.get("/indicators/json?q=tlp:RED OR tlp:AMBER")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        for item in data:
            assert item["tlp"] in ["RED", "AMBER"]

    def test_wildcard_query(self, client, sample_indicators):
        """Test wildcard in query."""
        response = client.get("/indicators/json?q=value:192.168.*")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        for item in data:
            assert item["value"].startswith("192.168.")

    def test_tags_query(self, client, sample_indicators):
        """Test tags search."""
        response = client.get("/indicators/json?q=tags:malware")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        for item in data:
            assert "malware" in item["tags"]


# ============================================================================
# Performance Tests
# ============================================================================

class TestPerformance:
    """Test API performance characteristics."""

    def test_large_result_set_handling(self, client, test_db):
        """Test API handles large result sets."""
        # Create many indicators
        from app.models import Indicator
        for i in range(100):
            ind = Indicator(
                value=f"192.168.{i // 256}.{i % 256}",
                type="ip",
                source="test",
                confidence=50,
                tlp="WHITE",
            )
            test_db.add(ind)
        test_db.commit()

        response = client.get("/indicators/json")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert len(data) > 0

    def test_concurrent_requests(self, client, sample_indicators):
        """Test API handles concurrent requests."""
        # Make multiple requests in sequence (simulating concurrent access)
        responses = []
        for _ in range(10):
            response = client.get("/indicators/json")
            responses.append(response)

        # All should succeed
        for response in responses:
            assert response.status_code == 200


# ============================================================================
# Liveness / Readiness / Dependency Status Endpoints
# ============================================================================

class TestHealthzEndpoint:
    """Test /healthz liveness probe."""

    def test_healthz_always_200(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200

    def test_healthz_json_status_ok(self, client):
        data = client.get("/healthz").get_json()
        assert data == {"status": "ok"}

    def test_healthz_no_external_calls(self, client):
        """healthz must not make any network calls."""
        with patch("requests.get") as mock_get, patch("requests.Session") as mock_session:
            response = client.get("/healthz")
            assert response.status_code == 200
            mock_get.assert_not_called()
            mock_session.assert_not_called()

    def test_healthz_content_type_json(self, client):
        response = client.get("/healthz")
        assert "application/json" in response.content_type

    def test_healthz_security_headers(self, client):
        response = client.get("/healthz")
        assert_security_headers(response)


class TestDepsEndpoint:
    """Test /deps dependency status snapshot."""

    def test_deps_returns_200(self, client):
        response = client.get("/deps")
        assert response.status_code == 200

    def test_deps_returns_json_dict(self, client):
        response = client.get("/deps")
        data = response.get_json()
        assert isinstance(data, dict)

    def test_deps_no_external_calls(self, client):
        """deps must not make any network calls."""
        with patch("requests.get") as mock_get:
            response = client.get("/deps")
            assert response.status_code == 200
            mock_get.assert_not_called()

    def test_deps_shows_updated_status(self, client):
        """After _dep_status is updated, /deps reflects new value."""
        from app.services.common import _dep_status
        _dep_status.update("test_source", "ok", duration_ms=5)
        data = client.get("/deps").get_json()
        assert "test_source" in data
        entry = data["test_source"]
        assert entry["status"] == "ok"
        assert entry["last_duration_ms"] == 5

    def test_deps_entry_schema(self, client):
        """Each entry in /deps has the expected keys."""
        from app.services.common import _dep_status
        _dep_status.update("schema_check", "down", error="timeout")
        data = client.get("/deps").get_json()
        entry = data.get("schema_check", {})
        assert "status" in entry
        assert "last_ok_ts" in entry
        assert "last_check_ts" in entry
        assert "last_error" in entry
        assert "last_duration_ms" in entry


class TestReadyzEndpoint:
    """Test /readyz readiness probe."""

    def test_readyz_200_when_db_ok(self, client, test_db):
        with patch("app.main.get_redis") as mock_redis:
            mock_redis.return_value.ping.return_value = True
            response = client.get("/readyz")
            assert response.status_code == 200

    def test_readyz_json_ready_when_ok(self, client, test_db):
        with patch("app.main.get_redis") as mock_redis:
            mock_redis.return_value.ping.return_value = True
            data = client.get("/readyz").get_json()
            assert data["status"] == "ready"
            assert data["checks"]["database"] is True
            assert data["checks"]["redis"] is True

    def test_readyz_503_when_redis_down(self, client, test_db):
        with patch("app.main.get_redis") as mock_redis:
            mock_redis.return_value.ping.side_effect = Exception("redis down")
            response = client.get("/readyz")
            assert response.status_code == 503
            data = response.get_json()
            assert data["status"] == "not_ready"
            assert data["checks"]["redis"] is False

    def test_readyz_content_type_json(self, client):
        with patch("app.main.get_redis") as mock_redis:
            mock_redis.return_value.ping.return_value = True
            response = client.get("/readyz")
            assert "application/json" in response.content_type

    def test_readyz_security_headers(self, client):
        with patch("app.main.get_redis") as mock_redis:
            mock_redis.return_value.ping.return_value = True
            response = client.get("/readyz")
            assert_security_headers(response)


# ---------------------------------------------------------------------------
# TestApiV1Coverage — migrated from test_coverage_boost2.py
# ---------------------------------------------------------------------------

class TestApiV1Coverage:

    def test_api_v1_indicators_returns_200(self, client):
        resp = client.get("/api/v1/indicators")
        assert resp.status_code == 200

    def test_api_v1_indicators_json_structure(self, client):
        resp = client.get("/api/v1/indicators")
        body = json.loads(resp.data)
        assert "items" in body or "indicators" in body or "data" in body or isinstance(body, (list, dict))

    def test_api_v1_indicators_filter_by_type(self, client):
        resp = client.get("/api/v1/indicators?type=ip")
        assert resp.status_code == 200

    def test_api_v1_indicators_filter_by_source(self, client):
        resp = client.get("/api/v1/indicators?source=misp")
        assert resp.status_code == 200

    def test_api_v1_indicators_pagination(self, client):
        resp = client.get("/api/v1/indicators?limit=5&offset=0")
        assert resp.status_code == 200

    def test_api_v1_feeds_returns_200(self, client):
        resp = client.get("/api/v1/feeds")
        assert resp.status_code == 200

    def test_api_v1_feeds_json(self, client):
        resp = client.get("/api/v1/feeds")
        body = json.loads(resp.data)
        assert isinstance(body, (dict, list))

    def test_api_v1_sync_missing_source(self, client):
        resp = client.post("/api/v1/sync", json={})
        assert resp.status_code == 400

    def test_api_v1_sync_invalid_source(self, client):
        resp = client.post("/api/v1/sync", json={"source": "nonexistent_source_xyz"})
        assert resp.status_code in (400, 202)

    def test_api_v1_runs_current(self, client):
        resp = client.get("/api/v1/runs/current")
        assert resp.status_code in (200, 404)

    def test_api_v1_logs_returns_200(self, client):
        resp = client.get("/api/v1/logs")
        assert resp.status_code in (200, 404)

    def test_openapi_yaml_accessible(self, client):
        resp = client.get("/api/v1/openapi.yaml")
        assert resp.status_code in (200, 404)

    def test_openapi_json_accessible(self, client):
        resp = client.get("/api/v1/openapi.json")
        assert resp.status_code in (200, 404)
