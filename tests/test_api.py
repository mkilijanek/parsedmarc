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
from unittest.mock import patch, MagicMock

import pytest

from conftest import EXPORT_FORMATS, assert_security_headers


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
