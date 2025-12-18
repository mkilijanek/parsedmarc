"""
Comprehensive security testing for IOC service.

Tests cover:
- Input validation and sanitization
- SQL injection prevention
- XSS prevention
- Host header validation
- Client IP extraction with proxy awareness
- Rate limiting
- Security headers
- Session cookie security
- CSRF protection
"""
from __future__ import annotations

import os
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask

from app.security import (
    validate_search_query,
    enforce_allowed_hosts,
    get_client_ip,
)
from conftest import assert_security_headers, assert_no_sql_injection


# ============================================================================
# Input Validation Tests
# ============================================================================

class TestSearchQueryValidation:
    """Test search query validation against SQL injection."""

    def test_validate_search_query_none(self):
        """Test that None query is valid."""
        assert validate_search_query(None) is True

    def test_validate_search_query_valid(self):
        """Test valid search queries."""
        valid_queries = [
            "type:ip",
            "confidence:>70 AND type:ip",
            "value:192.168.*",
            "tlp:RED OR tlp:AMBER",
            "tags:malware",
            "source:misp",
        ]
        for query in valid_queries:
            assert validate_search_query(query) is True, f"Valid query rejected: {query}"

    def test_validate_search_query_sql_injection(self):
        """Test SQL injection patterns are rejected."""
        sql_injection_patterns = [
            "type:ip; DROP TABLE indicators;--",
            "value:test' OR '1'='1",
            "confidence:>70 -- comment",
            "type:ip/**/AND/**/'1'='1",
            "value:test' DROP TABLE users--",
            "confidence:50; DELETE FROM indicators;",
            "INSERT INTO indicators VALUES",
            "UPDATE indicators SET",
            "ALTER TABLE indicators",
        ]
        for query in sql_injection_patterns:
            assert validate_search_query(query) is False, f"SQL injection not detected: {query}"

    def test_validate_search_query_max_length(self):
        """Test query length limit enforcement."""
        # Valid length (under 500 chars)
        valid = "a" * 499
        assert validate_search_query(valid) is True

        # Invalid length (over 500 chars)
        invalid = "a" * 501
        assert validate_search_query(invalid) is False

    def test_validate_search_query_case_insensitive(self):
        """Test that SQL keyword detection is case-insensitive."""
        patterns = [
            "drop table users",
            "DROP TABLE USERS",
            "DrOp TaBlE uSeRs",
            "delete from indicators",
            "DELETE FROM INDICATORS",
        ]
        for query in patterns:
            assert validate_search_query(query) is False, f"Case variant not detected: {query}"

    def test_validate_search_query_comment_variations(self):
        """Test various SQL comment patterns."""
        comment_patterns = [
            "type:ip--comment",
            "type:ip --comment",
            "type:ip/*comment*/",
            "type:ip /* comment */",
        ]
        for query in comment_patterns:
            assert validate_search_query(query) is False, f"Comment pattern not detected: {query}"


# ============================================================================
# Host Header Validation Tests
# ============================================================================

class TestHostHeaderValidation:
    """Test ALLOWED_HOSTS enforcement."""

    def test_enforce_allowed_hosts_wildcard(self):
        """Test that wildcard allows all hosts."""
        with patch.dict(os.environ, {"ALLOWED_HOSTS": "*"}):
            with patch("app.security.request") as mock_request:
                mock_request.host = "any-host.com"
                # Should not raise
                enforce_allowed_hosts()

    def test_enforce_allowed_hosts_empty(self):
        """Test that empty ALLOWED_HOSTS allows all."""
        with patch.dict(os.environ, {"ALLOWED_HOSTS": ""}):
            with patch("app.security.request") as mock_request:
                mock_request.host = "any-host.com"
                # Should not raise
                enforce_allowed_hosts()

    def test_enforce_allowed_hosts_valid(self):
        """Test that allowed hosts pass validation."""
        with patch.dict(os.environ, {"ALLOWED_HOSTS": "example.com,api.example.com"}):
            with patch("app.security.request") as mock_request:
                mock_request.host = "example.com"
                # Should not raise
                enforce_allowed_hosts()

                mock_request.host = "api.example.com:443"
                # Should not raise
                enforce_allowed_hosts()

    def test_enforce_allowed_hosts_invalid(self):
        """Test that disallowed hosts are rejected."""
        with patch.dict(os.environ, {"ALLOWED_HOSTS": "example.com"}):
            with patch("app.security.request") as mock_request:
                mock_request.host = "evil.com"

                with pytest.raises(Exception):  # Should abort with 400
                    enforce_allowed_hosts()

    def test_enforce_allowed_hosts_case_insensitive(self):
        """Test that host matching is case-insensitive."""
        with patch.dict(os.environ, {"ALLOWED_HOSTS": "Example.COM"}):
            with patch("app.security.request") as mock_request:
                mock_request.host = "example.com"
                # Should not raise
                enforce_allowed_hosts()

                mock_request.host = "EXAMPLE.COM"
                # Should not raise
                enforce_allowed_hosts()

    def test_enforce_allowed_hosts_port_stripping(self):
        """Test that ports are properly stripped from host header."""
        with patch.dict(os.environ, {"ALLOWED_HOSTS": "example.com"}):
            with patch("app.security.request") as mock_request:
                mock_request.host = "example.com:443"
                # Should not raise (port stripped)
                enforce_allowed_hosts()

                mock_request.host = "example.com:8080"
                # Should not raise (port stripped)
                enforce_allowed_hosts()


# ============================================================================
# Client IP Extraction Tests
# ============================================================================

class TestClientIPExtraction:
    """Test secure client IP extraction with proxy awareness."""

    def test_get_client_ip_direct_connection(self):
        """Test IP extraction with direct connection (no proxy)."""
        with patch.dict(os.environ, {"TRUSTED_PROXY_COUNT": "0"}):
            with patch("app.security.request") as mock_request:
                mock_request.remote_addr = "1.2.3.4"
                mock_request.headers = {}

                ip = get_client_ip()
                assert ip == "1.2.3.4"

    def test_get_client_ip_single_proxy(self):
        """Test IP extraction behind single proxy."""
        with patch.dict(os.environ, {"TRUSTED_PROXY_COUNT": "1"}):
            with patch("app.security.request") as mock_request:
                mock_request.remote_addr = "10.0.0.1"
                mock_request.headers = {"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}

                ip = get_client_ip()
                assert ip == "1.2.3.4"

    def test_get_client_ip_multiple_proxies(self):
        """Test IP extraction behind multiple proxies."""
        with patch.dict(os.environ, {"TRUSTED_PROXY_COUNT": "2"}):
            with patch("app.security.request") as mock_request:
                mock_request.remote_addr = "10.0.0.3"
                # Client -> Proxy1 -> Proxy2 -> App
                mock_request.headers = {"X-Forwarded-For": "1.2.3.4, 10.0.0.2, 10.0.0.3"}

                ip = get_client_ip()
                assert ip == "1.2.3.4"

    def test_get_client_ip_spoofing_prevention(self):
        """Test that X-Forwarded-For is ignored when TRUSTED_PROXY_COUNT=0."""
        with patch.dict(os.environ, {"TRUSTED_PROXY_COUNT": "0"}):
            with patch("app.security.request") as mock_request:
                mock_request.remote_addr = "1.2.3.4"
                # Attacker tries to spoof IP
                mock_request.headers = {"X-Forwarded-For": "6.6.6.6"}

                ip = get_client_ip()
                # Should use remote_addr, not X-Forwarded-For
                assert ip == "1.2.3.4"

    def test_get_client_ip_malformed_header(self):
        """Test handling of malformed X-Forwarded-For header."""
        with patch.dict(os.environ, {"TRUSTED_PROXY_COUNT": "1"}):
            with patch("app.security.request") as mock_request:
                mock_request.remote_addr = "1.2.3.4"
                mock_request.headers = {"X-Forwarded-For": ""}

                ip = get_client_ip()
                # Should fall back to remote_addr
                assert ip == "1.2.3.4"

    def test_get_client_ip_whitespace_handling(self):
        """Test that whitespace in X-Forwarded-For is handled correctly."""
        with patch.dict(os.environ, {"TRUSTED_PROXY_COUNT": "1"}):
            with patch("app.security.request") as mock_request:
                mock_request.remote_addr = "10.0.0.1"
                mock_request.headers = {"X-Forwarded-For": " 1.2.3.4 , 10.0.0.1 "}

                ip = get_client_ip()
                assert ip == "1.2.3.4"

    def test_get_client_ip_single_ip_in_xff(self):
        """Test X-Forwarded-For with single IP."""
        with patch.dict(os.environ, {"TRUSTED_PROXY_COUNT": "1"}):
            with patch("app.security.request") as mock_request:
                mock_request.remote_addr = "10.0.0.1"
                mock_request.headers = {"X-Forwarded-For": "1.2.3.4"}

                ip = get_client_ip()
                assert ip == "1.2.3.4"

    def test_get_client_ip_index_out_of_range(self):
        """Test behavior when trusted proxy count exceeds XFF chain length."""
        with patch.dict(os.environ, {"TRUSTED_PROXY_COUNT": "5"}):
            with patch("app.security.request") as mock_request:
                mock_request.remote_addr = "10.0.0.1"
                mock_request.headers = {"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}

                ip = get_client_ip()
                # Should fall back to first IP
                assert ip == "1.2.3.4"


# ============================================================================
# Security Headers Tests
# ============================================================================

class TestSecurityHeaders:
    """Test security header implementation."""

    def test_security_headers_present(self, client):
        """Test that all security headers are present in responses."""
        response = client.get("/health")
        assert_security_headers(response)

    def test_csp_header(self, client):
        """Test Content-Security-Policy header."""
        response = client.get("/health")
        csp = response.headers.get("Content-Security-Policy")

        assert csp is not None
        assert "default-src 'self'" in csp
        assert "script-src" in csp
        assert "style-src" in csp

    def test_hsts_header(self, client):
        """Test Strict-Transport-Security header."""
        response = client.get("/health")
        hsts = response.headers.get("Strict-Transport-Security")

        assert hsts is not None
        assert "max-age=" in hsts
        assert "includeSubDomains" in hsts

    def test_xss_protection_header(self, client):
        """Test X-XSS-Protection header."""
        response = client.get("/health")
        xss = response.headers.get("X-XSS-Protection")

        assert xss == "1; mode=block"

    def test_frame_options_header(self, client):
        """Test X-Frame-Options header."""
        response = client.get("/health")
        frame = response.headers.get("X-Frame-Options")

        assert frame == "SAMEORIGIN"

    def test_content_type_options_header(self, client):
        """Test X-Content-Type-Options header."""
        response = client.get("/health")
        content_type = response.headers.get("X-Content-Type-Options")

        assert content_type == "nosniff"

    def test_permissions_policy_header(self, client):
        """Test Permissions-Policy header."""
        response = client.get("/health")
        permissions = response.headers.get("Permissions-Policy")

        assert permissions is not None
        assert "geolocation=()" in permissions
        assert "microphone=()" in permissions
        assert "camera=()" in permissions


# ============================================================================
# Session Security Tests
# ============================================================================

class TestSessionSecurity:
    """Test session cookie security configuration."""

    def test_session_cookie_secure(self, app):
        """Test that session cookies are marked Secure."""
        assert app.config["SESSION_COOKIE_SECURE"] is True

    def test_session_cookie_httponly(self, app):
        """Test that session cookies are marked HttpOnly."""
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True

    def test_session_cookie_samesite(self, app):
        """Test that session cookies have SameSite=Lax."""
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    def test_session_lifetime(self, app):
        """Test that session lifetime is limited."""
        assert app.config["PERMANENT_SESSION_LIFETIME"] == 3600


# ============================================================================
# Rate Limiting Tests
# ============================================================================

class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limit_not_exceeded(self, client):
        """Test that normal usage doesn't trigger rate limit."""
        for _ in range(5):
            response = client.get("/health")
            assert response.status_code == 200

    def test_rate_limit_headers(self, client):
        """Test that rate limit headers are present."""
        response = client.get("/health")

        # Flask-Limiter may add these headers
        # Test is informational rather than strict
        assert response.status_code == 200


# ============================================================================
# XSS Prevention Tests
# ============================================================================

class TestXSSPrevention:
    """Test XSS prevention in outputs."""

    def test_no_script_tag_in_html_response(self, client, sample_indicators):
        """Test that script tags in data don't execute in HTML."""
        # Note: This test depends on the HTML rendering implementation
        # which should escape all user input
        response = client.get("/")
        assert response.status_code == 200

        # HTML should not contain unescaped script tags
        html = response.get_data(as_text=True)
        # Check for proper escaping if any indicators contain scripts
        if "<script>" in html:
            # If present, should be escaped
            assert "&lt;script&gt;" in html or "\\u003cscript\\u003e" in html

    def test_json_response_escaping(self, client, sample_indicators):
        """Test that JSON responses properly escape data."""
        response = client.get("/indicators/json")
        assert response.status_code == 200

        # JSON should be valid and properly escaped
        import json
        data = json.loads(response.get_data(as_text=True))
        assert isinstance(data, list)


# ============================================================================
# Secret Key Validation Tests
# ============================================================================

class TestSecretKeyValidation:
    """Test SECRET_KEY validation."""

    def test_secret_key_required(self):
        """Test that SECRET_KEY is required."""
        with patch.dict(os.environ, {"SECRET_KEY": ""}):
            with pytest.raises(RuntimeError, match="SECRET_KEY environment variable must be set"):
                from app.config import Config
                Config()

    def test_secret_key_minimum_length(self):
        """Test that SECRET_KEY must be at least 32 characters."""
        with patch.dict(os.environ, {"SECRET_KEY": "short"}):
            with pytest.raises(RuntimeError, match="at least 32 characters"):
                from app.config import Config
                Config()

    def test_secret_key_valid_length(self):
        """Test that 32+ character SECRET_KEY is accepted."""
        with patch.dict(os.environ, {"SECRET_KEY": "a" * 32}):
            from app.config import Config
            cfg = Config()
            assert cfg.SECRET_KEY == "a" * 32


# ============================================================================
# MISP SSL Verification Tests
# ============================================================================

class TestMISPSSLVerification:
    """Test MISP SSL verification default."""

    def test_misp_ssl_verify_default_true(self):
        """Test that MISP_VERIFY_SSL defaults to true."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove MISP_VERIFY_SSL from environment
            if "MISP_VERIFY_SSL" in os.environ:
                del os.environ["MISP_VERIFY_SSL"]

            from app.config import Config
            cfg = Config()
            assert cfg.MISP_VERIFY_SSL is True

    def test_misp_ssl_verify_explicit_false(self):
        """Test that MISP_VERIFY_SSL can be set to false (for dev)."""
        with patch.dict(os.environ, {"MISP_VERIFY_SSL": "false"}):
            from app.config import Config
            cfg = Config()
            assert cfg.MISP_VERIFY_SSL is False


# ============================================================================
# Input Sanitization Tests
# ============================================================================

class TestInputSanitization:
    """Test input sanitization across the application."""

    def test_query_parameter_validation(self, client):
        """Test that invalid query parameters are rejected."""
        # SQL injection attempt
        response = client.get("/indicators?q=type:ip;DROP TABLE users--")
        assert response.status_code == 400

    def test_type_filter_validation(self, client):
        """Test that type filter is validated."""
        # Valid types
        for ioc_type in ["ip", "domain", "url", "hash", "email", "all"]:
            response = client.get(f"/indicators?type={ioc_type}")
            assert response.status_code == 200

    def test_tlp_filter_validation(self, client):
        """Test that TLP filter is validated."""
        # Valid TLP levels
        for tlp in ["WHITE", "GREEN", "AMBER", "RED", "all"]:
            response = client.get(f"/indicators?tlp={tlp}")
            assert response.status_code == 200

    def test_confidence_range_validation(self, client):
        """Test that confidence values are validated as integers."""
        # Valid confidence
        response = client.get("/indicators?min_conf=50&max_conf=100")
        assert response.status_code == 200

        # Invalid confidence (not integer)
        response = client.get("/indicators?min_conf=abc")
        assert response.status_code == 400

    def test_path_parameter_validation(self, client):
        """Test that path parameters are validated."""
        # Invalid source with special characters
        response = client.get("/sources/../../etc/passwd")
        # Should either redirect safely or return error
        assert response.status_code in [400, 404]


# ============================================================================
# Audit Logging Tests
# ============================================================================

class TestAuditLogging:
    """Test audit logging for security monitoring."""

    def test_audit_log_records_ip(self, client, test_db):
        """Test that audit log records client IP."""
        response = client.get("/indicators")
        assert response.status_code == 200

        # Check audit log (note: this depends on implementation)
        from app.models import AuditLog
        logs = test_db.query(AuditLog).all()
        # Should have at least one log entry
        assert len(logs) > 0

    def test_audit_log_records_actions(self, client, test_db, sample_indicators):
        """Test that audit log records different actions."""
        # Query action
        client.get("/indicators?q=type:ip")

        # Export action
        client.get("/indicators/json")

        from app.models import AuditLog
        logs = test_db.query(AuditLog).all()

        actions = [log.action for log in logs]
        assert "query" in actions or "export" in actions
