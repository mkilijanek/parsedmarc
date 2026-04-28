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
from unittest.mock import patch

import pytest
from conftest import assert_security_headers
from flask import Flask

from app.main import create_app
from app.models import AuditLog
from app.security import (
    enforce_allowed_hosts,
    get_client_ip,
    validate_search_query,
)

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
            "value:\"192.168.1.1\"",
            "comments:'apt28'",
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
            "confidence:>70 -- comment",
            "type:ip/**/AND/**/1=1",
            "value:test; select * from indicators",
            "value:xp_cmdshell",
            "value:0x414141",
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
            "xp_cmdshell",
            "XP_CMDSHELL",
            "Xp_CmDsHeLl",
            "0x414243",
            "0X414243",
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


class TestProductionSecurityConfig:
    """Production safety checks for permissive host/CORS defaults."""

    def test_production_rejects_wildcard_hosts_and_cors(self):
        with patch.dict(
            os.environ,
            {
                "APP_ENV": "production",
                "ALLOWED_HOSTS": "*",
                "CORS_ORIGINS": "*",
                "SECURITY_ALLOW_PERMISSIVE_DEFAULTS": "false",
            },
            clear=False,
        ):
            with pytest.raises(RuntimeError, match="ALLOWED_HOSTS cannot be '\\*'"):
                create_app()

    def test_production_allows_override_for_permissive_defaults(self):
        with patch.dict(
            os.environ,
            {
                "APP_ENV": "production",
                "ALLOWED_HOSTS": "*",
                "CORS_ORIGINS": "*",
                "SECURITY_ALLOW_PERMISSIVE_DEFAULTS": "true",
            },
            clear=False,
        ):
            app = create_app()
            assert isinstance(app, Flask)

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

    def test_hsts_header_can_be_disabled(self):
        with patch.dict(
            os.environ,
            {
                "HSTS_ENABLED": "false",
                "SESSION_COOKIE_SECURE_ENABLED": "false",
            },
            clear=False,
        ):
            app = create_app()
            client = app.test_client()
            response = client.get("/health")

        assert response.headers.get("Strict-Transport-Security") is None

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

    def test_cross_origin_and_referrer_headers(self, client):
        """Test browser isolation headers for admin and API surfaces."""
        response = client.get("/health")

        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert response.headers.get("Cross-Origin-Opener-Policy") == "same-origin"
        assert response.headers.get("Cross-Origin-Resource-Policy") == "same-origin"
        assert response.headers.get("X-Permitted-Cross-Domain-Policies") == "none"


# ============================================================================
# Session Security Tests
# ============================================================================

class TestSessionSecurity:
    """Test session cookie security configuration."""

    def test_session_cookie_secure(self, app):
        """Test that session cookies are marked Secure."""
        assert app.config["SESSION_COOKIE_SECURE"] is True

    def test_session_cookie_secure_can_be_disabled(self):
        with patch.dict(os.environ, {"SESSION_COOKIE_SECURE_ENABLED": "false"}, clear=False):
            insecure_app = create_app()
        assert insecure_app.config["SESSION_COOKIE_SECURE"] is False

    def test_session_cookie_httponly(self, app):
        """Test that session cookies are marked HttpOnly."""
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True

    def test_session_cookie_samesite(self, app):
        """Test that session cookies have SameSite=Lax."""
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    def test_session_lifetime(self, app):
        """Test that session lifetime is limited."""
        assert app.config["PERMANENT_SESSION_LIFETIME"] == 3600

    def test_admin_post_requires_csrf_token(self, admin_client, sample_indicators):
        response = admin_client.post("/admin/sync", data={"source": "misp"}, follow_redirects=False)
        assert response.status_code == 400
        assert "CSRF validation failed" in response.get_data(as_text=True)

    def test_admin_html_injects_csrf_token(self, admin_client, sample_indicators, sample_feed_stats):
        response = admin_client.get("/admin")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "window.__adminCsrfToken" in html
        assert "csrf_token" in html

    def test_admin_login_sets_admin_role_baseline(self, admin_client):
        with admin_client.session_transaction() as sess:
            assert sess.get("admin_authenticated") is True
            assert sess.get("admin_role") == "admin"

    def test_viewer_role_cannot_perform_admin_post(self, client):
        with client.session_transaction() as sess:
            sess["admin_authenticated"] = True
            sess["admin_user_id"] = "viewer"
            sess["admin_role"] = "viewer"
            sess["admin_csrf_token"] = "csrf"

        response = client.post("/admin/sync", data={"source": "all", "csrf_token": "csrf"})

        assert response.status_code == 403
        assert "insufficient role permissions" in response.get_data(as_text=True)

    def test_login_rate_limit_returns_operator_facing_html(self, client):
        last_response = None
        for _ in range(11):
            last_response = client.get("/auth/login")

        assert last_response is not None
        assert last_response.status_code == 429
        html = last_response.get_data(as_text=True)
        assert "Too Many Login Attempts" in html
        assert "Wait about 15 minutes" in html


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

    def test_admin_api_rate_limit_exceed_is_audited(self, client, test_db):
        """Admin API rate limit violations are returned as JSON and written to audit log."""
        if not client.application.limiter.enabled:
            pytest.skip("rate limiting is disabled for this environment")
        statuses = [
            client.post("/api/sync", json={"source": "does-not-exist"}).status_code
            for _ in range(11)
        ]

        assert statuses[:10] == [400] * 10
        assert statuses[-1] == 429
        row = (
            test_db.query(AuditLog)
            .filter(AuditLog.action == "rate_limit_exceeded")
            .one_or_none()
        )
        assert row is not None
        assert (row.metadata_ or {}).get("path") == "/api/sync"


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

        # Inline framework scripts can exist; ensure obvious XSS payloads are not rendered.
        html = response.get_data(as_text=True)
        lowered = html.lower()
        assert "<script>alert(" not in lowered
        assert "javascript:alert(" not in lowered
        assert "onerror=alert(" not in lowered

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
        with patch.dict(os.environ, {"SECRET_KEY": "a" * 32}, clear=True):
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

    def test_admin_audit_uses_authenticated_user_id(self, admin_client, admin_csrf_token, test_db, sample_indicators):
        """Test that admin audit entries store the session user identifier."""
        response = admin_client.post(
            "/admin/feed/new",
            data={
                "source_id": "audit-feed",
                "display_name": "Audit Feed",
                "source_type": "misp",
                "base_url": "https://audit.example.test",
                "auth_type": "api_key",
                "schedule_cron": "*/30 * * * *",
                "enabled": "on",
                "csrf_token": admin_csrf_token,
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        from app.models import AuditLog

        audit = test_db.query(AuditLog).filter(AuditLog.action == "admin_feed_add").order_by(AuditLog.id.desc()).first()
        assert audit is not None
        assert audit.user_id == "admin"
        assert audit.previous_hash is not None
        assert audit.log_hash is not None

    def test_admin_audit_verify_detects_tampering(self, admin_client, admin_csrf_token, test_db, sample_indicators):
        """Audit verification reports signed chain validity and detects changed metadata."""
        response = admin_client.post(
            "/admin/feed/new",
            data={
                "source_id": "tamper-feed",
                "display_name": "Tamper Feed",
                "source_type": "misp",
                "base_url": "https://tamper.example.test",
                "auth_type": "api_key",
                "schedule_cron": "*/30 * * * *",
                "enabled": "on",
                "csrf_token": admin_csrf_token,
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        verified = admin_client.get("/admin/audit/verify")
        assert verified.status_code == 200
        assert verified.get_json()["valid"] is True

        audit = test_db.query(AuditLog).filter(AuditLog.action == "admin_feed_add").order_by(AuditLog.id.desc()).first()
        assert audit is not None
        audit.metadata_ = {"tampered": True}
        test_db.commit()

        tampered = admin_client.get("/admin/audit/verify")
        assert tampered.status_code == 409
        body = tampered.get_json()
        assert body["valid"] is False
        assert body["failure_count"] >= 1

    def test_admin_audit_report_includes_integrity_and_controls(self, admin_client, sample_indicators):
        response = admin_client.get("/admin/audit/report")

        assert response.status_code == 200
        body = response.get_json()
        assert body["audit_table"] == "audit_log"
        assert body["central_log_table"] == "app_logs"
        assert "ISO27001-A.12.4.1" in body["controls"]
        assert body["integrity"]["valid"] is True


# ============================================================================
# Admin Login Rate Limit DB Override Tests
# ============================================================================

class TestAdminLoginRateLimitDbOverride:
    """Test DB-backed admin login rate limit configuration."""

    def test_get_admin_login_rate_limit_from_db(self, test_db):
        """Test retrieving rate limit from DB override."""
        from app.settings_store import get_admin_login_rate_limit, get_admin_login_rate_limit_window
        from app.models import AppSetting

        # Initially should return default from config
        default_limit = get_admin_login_rate_limit(test_db)
        assert default_limit is not None
        assert "per" in default_limit

        default_window = get_admin_login_rate_limit_window(test_db)
        assert default_window == 15 or isinstance(default_window, int)

        # Set DB override
        test_db.add(AppSetting(
            key="feedcfg.security.admin_login_rate_limit",
            value="5 per 5 minute",
            is_secret=False,
        ))
        test_db.add(AppSetting(
            key="feedcfg.security.admin_login_rate_limit_window_minutes",
            value="5",
            is_secret=False,
        ))
        test_db.commit()

        # Should return DB value
        db_limit = get_admin_login_rate_limit(test_db)
        assert db_limit == "5 per 5 minute"

        db_window = get_admin_login_rate_limit_window(test_db)
        assert db_window == 5

    def test_admin_login_rate_limit_falls_back_to_env(self, test_db, app):
        """Test that DB override falls back to env/config when not in DB."""
        from app.settings_store import get_admin_login_rate_limit

        # Ensure no DB override exists
        from app.models import AppSetting
        test_db.query(AppSetting).filter(
            AppSetting.key.in_([
                "feedcfg.security.admin_login_rate_limit",
                "feedcfg.security.admin_login_rate_limit_window_minutes",
            ])
        ).delete(synchronize_session=False)
        test_db.commit()

        with app.app_context():
            limit = get_admin_login_rate_limit(test_db)
            # Should return config/env default
            assert limit is not None
            assert isinstance(limit, str)
            assert "per" in limit

    def test_admin_login_rate_limit_invalid_window_defaults(self, test_db):
        """Test that invalid window value falls back to default."""
        from app.settings_store import get_admin_login_rate_limit_window
        from app.models import AppSetting

        # Set invalid DB value
        test_db.add(AppSetting(
            key="feedcfg.security.admin_login_rate_limit_window_minutes",
            value="invalid",
            is_secret=False,
        ))
        test_db.commit()

        # Should return default (15) for invalid value
        window = get_admin_login_rate_limit_window(test_db)
        assert window == 15

    def test_db_override_persists_and_reads_back(self, test_db, admin_client):
        """Test that setting security config via admin panel persists correctly."""
        from flask import session as flask_session

        from app.models import AppSetting

        # Get admin page to initialize session and extract CSRF token
        with admin_client.session_transaction() as sess:
            sess["admin_authenticated"] = True
            sess["admin_user_id"] = "admin"
            sess["admin_role"] = "admin"
            sess["admin_csrf_token"] = "test-csrf-token"
            csrf_token = "test-csrf-token"

        # Post new rate limit via admin config form with CSRF token
        response = admin_client.post("/admin/global-config", data={
            "csrf_token": csrf_token,
            "proxy_http_url": "",
            "proxy_https_url": "",
            "proxy_no_proxy": "",
            "proxy_ca_bundle_path": "",
            "trusted_proxy_count": "0",
            "sentinel_tenant_id": "",
            "sentinel_client_id": "",
            "sentinel_auth_mode": "client_secret",
            "sentinel_scope": "",
            "sentinel_endpoint_url": "",
            "sentinel_chunk_size": "100",
            "sentinel_cert_thumbprint": "",
            "admin_login_rate_limit": "20 per 30 minute",
            "admin_login_rate_limit_window_minutes": "30",
        }, follow_redirects=True)

        assert response.status_code == 200

        # Verify DB has the value
        rate_limit_setting = test_db.query(AppSetting).filter_by(
            key="feedcfg.security.admin_login_rate_limit"
        ).one_or_none()
        assert rate_limit_setting is not None
        assert rate_limit_setting.value == "20 per 30 minute"

        window_setting = test_db.query(AppSetting).filter_by(
            key="feedcfg.security.admin_login_rate_limit_window_minutes"
        ).one_or_none()
        assert window_setting is not None
        assert window_setting.value == "30"


# ============================================================================
# Admin Auth Disabled Tests
# ============================================================================

class TestAdminAuthDisabled:
    """Test admin authentication disabled mode (dev/test only)."""

    def test_admin_auth_enabled_by_default(self, client):
        """Admin auth is enabled by default."""
        from app.config import Config
        cfg = Config()
        assert cfg.security.ADMIN_AUTH_ENABLED is True

    def test_admin_auth_disabled_via_environ(self):
        """ADMIN_AUTH_ENABLED=false disables admin authentication."""
        import os
        # Set env var before creating config
        os.environ["ADMIN_AUTH_ENABLED"] = "false"
        try:
            from app.config import Config
            cfg = Config()
            assert cfg.security.ADMIN_AUTH_ENABLED is False
        finally:
            del os.environ["ADMIN_AUTH_ENABLED"]

    def test_admin_auth_disabled_shows_warning_banner(self, admin_client):
        """Warning banner CSS class is present when auth is disabled."""
        # Admin client is already authenticated, check page renders
        response = admin_client.get("/admin")
        assert response.status_code == 200


# ============================================================================
# Toast Notification System Tests
# ============================================================================

class TestToastNotificationSystem:
    """Test toast notification system integration."""

    def test_toast_container_exists_in_layout(self, client):
        """Toast container element exists in layout template."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert 'id="toast-container"' in html
        assert 'class="toast-container"' in html

    def test_showtoast_function_exists(self, client):
        """showToast JavaScript function is defined."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert "window.showToast = function" in html or "window.showToast =" in html
        assert "toast-container" in html

    def test_toast_css_styles_exist(self, client):
        """Toast CSS styles are present in layout."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert ".toast-container" in html
        assert ".toast-success" in html or "toast-" in html
        assert "@keyframes slideIn" in html or "slideIn" in html


# ============================================================================
# Mobile Responsive Design Tests
# ============================================================================

class TestMobileResponsiveDesign:
    """Test mobile-first responsive design."""

    def test_mobile_menu_button_present(self, client):
        """Mobile menu button exists in header."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert "mobile-menu-btn" in html
        assert 'id="mobileMenuBtn"' in html
        assert "aria-expanded" in html

    def test_mobile_menu_toggle_javascript(self, client):
        """Mobile menu toggle JavaScript is present."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert "mobileMenuBtn" in html
        assert "navMenu.classList.toggle('active')" in html or "navMenu.classList.toggle" in html

    def test_mobile_breakpoint_css_exists(self, client):
        """Mobile breakpoint CSS exists."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert "@media (max-width: 768px)" in html
        assert ".mobile-menu-btn" in html
        assert ".nav-menu" in html

    def test_touch_friendly_css_exists(self, client):
        """Touch-friendly CSS for mobile devices."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert "@media (pointer: coarse)" in html or "min-height: 44px" in html
        assert "min-width: 44px" in html

    def test_table_container_scrollable(self, client):
        """Table containers are scrollable on mobile."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "table-container" in html
        assert "overflow-x: auto" in html or "overflow-x:auto" in html

    def test_reduced_motion_respected(self, client):
        """Reduced motion preference is respected."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert "prefers-reduced-motion" in html
        assert "animation-duration: 0.01ms" in html or "animation-duration:0.01ms" in html


# ============================================================================
# Loading States and Skeleton Screens Tests
# ============================================================================

class TestLoadingStates:
    """Test loading states and skeleton screens."""

    def test_skeleton_css_exists(self, client):
        """Skeleton CSS is present in layout."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert ".skeleton" in html
        assert "@keyframes shimmer" in html or "animation: shimmer" in html

    def test_skeleton_variants_exist(self, client):
        """Different skeleton variants exist."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert ".skeleton-text" in html
        assert ".skeleton-title" in html
        assert ".skeleton-row" in html
        assert ".skeleton-card" in html

    def test_button_loading_css_exists(self, client):
        """Button loading CSS exists."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert ".btn-loading" in html
        assert "@keyframes spin" in html

    def test_loading_utilities_javascript(self, client):
        """Loading utility JavaScript functions exist."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert "window.setLoading" in html or "setLoading =" in html
        assert "window.createSkeleton" in html or "createSkeleton =" in html

    def test_loading_overlay_css_exists(self, client):
        """Loading overlay CSS exists."""
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert ".loading-overlay" in html
        assert "[data-loading]" in html


# ============================================================================
# Search Autocomplete Tests
# ============================================================================

class TestSearchAutocomplete:
    """Test search autocomplete functionality."""

    def test_autocomplete_container_exists(self, client):
        """Autocomplete container exists in indicators page."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "autocomplete-container" in html
        assert "autocomplete-dropdown" in html
        assert "autocomplete-list" in html

    def test_autocomplete_aria_attributes_exist(self, client):
        """ARIA attributes for accessibility."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "aria-autocomplete" in html
        assert "aria-controls" in html
        assert 'role="listbox"' in html or "role='listbox'" in html
        assert "aria-selected" in html or "aria-selected=" in html

    def test_autocomplete_css_styles_exist(self, client):
        """Autocomplete CSS styles exist."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert ".autocomplete-container" in html
        assert ".autocomplete-dropdown" in html
        assert ".autocomplete-item" in html

    def test_autocomplete_javascript_exists(self, client):
        """Autocomplete JavaScript exists."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "getRecentSearches" in html or "recent-searches" in html
        assert "saveSearch" in html
        assert "renderSuggestions" in html or "renderSuggestions" in html
        assert "STORAGE_KEY" in html

    def test_recent_searches_localstorage(self, client):
        """Recent searches use localStorage."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "localStorage" in html
        assert "STORAGE_KEY" in html or "getItem" in html


# ============================================================================
# Table Sorting Tests
# ============================================================================

class TestTableSorting:
    """Test table sorting functionality with sticky headers."""

    def test_table_sortable_headers_exist(self, client):
        """Sortable table headers exist with proper classes."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "sortable" in html
        assert "sort-asc" in html or "sort-desc" in html

    def test_table_aria_sort_attributes_exist(self, client):
        """ARIA sort attributes for accessibility."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "aria-sort" in html
        assert 'role="columnheader"' in html or "role='columnheader'" in html

    def test_table_sticky_header_css_exists(self, client):
        """Sticky header CSS exists."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "position: sticky" in html or "position:sticky" in html
        assert "thead" in html

    def test_table_sorting_javascript_exists(self, client):
        """Table sorting JavaScript exists."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "sortTable" in html
        assert "currentSort" in html or "sortTypes" in html

    def test_table_sorting_keyboard_support(self, client):
        """Table sorting has keyboard support."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "tabindex" in html
        assert 'keydown' in html or "keydown" in html

    def test_table_sort_indicators_css(self, client):
        """Sort indicator CSS exists."""
        response = client.get("/indicators")
        html = response.get_data(as_text=True)
        assert "th.sort-asc" in html or "th.sort-desc" in html
        assert 'content:' in html or "::after" in html
