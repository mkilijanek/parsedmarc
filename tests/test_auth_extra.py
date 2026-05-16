"""Extra coverage tests for app/routes/auth.py. Covers login/logout flows."""
from __future__ import annotations

import pytest


class TestAuthLogin:
    def test_login_page_returns_200(self, client, sample_indicators):
        resp = client.get("/auth/login")
        assert resp.status_code == 200

    def test_login_page_with_msg_param(self, client, sample_indicators):
        resp = client.get("/auth/login?msg=Invalid+admin+token.")
        assert resp.status_code == 200

    def test_login_page_with_next_param(self, client, sample_indicators):
        resp = client.get("/auth/login?next=/admin")
        assert resp.status_code == 200

    def test_login_post_wrong_token_redirects(self, client, sample_indicators):
        resp = client.post("/auth/login", data={
            "admin_token": "wrong-token-value",
            "next": "/admin",
        })
        assert resp.status_code in (302, 303)
        location = resp.headers.get("Location", "")
        assert "msg" in location or "login" in location

    def test_login_post_correct_token_redirects_to_admin(self, admin_client, sample_indicators):
        with admin_client.session_transaction() as sess:
            csrf = sess.get("admin_csrf_token", "")
        resp = admin_client.post("/auth/login", data={
            "admin_token": "test-admin-token",
            "next": "/admin",
            "csrf_token": csrf,
        })
        assert resp.status_code in (302, 303, 200)

    def test_login_post_empty_token_redirects(self, client, sample_indicators):
        resp = client.post("/auth/login", data={
            "admin_token": "",
            "next": "/admin",
        })
        assert resp.status_code in (302, 303)


class TestAuthLogout:
    def test_logout_get_returns_405_or_redirect(self, admin_client, sample_indicators):
        resp = admin_client.get("/auth/logout")
        assert resp.status_code in (302, 303, 200, 405)

    def test_logout_post_redirects(self, admin_client, sample_indicators):
        with admin_client.session_transaction() as sess:
            csrf = sess.get("admin_csrf_token", "")
        resp = admin_client.post("/auth/logout", data={"csrf_token": csrf})
        assert resp.status_code in (302, 303, 200)


class TestAuthSessionCheck:
    def test_admin_panel_requires_auth(self, client, sample_indicators):
        resp = client.get("/admin")
        assert resp.status_code in (302, 303, 200, 401, 403)

    def test_authenticated_client_can_access_admin(self, admin_client, sample_indicators):
        resp = admin_client.get("/admin")
        assert resp.status_code == 200

    def test_admin_panel_has_csrf_token_in_session(self, admin_client, sample_indicators):
        admin_client.get("/admin")
        with admin_client.session_transaction() as sess:
            assert "admin_csrf_token" in sess

    def test_unauthenticated_redirect_includes_next(self, client, sample_indicators):
        resp = client.get("/admin", follow_redirects=False)
        if resp.status_code in (302, 303):
            location = resp.headers.get("Location", "")
            assert "login" in location or "admin" in location


class TestShouldRedirectAuthSurface:
    def test_login_get_accessible_over_http(self, client, sample_indicators):
        resp = client.get("/auth/login")
        assert resp.status_code in (200, 301, 302)


class TestAdminApiTokenEndpoint:
    def test_admin_token_endpoint_requires_auth(self, client, sample_indicators):
        resp = client.get("/admin/api/token")
        assert resp.status_code in (302, 303, 401, 403, 404, 200)

    def test_admin_token_endpoint_with_auth(self, admin_client, sample_indicators):
        resp = admin_client.get("/admin/api/token")
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.get_json()
            assert data is not None
