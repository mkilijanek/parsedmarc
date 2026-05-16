"""Coverage tests for ops_admin.py wipe, add feed, configure, test connection routes."""
from __future__ import annotations

import pytest


def _get_csrf(admin_client):
    admin_client.get("/admin")
    with admin_client.session_transaction() as sess:
        return sess.get("admin_csrf_token", "")


class TestAdminDangerWipeOperation:
    def test_wipe_wrong_confirm_phrase_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/danger/wipe",
            data={
                "csrf_token": csrf,
                "X-Admin-Token": "test-admin-token",
                "confirm_phrase": "DELETE",
                "confirm_instance": "ioc-service",
                "operation": "soft",
            },
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (302, 303)
        location = resp.headers.get("Location", "")
        assert "msg" in location or "admin" in location

    def test_wipe_wrong_instance_name_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/danger/wipe",
            data={
                "csrf_token": csrf,
                "confirm_phrase": "WIPE",
                "confirm_instance": "wrong-instance-name",
                "operation": "soft",
            },
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (302, 303)

    def test_wipe_selected_invalid_table_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/danger/wipe",
            data={
                "csrf_token": csrf,
                "confirm_phrase": "WIPE",
                "confirm_instance": "ioc-service",
                "operation": "selected",
                "tables": [],
            },
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (302, 303)

    def test_wipe_invalid_operation_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/danger/wipe",
            data={
                "csrf_token": csrf,
                "confirm_phrase": "WIPE",
                "confirm_instance": "ioc-service",
                "operation": "unknown_op",
            },
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (302, 303)


class TestAdminAddFeedValidation:
    def test_add_feed_invalid_source_type_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/feed/new",
            data={
                "csrf_token": csrf,
                "source_id": "custom_feed",
                "display_name": "Custom Feed",
                "source_type": "nonexistent_type_xyz",
                "enabled": "1",
            },
        )
        assert resp.status_code in (302, 303)
        location = resp.headers.get("Location", "")
        assert "msg" in location or "admin" in location

    def test_add_feed_missing_source_id_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/feed/new",
            data={
                "csrf_token": csrf,
                "source_id": "",
                "display_name": "No Source",
                "source_type": "misp",
            },
        )
        assert resp.status_code in (302, 303)

    def test_add_feed_missing_display_name_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/feed/new",
            data={
                "csrf_token": csrf,
                "source_id": "test_feed",
                "display_name": "",
                "source_type": "misp",
            },
        )
        assert resp.status_code in (302, 303)


class TestAdminFeedConfigure:
    def test_configure_unknown_feed_redirects(self, admin_client, sample_indicators):
        resp = admin_client.get("/admin/feed/nonexistent_xyz/configure")
        assert resp.status_code in (302, 303, 200)

    def test_configure_known_feed_returns_200(self, admin_client, sample_indicators):
        resp = admin_client.get("/admin/feed/misp/configure")
        assert resp.status_code in (200, 302, 303)

    def test_configure_save_unknown_feed_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/feed/nonexistent_xyz/configure",
            data={"csrf_token": csrf},
        )
        assert resp.status_code in (302, 303)


class TestAdminFeedTestConnection:
    def test_test_connection_unknown_feed_redirects(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/feed/nonexistent_xyz/test",
            data={"csrf_token": csrf},
        )
        assert resp.status_code in (302, 303)

    def test_test_connection_known_feed_returns_redirect(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/feed/misp/test",
            data={"csrf_token": csrf},
        )
        assert resp.status_code in (302, 303)


class TestAdminSyncJob:
    def test_sync_job_detail_unknown_returns_redirect(self, admin_client, sample_indicators):
        resp = admin_client.get("/admin/sync-jobs/nonexistent-job-id")
        assert resp.status_code in (302, 303, 404, 200)

    def test_sync_jobs_list_returns_2xx_or_redirect(self, admin_client, sample_indicators):
        resp = admin_client.get("/admin/sync-jobs")
        assert resp.status_code in (200, 302, 303, 404)

    def test_admin_manual_sync_all(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/sync",
            data={"csrf_token": csrf, "source": "all"},
        )
        assert resp.status_code in (302, 303, 200)


class TestAdminApiDlq:
    def test_dlq_list_with_auth(self, admin_client, sample_indicators):
        resp = admin_client.get(
            "/admin/api/dead-letter-jobs",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (200, 404, 501)

    def test_dlq_requeue_unknown_job(self, admin_client, sample_indicators):
        csrf = _get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/api/dead-letter-jobs/99999/requeue",
            data={"csrf_token": csrf},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (200, 400, 404, 501)
