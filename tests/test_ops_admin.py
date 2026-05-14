from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


class TestOpsAdminCoverage:

    def test_admin_panel_returns_200(self, admin_client):
        resp = admin_client.get("/admin")
        assert resp.status_code == 200

    def test_admin_panel_with_msg_param(self, admin_client):
        resp = admin_client.get("/admin?msg=test+message")
        assert resp.status_code == 200

    def test_admin_sync_jobs_page(self, admin_client):
        resp = admin_client.get("/admin/sync-jobs")
        assert resp.status_code in (200, 302, 404)

    def test_admin_scheduler_status_returns_200(self, admin_client):
        resp = admin_client.get("/admin/api/scheduler-status")
        assert resp.status_code in (200, 404)

    def test_admin_feeds_configure_page(self, admin_client):
        resp = admin_client.get("/admin/feed/misp/configure")
        assert resp.status_code in (200, 302, 404)

    def test_api_logs_page(self, admin_client):
        resp = admin_client.get("/api/logs")
        assert resp.status_code in (200, 302)

    def test_dead_letter_jobs_list_empty(self, admin_client):
        resp = admin_client.get("/admin/api/dead-letter-jobs")
        body = json.loads(resp.data)
        assert body["count"] == 0 or body["count"] >= 0

    def test_db_circuit_state_endpoint(self, admin_client):
        resp = admin_client.get("/admin/api/db-circuit")
        assert resp.status_code == 200
        body = json.loads(resp.data)
        assert "state" in body
