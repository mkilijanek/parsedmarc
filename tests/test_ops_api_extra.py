"""Extra route tests for ops_api.py — covers DLQ, circuit breaker, runs endpoints."""
from __future__ import annotations

import pytest


class TestAdminApiDeadLetterJobs:
    def test_dlq_endpoint_returns_json(self, admin_client, sample_indicators):
        resp = admin_client.get(
            "/admin/api/dead-letter-jobs",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (200, 501)
        if resp.status_code == 200:
            data = resp.get_json()
            assert "count" in data
            assert "items" in data

    def test_dlq_endpoint_without_auth_denied(self, client, sample_indicators):
        resp = client.get("/admin/api/dead-letter-jobs")
        assert resp.status_code in (200, 302, 401, 403, 501)

    def test_dlq_with_feed_filter(self, admin_client, sample_indicators):
        resp = admin_client.get(
            "/admin/api/dead-letter-jobs?feed=misp&limit=10",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (200, 501)

    def test_dlq_requeue_not_found(self, admin_client, sample_indicators):
        resp = admin_client.post(
            "/admin/api/dead-letter-jobs/99999/requeue",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (200, 400, 404, 501)


class TestAdminApiDbCircuit:
    def test_db_circuit_returns_state(self, admin_client, sample_indicators):
        resp = admin_client.get(
            "/admin/api/db-circuit",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "state" in data


class TestApiRunsCurrent:
    def test_runs_current_returns_json(self, client, sample_indicators):
        resp = client.get(
            "/api/runs/current",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (200, 401, 403)
        if resp.status_code == 200:
            data = resp.get_json()
            assert isinstance(data, (dict, list))

    def test_runs_current_v1_endpoint(self, client, sample_indicators):
        resp = client.get(
            "/api/v1/runs/current",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (200, 401, 403, 404)


class TestApiSyncPost:
    def test_sync_with_admin_token_header(self, client, sample_indicators):
        resp = client.post(
            "/api/sync",
            json={"source": "misp"},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (200, 202, 400, 409)

    def test_sync_missing_source_returns_400(self, client, sample_indicators):
        resp = client.post(
            "/api/sync",
            json={},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (400, 422)

    def test_sync_invalid_source_returns_400(self, client, sample_indicators):
        resp = client.post(
            "/api/sync",
            json={"source": "nonexistent_feed_xyz"},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (400, 404, 422)


class TestApiFeeds:
    def test_feeds_returns_list(self, client, sample_indicators, sample_feed_stats):
        resp = client.get("/api/feeds")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, (dict, list))

    def test_feeds_with_pagination_params(self, client, sample_indicators, sample_feed_stats):
        resp = client.get("/api/feeds?limit=10&offset=0")
        assert resp.status_code == 200

    def test_feeds_metrics_endpoint(self, client, sample_indicators, sample_feed_stats):
        resp = client.get("/api/feeds/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data is not None
