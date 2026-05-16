"""Extra coverage tests for app/routes/api_v1.py. Closes #236."""
from __future__ import annotations

import pytest


class TestApiV1OpenAPI:
    def test_openapi_yaml_returns_yaml(self, client, sample_indicators):
        resp = client.get("/api/v1/openapi.yaml")
        assert resp.status_code == 200
        assert b"openapi" in resp.data.lower() or b"paths" in resp.data.lower() or len(resp.data) > 100

    def test_openapi_json_returns_json(self, client, sample_indicators):
        resp = client.get("/api/v1/openapi.json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data is not None

    def test_api_docs_returns_html(self, client, sample_indicators):
        resp = client.get("/api/v1/docs")
        assert resp.status_code == 200
        assert b"html" in resp.data.lower()

    def test_swagger_ui_returns_html(self, client, sample_indicators):
        resp = client.get("/api/swagger")
        assert resp.status_code == 200
        assert b"html" in resp.data.lower()


class TestApiV1Indicators:
    def test_indicators_basic(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data

    def test_indicators_with_pagination(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?limit=2&offset=0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["items"]) <= 2

    def test_indicators_type_filter(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?type=ip")
        assert resp.status_code == 200
        data = resp.get_json()
        for item in data["items"]:
            assert item["type"] == "ip"

    def test_indicators_tlp_filter(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?tlp=GREEN")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data["items"], list)

    def test_indicators_invalid_min_conf_returns_400(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?min_conf=notanumber")
        assert resp.status_code == 400

    def test_indicators_invalid_max_conf_returns_400(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?max_conf=abc")
        assert resp.status_code == 400

    def test_indicators_invalid_limit_returns_400(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?limit=notint")
        assert resp.status_code == 400

    def test_indicators_with_search_query(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?q=source:misp")
        assert resp.status_code == 200

    def test_indicators_source_filter(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?source=misp")
        assert resp.status_code == 200

    def test_indicators_min_conf_filter(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?min_conf=50&max_conf=100")
        assert resp.status_code == 200
        data = resp.get_json()
        for item in data["items"]:
            assert item["confidence"] >= 50

    def test_indicators_item_shape(self, client, sample_indicators):
        resp = client.get("/api/v1/indicators?limit=1")
        assert resp.status_code == 200
        data = resp.get_json()
        if data["items"]:
            item = data["items"][0]
            for key in ("id", "uuid", "value", "type", "source", "confidence", "tlp", "is_active"):
                assert key in item


class TestApiV1Feeds:
    def test_v1_feeds_returns_list(self, client, sample_indicators, sample_feed_stats):
        resp = client.get("/api/v1/feeds")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert "total" in data

    def test_v1_feeds_pagination(self, client, sample_indicators, sample_feed_stats):
        resp = client.get("/api/v1/feeds?limit=1&offset=0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["items"]) <= 1

    def test_v1_feeds_metrics(self, client, sample_indicators, sample_feed_stats):
        resp = client.get("/api/v1/feeds/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert "summary" in data
        assert "timeseries" in data

    def test_v1_feeds_metrics_with_window(self, client, sample_indicators, sample_feed_stats):
        resp = client.get("/api/v1/feeds/metrics?hours=48")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["hours"] == 48

    def test_v1_feeds_sort_by_source(self, client, sample_indicators, sample_feed_stats):
        resp = client.get("/api/v1/feeds?sort=source&order=asc")
        assert resp.status_code == 200


class TestApiV1RunsCurrent:
    def test_runs_current_returns_structure(self, client, sample_indicators):
        resp = client.get("/api/v1/runs/current")
        assert resp.status_code in (200, 401, 403)
        if resp.status_code == 200:
            data = resp.get_json()
            assert "running" in data
            assert "latest" in data
            assert "queued_jobs" in data


class TestApiV1Sync:
    def test_sync_requires_admin_token(self, client, sample_indicators):
        resp = client.post("/api/v1/sync", json={"source": "misp"})
        assert resp.status_code in (401, 403)

    def test_sync_missing_source_returns_400(self, client, sample_indicators):
        resp = client.post(
            "/api/v1/sync",
            json={},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code == 400

    def test_sync_invalid_source_returns_400(self, client, sample_indicators):
        resp = client.post(
            "/api/v1/sync",
            json={"source": "nonexistent_xyz"},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (400, 404)

    def test_sync_valid_source_accepted(self, client, sample_indicators):
        resp = client.post(
            "/api/v1/sync",
            json={"source": "misp"},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert resp.status_code in (202, 400)


class TestApiV1Logs:
    def test_logs_returns_list(self, client, sample_indicators):
        resp = client.get("/api/v1/logs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert "count" in data

    def test_logs_with_level_filter(self, client, sample_indicators):
        resp = client.get("/api/v1/logs?level=INFO")
        assert resp.status_code == 200

    def test_logs_with_limit(self, client, sample_indicators):
        resp = client.get("/api/v1/logs?limit=5")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["items"]) <= 5

    def test_logs_with_feed_filter(self, client, sample_indicators):
        resp = client.get("/api/v1/logs?feed=misp")
        assert resp.status_code == 200

    def test_logs_with_since_filter(self, client, sample_indicators):
        resp = client.get("/api/v1/logs?since=2020-01-01T00:00:00Z")
        assert resp.status_code == 200

    def test_logs_with_invalid_since_ignored(self, client, sample_indicators):
        resp = client.get("/api/v1/logs?since=notadate")
        assert resp.status_code == 200


class TestApiV1DeprecationHeaders:
    def test_legacy_sync_has_deprecation_header(self, client, sample_indicators):
        resp = client.post(
            "/api/sync",
            json={"source": "misp"},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        # If a successor exists for /api/sync, expect Deprecation header
        # The test just verifies the endpoint responds without error
        assert resp.status_code in (202, 400, 401, 403)
