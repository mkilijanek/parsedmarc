from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


def test_indicators_formats_links_quote_url_values(client, sample_indicators):
    response = client.get("/indicators?type=url")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "value%3A%22http%3A%2F%2Fevil.com%2Fpayload.exe%22" in html
    assert "source%3A%22malwarebazaar%22" in html


def test_quick_export_preserves_active_filters(client, sample_indicators):
    response = client.get("/indicators?type=ip&tlp=RED&source=misp&min_conf=80&max_conf=100")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "/indicators/json?type=ip&amp;tlp=RED&amp;source=misp&amp;min_conf=80&amp;max_conf=100" in html


def test_source_dropdown_shows_distinct_sources(client, sample_indicators):
    response = client.get("/indicators")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "<option value='malwarebazaar'" in html
    assert "<option value='mwdb'" in html


def test_admin_panel_exposes_config_and_sync_controls(client, sample_indicators, sample_feed_stats):
    response = client.get("/admin")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Configuration Panel" in html
    assert "Manual Synchronization and Feed Management" in html
    assert "Config Readiness" in html
    assert "href='/admin/feed/misp/configure'" in html
    assert "Add New Feed" in html


def test_misp_feed_is_disabled_by_default(client, sample_indicators, sample_feed_stats):
    response = client.get("/admin")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "value='misp'" in html
    assert ">Enable</button>" in html


def test_dark_mode_toggle_script_present(client, sample_indicators):
    response = client.get("/indicators")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "localStorage.setItem(themeKey, next);" in html
    assert "id=\"themeToggleGlobal\"" in html


def test_startup_loader_uses_shorter_min_visible_delay(client, sample_indicators):
    response = client.get("/indicators")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "const minVisibleMs = 400;" in html


def test_unified_table_template_has_accessibility_roles_and_badges():
    template = Path("app/templates/table.html").read_text(encoding="utf-8")
    assert 'role="table"' in template
    assert 'role="columnheader"' in template
    assert 'role="cell"' in template
    assert "badge-tlp" in template
    assert "badge-type" in template


def test_dark_mode_toggle_present_on_overview_and_logs(client, sample_indicators):
    overview = client.get("/")
    logs = client.get("/logs")
    assert overview.status_code == 200
    assert logs.status_code == 200
    overview_html = overview.get_data(as_text=True)
    logs_html = logs.get_data(as_text=True)
    assert "id=\"themeToggleGlobal\"" in overview_html
    assert "localStorage.getItem(themeKey)" in overview_html
    assert "id=\"themeToggleGlobal\"" in logs_html
    assert "localStorage.getItem(themeKey)" in logs_html


def test_global_topbar_present_on_indicators_and_admin(client, sample_indicators, sample_feed_stats):
    indicators = client.get("/indicators")
    admin = client.get("/admin")
    assert indicators.status_code == 200
    assert admin.status_code == 200
    indicators_html = indicators.get_data(as_text=True)
    admin_html = admin.get_data(as_text=True)
    assert 'id="globalTopbar"' in indicators_html
    assert 'id="globalTopbar"' in admin_html
    assert 'href="/admin"' in indicators_html
    assert 'href="/indicators"' in admin_html


def test_admin_sync_rejects_incomplete_feed_config(client, sample_indicators):
    response = client.post("/admin/sync", data={"source": "misp"}, follow_redirects=True)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "configuration incomplete" in html.lower()


def test_feed_configure_is_scoped_to_single_feed(client, sample_indicators):
    response = client.post(
        "/admin/feed/mwdb/configure",
        data={
            "display_name": "MWDB",
            "base_url": "https://mwdb.local",
            "schedule_cron": "*/15 * * * *",
            "api_key": "secret123",
        },
        follow_redirects=False,
    )
    assert response.status_code in {301, 302}


def test_feed_configure_has_test_connection_button(client, sample_indicators):
    response = client.get("/admin/feed/abusech/configure")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Test connection" in html
    assert "Save settings" in html


def test_mwdb_configure_shows_extended_fields(client, sample_indicators):
    response = client.get("/admin/feed/mwdb/configure")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "MWDB tags (comma-separated)" in html
    assert "MWDB days" in html
    assert "No time limit" in html


def test_abusech_configure_shows_service_selectors(client, sample_indicators):
    response = client.get("/admin/feed/abusech/configure")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "ThreatFox" in html
    assert "URLhaus" in html
    assert "Bazaar" in html
    assert "FeodoTracker" in html
    assert "YARAify" in html
    assert "Custom filter" in html


def test_feed_test_connection_endpoint_redirects(client, sample_indicators):
    response = client.post("/admin/feed/abusech/test", data={"api_key": ""}, follow_redirects=False)
    assert response.status_code in {301, 302}


def test_malwarebazaar_test_connection_error_mentions_abusech_auth_key(client, sample_indicators):
    with patch("app.main.requests.post") as mocked_post:
        response = client.post("/admin/feed/malwarebazaar/test", data={"api_key": ""}, follow_redirects=True)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "ABUSECH_AUTH_KEY" in html
    mocked_post.assert_not_called()


def test_admin_logs_tab_and_api(client, sample_indicators):
    page = client.get("/logs")
    assert page.status_code == 200
    api = client.get("/api/logs?limit=10")
    assert api.status_code == 200
    data = api.get_json()
    assert "items" in data


def test_api_sync_enqueue_returns_202_and_job_id(client, sample_indicators):
    response = client.post("/api/sync", json={"source": "abusech"})
    assert response.status_code == 202
    data = response.get_json()
    assert data["source"] == "abusech"
    assert len(data["jobs"]) == 1
    assert data["jobs"][0]["feed_source_id"] == "abusech"
    assert isinstance(data["jobs"][0]["job_id"], str) and data["jobs"][0]["job_id"]
    assert data["jobs"][0]["created"] is True


def test_api_sync_idempotency_reuses_existing_job(client, sample_indicators):
    first = client.post("/api/sync", json={"source": "abusech"})
    second = client.post("/api/sync", json={"source": "abusech"})
    assert first.status_code == 202
    assert second.status_code == 202
    first_data = first.get_json()
    second_data = second.get_json()
    assert first_data["jobs"][0]["job_id"] == second_data["jobs"][0]["job_id"]
    assert second_data["jobs"][0]["created"] is False


def test_api_logs_filter_by_job_id(client, sample_indicators):
    sync_resp = client.post("/api/sync", json={"source": "abusech"})
    job_id = sync_resp.get_json()["jobs"][0]["job_id"]
    logs_resp = client.get(f"/api/logs?job_id={job_id}&limit=50")
    assert logs_resp.status_code == 200
    data = logs_resp.get_json()
    assert data["count"] >= 1
    assert all(item["run_id"] == job_id for item in data["items"])


def test_api_500_returns_json_with_correlation_id(client, sample_indicators):
    response = client.get("/api/logs?limit=not-a-number")
    assert response.status_code == 500
    data = response.get_json()
    assert isinstance(data.get("error"), str) and data["error"]
    assert isinstance(data.get("correlation_id"), str) and data["correlation_id"]
