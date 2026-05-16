from __future__ import annotations

from datetime import datetime, timezone
from app.models import AuditLog
from pathlib import Path
from unittest.mock import patch

from app.models import AppSetting, SyncJob


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


def test_admin_panel_requires_authentication(client, sample_indicators, sample_feed_stats):
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code in {301, 302}
    assert "/auth/login" in response.headers["Location"]


def test_admin_panel_exposes_config_and_sync_controls(admin_client, sample_indicators, sample_feed_stats):
    response = admin_client.get("/admin")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Configuration Panel" in html
    assert "Manual Synchronization and Feed Management" in html
    assert "Recent Sync Jobs" in html
    assert "/admin/feed/misp/configure" in html
    assert "Add New Feed" in html
    assert "Apply filters" in html or "Apply Filters" in html
    assert "Problems only" in html or "Problems Only" in html
    assert "Danger Zone" in html
    assert "Skip TLS certificate verification" in html
    assert "Organization CA bundle path" in html
    assert "curl -k equivalent" in html
    assert "Feed Statistics" in html
    assert "CSV" in html
    assert "id=\"feedMetricsChart\"" in html
    assert "id=\"feedAvailabilityChart\"" in html
    assert "/logs?feed=" in html
    assert "Raw stats:" in html


def test_misp_feed_is_disabled_by_default(admin_client, sample_indicators, sample_feed_stats, test_db):
    from app.models import Feed
    misp_feed = Feed(
        source_id="misp",
        source_type="misp",
        display_name="MISP",
        enabled=False,
    )
    test_db.add(misp_feed)
    test_db.commit()
    response = admin_client.get("/admin")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    # Feed source ID appears in form hidden inputs (double-quoted in HTML)
    assert 'value="misp"' in html
    assert ">Enable</button>" in html


def test_dark_mode_toggle_script_present(client, sample_indicators):
    response = client.get("/indicators")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    # localStorage is wrapped in safe helpers (_lsGet/_lsSet) to handle SecurityError
    assert "lsSet(themeKey, next)" in html
    assert "id=\"themeToggle\"" in html


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


def test_app_package_init_is_lazy():
    init_text = Path("app/__init__.py").read_text(encoding="utf-8")
    top_level = "\n".join(init_text.splitlines()[:6])
    assert "from .main import create_app" not in top_level
    assert "def create_app" in init_text


def test_dark_mode_toggle_present_on_overview_and_logs(client, sample_indicators):
    overview = client.get("/")
    logs = client.get("/logs")
    assert overview.status_code == 200
    assert logs.status_code == 200
    overview_html = overview.get_data(as_text=True)
    logs_html = logs.get_data(as_text=True)
    assert "id=\"themeToggle\"" in overview_html
    assert "lsGet(themeKey)" in overview_html
    assert "id=\"themeToggle\"" in logs_html
    assert "lsGet(themeKey)" in logs_html


def test_global_topbar_present_on_indicators_and_admin(admin_client, client, sample_indicators, sample_feed_stats):
    indicators = client.get("/indicators")
    admin = admin_client.get("/admin")
    assert indicators.status_code == 200
    assert admin.status_code == 200
    indicators_html = indicators.get_data(as_text=True)
    admin_html = admin.get_data(as_text=True)
    # Check for unified layout navigation
    assert 'class="topbar"' in indicators_html or 'class="topbar"' in admin_html
    assert 'href="/admin"' in indicators_html
    assert 'href="/indicators"' in admin_html


def test_admin_sync_rejects_incomplete_feed_config(admin_client, admin_csrf_token, sample_indicators):
    response = admin_client.post("/admin/sync", data={"source": "misp", "csrf_token": admin_csrf_token}, follow_redirects=True)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "configuration incomplete" in html.lower()


def test_feed_configure_is_scoped_to_single_feed(admin_client, admin_csrf_token, sample_indicators):
    response = admin_client.post(
        "/admin/feed/mwdb/configure",
        data={
            "display_name": "MWDB",
            "base_url": "https://mwdb.local",
            "schedule_cron": "*/15 * * * *",
            "api_key": "secret123",
            "csrf_token": admin_csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code in {301, 302}


def test_feed_configure_has_test_connection_button(admin_client, sample_indicators):
    response = admin_client.get("/admin/feed/abusech/configure")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Test connection" in html
    assert "Save settings" in html


def test_mwdb_configure_shows_extended_fields(admin_client, sample_indicators):
    response = admin_client.get("/admin/feed/mwdb/configure")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "MWDB tags (comma-separated)" in html
    assert "MWDB days" in html
    assert "No time limit" in html
    assert "Base URL" not in html


def test_abusech_configure_shows_service_selectors(admin_client, sample_indicators):
    response = admin_client.get("/admin/feed/abusech/configure")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "ThreatFox" in html
    assert "URLhaus" in html
    assert "FeodoTracker" in html
    assert "YARAify" in html
    assert "YARAify identifier" in html
    assert "YARAify lookup hashes" in html
    assert "Hunting FPList" in html
    assert "Custom filter" in html
    assert "Base URL" not in html
    assert "Bazaar tags" not in html


def test_feed_test_connection_endpoint_redirects(admin_client, admin_csrf_token, sample_indicators):
    response = admin_client.post("/admin/feed/abusech/test", data={"api_key": "", "csrf_token": admin_csrf_token}, follow_redirects=False)
    assert response.status_code in {301, 302}


def test_dangerous_wipe_requires_admin_token(admin_client, admin_csrf_token, sample_indicators):
    panel = admin_client.get("/admin")
    assert panel.status_code == 200
    assert "Danger Zone" in panel.get_data(as_text=True)
    assert "ADMIN_DANGEROUS_OPS" not in panel.get_data(as_text=True)

    response = admin_client.post(
        "/admin/danger/wipe",
        data={"operation": "soft", "admin_token": "x", "confirm_phrase": "WIPE", "confirm_instance": "ioc-service", "csrf_token": admin_csrf_token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Dangerous operation denied: invalid admin token" in html


def test_malwarebazaar_test_connection_error_mentions_abusech_auth_key(admin_client, admin_csrf_token, sample_indicators):
    with patch("app.main.requests.post") as mocked_post:
        response = admin_client.post("/admin/feed/malwarebazaar/test", data={"api_key": "", "csrf_token": admin_csrf_token}, follow_redirects=True)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "ABUSECH_AUTH_KEY" in html
    mocked_post.assert_not_called()


def test_admin_settings_persist_proxy_skip_tls_verify(admin_client, admin_csrf_token, sample_indicators, test_db):
    resp = admin_client.post(
        "/admin/global-config",
        data={
            "proxy_http_url": "http://proxy.local:8080",
            "proxy_https_url": "http://proxy.local:8080",
            "proxy_no_proxy": "localhost,127.0.0.1",
            "proxy_ca_bundle_path": "/etc/ssl/certs/org-ca.pem",
            "proxy_skip_tls_verify": "1",
            "trusted_proxy_count": "1",
            "csrf_token": admin_csrf_token,
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    row = test_db.query(AppSetting).filter(AppSetting.key == "proxy.skip_tls_verify").one_or_none()
    assert row is not None
    assert str(row.value) == "1"
    row_ca = test_db.query(AppSetting).filter(AppSetting.key == "proxy.ca_bundle_path").one_or_none()
    assert row_ca is not None
    assert str(row_ca.value) == "/etc/ssl/certs/org-ca.pem"


def test_admin_proxy_test_runs_and_persists_results(admin_client, admin_csrf_token, sample_indicators, test_db):
    class _Resp:
        def __init__(self, url: str):
            self.status_code = 200
            self.headers = {"Content-Type": "text/html"}
            if "mwdb" in url:
                self.text = "<html><head><title>MWDB Malware Database</title></head><body></body></html>"
            elif "abuse.ch" in url:
                self.text = "<html><head><title>abuse.ch</title></head><body></body></html>"
            else:
                self.text = "<html><head><title>CERT Polska</title></head><body></body></html>"

        def raise_for_status(self):
            return None

    with patch("app.main.requests.get", side_effect=lambda url, timeout=None: _Resp(url)):
        resp = admin_client.post("/admin/proxy-test", data={"csrf_token": admin_csrf_token}, follow_redirects=True)
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Proxy test completed" in html
    assert "Proxy Test Results" in html
    row = test_db.query(AppSetting).filter(AppSetting.key == "proxy.last_test_result").one_or_none()
    assert row is not None
    assert "MWDB" in str(row.value)


def test_admin_logs_tab_and_api(client, sample_indicators):
    page = client.get("/logs")
    assert page.status_code == 200
    page_html = page.get_data(as_text=True)
    assert "Copy all visible logs" in page_html
    assert "Download visible .log" in page_html
    assert "navigator.clipboard" in page_html
    assert "await navigator.clipboard.writeText" in page_html
    api = client.get("/api/logs?limit=10")
    assert api.status_code == 200
    data = api.get_json()
    assert "items" in data


def test_api_sync_enqueue_returns_202_and_job_id(client, sample_indicators):
    headers = {"X-Admin-Token": "test-admin-token"}
    response = client.post("/api/sync", json={"source": "abusech"}, headers=headers)
    assert response.status_code == 202
    data = response.get_json()
    assert data["source"] == "abusech"
    assert len(data["jobs"]) == 1
    assert data["jobs"][0]["feed_source_id"] == "abusech"
    assert isinstance(data["jobs"][0]["job_id"], str) and data["jobs"][0]["job_id"]
    assert data["jobs"][0]["created"] is True


def test_api_sync_idempotency_reuses_existing_job(client, sample_indicators):
    headers = {"X-Admin-Token": "test-admin-token"}
    first = client.post("/api/sync", json={"source": "abusech"}, headers=headers)
    second = client.post("/api/sync", json={"source": "abusech"}, headers=headers)
    assert first.status_code == 202
    assert second.status_code == 202
    first_data = first.get_json()
    second_data = second.get_json()
    assert first_data["jobs"][0]["job_id"] == second_data["jobs"][0]["job_id"]
    assert second_data["jobs"][0]["created"] is False


def test_api_logs_filter_by_job_id(client, sample_indicators):
    sync_resp = client.post("/api/sync", json={"source": "abusech"}, headers={"X-Admin-Token": "test-admin-token"})
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


def test_sync_job_details_page_renders(admin_client, client, sample_indicators):
    sync_resp = client.post("/api/sync", json={"source": "abusech"}, headers={"X-Admin-Token": "test-admin-token"})
    assert sync_resp.status_code == 202
    job_id = sync_resp.get_json()["jobs"][0]["job_id"]
    details = admin_client.get(f"/admin/sync-jobs/{job_id}")
    assert details.status_code == 200
    html = details.get_data(as_text=True)
    assert "Sync Job Details" in html
    assert job_id in html


def test_sync_job_cancel_endpoint_cancels_queued_job(admin_client, admin_csrf_token, sample_indicators, test_db):
    # Ensure default feeds exist.
    assert admin_client.get("/admin").status_code == 200
    job = SyncJob(
        job_id="cancel-job-1",
        feed_source_id="abusech",
        trigger_type="manual",
        idempotency_key="abusech:manual:test",
        status="queued",
        result_json={},
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(job)
    test_db.commit()

    resp = admin_client.post("/admin/sync-jobs/cancel-job-1/cancel", data={"csrf_token": admin_csrf_token}, follow_redirects=True)
    assert resp.status_code == 200
    refreshed = test_db.query(SyncJob).filter(SyncJob.job_id == "cancel-job-1").one()
    assert refreshed.status == "cancelled"
    audit = test_db.query(AuditLog).filter(AuditLog.action == "admin_sync_job_cancel").order_by(AuditLog.id.desc()).first()
    assert audit is not None
    assert audit.user_id == "admin"
    assert (audit.metadata_ or {}).get("job_id") == "cancel-job-1"


def test_sync_job_retry_endpoint_enqueues_new_job(admin_client, admin_csrf_token, sample_indicators, test_db):
    # Ensure default feeds exist.
    assert admin_client.get("/admin").status_code == 200
    failed = SyncJob(
        job_id="failed-job-1",
        feed_source_id="abusech",
        trigger_type="manual",
        idempotency_key="abusech:manual:failed1",
        status="failed",
        error="boom",
        result_json={},
        created_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    test_db.add(failed)
    test_db.commit()

    resp = admin_client.post("/admin/sync-jobs/failed-job-1/retry", data={"csrf_token": admin_csrf_token}, follow_redirects=True)
    assert resp.status_code == 200
    queued = (
        test_db.query(SyncJob)
        .filter(SyncJob.feed_source_id == "abusech", SyncJob.trigger_type == "retry")
        .all()
    )
    assert queued
    audit = test_db.query(AuditLog).filter(AuditLog.action == "admin_sync_job_retry").order_by(AuditLog.id.desc()).first()
    assert audit is not None
    assert audit.user_id == "admin"
    assert (audit.metadata_ or {}).get("job_id") == "failed-job-1"


def test_admin_add_feed_records_audit_entry(admin_client, admin_csrf_token, sample_indicators, test_db):
    response = admin_client.post(
        "/admin/feed/new",
        data={
            "source_id": "ref-feed",
            "display_name": "Ref Feed",
            "source_type": "misp",
            "base_url": "https://misp.example.test",
            "auth_type": "api_key",
            "schedule_cron": "*/30 * * * *",
            "enabled": "on",
            "csrf_token": admin_csrf_token,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    audit = test_db.query(AuditLog).filter(AuditLog.action == "admin_feed_add").order_by(AuditLog.id.desc()).first()
    assert audit is not None
    assert audit.user_id == "admin"
    assert (audit.metadata_ or {}).get("source") == "ref-feed"


def test_admin_feed_configure_save_records_audit_entry(admin_client, admin_csrf_token, sample_indicators, test_db):
    assert admin_client.get("/admin").status_code == 200
    response = admin_client.post(
        "/admin/feed/abusech/configure",
        data={
            "display_name": "abuse.ch bundle",
            "schedule_cron": "*/5 * * * *",
            "api_key": "secret-token",
            "threatfox_enabled": "1",
            "urlhaus_enabled": "1",
            "feodotracker_enabled": "1",
            "yaraify_enabled": "1",
            "yaraify_identifier": "task-123",
            "hunting_fplist_enabled": "1",
            "csrf_token": admin_csrf_token,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    audit = test_db.query(AuditLog).filter(AuditLog.action == "admin_feed_configure_save").order_by(AuditLog.id.desc()).first()
    assert audit is not None
    assert audit.user_id == "admin"
    assert (audit.metadata_ or {}).get("source") == "abusech"
