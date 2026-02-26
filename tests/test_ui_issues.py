from __future__ import annotations


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


def test_dark_mode_toggle_script_present(client, sample_indicators):
    response = client.get("/indicators")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "localStorage.setItem(themeKey, next);" in html
    assert "id=\"themeToggleGlobal\"" in html


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


def test_admin_logs_tab_and_api(client, sample_indicators):
    page = client.get("/logs")
    assert page.status_code == 200
    api = client.get("/api/logs?limit=10")
    assert api.status_code == 200
    data = api.get_json()
    assert "items" in data
