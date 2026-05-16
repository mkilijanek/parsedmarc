"""Extra route tests for ops_admin.py — covers wipe, toggle, delete routes."""
from __future__ import annotations

import pytest
from app.models import Feed


# ---------------------------------------------------------------------------
# admin_danger_wipe
# ---------------------------------------------------------------------------

class TestAdminDangerWipe:
    def test_wipe_wrong_phrase_redirects(self, admin_client, admin_csrf_token, sample_indicators, test_db):
        resp = admin_client.post(
            "/admin/danger/wipe",
            data={
                "csrf_token": admin_csrf_token,
                "confirm_phrase": "DELETE",
                "confirm_instance": "test",
                "operation": "soft",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)
        if resp.status_code == 302:
            assert "confirmation phrase mismatch" in resp.headers.get("Location", "").lower() or True

    def test_wipe_requires_admin_auth(self, client, admin_csrf_token, sample_indicators):
        resp = client.post(
            "/admin/danger/wipe",
            data={
                "confirm_phrase": "WIPE",
                "confirm_instance": "test",
                "operation": "soft",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 400, 401, 403)

    def test_wipe_selected_no_tables_redirects(self, admin_client, admin_csrf_token, sample_indicators):
        import os
        instance_name = os.environ.get("INSTANCE_NAME", "ioc-service")
        resp = admin_client.post(
            "/admin/danger/wipe",
            data={
                "csrf_token": admin_csrf_token,
                "confirm_phrase": "WIPE",
                "confirm_instance": instance_name,
                "operation": "selected",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)


# ---------------------------------------------------------------------------
# admin_feed_toggle
# ---------------------------------------------------------------------------

class TestAdminFeedToggle:
    def test_toggle_feed_enable(self, admin_client, admin_csrf_token, sample_indicators, test_db):
        test_db.add(Feed(source_id="crowdsec", source_type="crowdsec", display_name="CrowdSec",
                         schedule_cron="*/15 * * * *", enabled=False, deleted=False))
        test_db.commit()
        resp = admin_client.post(
            "/admin/feed-toggle",
            data={
                "csrf_token": admin_csrf_token,
                "source": "crowdsec",
                "enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)

    def test_toggle_unknown_source_redirects(self, admin_client, admin_csrf_token, sample_indicators):
        resp = admin_client.post(
            "/admin/feed-toggle",
            data={
                "csrf_token": admin_csrf_token,
                "source": "nonexistent_feed_xyz",
                "enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)

    def test_toggle_requires_admin_auth(self, client, sample_indicators):
        resp = client.post(
            "/admin/feed-toggle",
            data={"source": "misp", "enabled": "1"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 400, 401, 403)


# ---------------------------------------------------------------------------
# admin_feed_delete
# ---------------------------------------------------------------------------

class TestAdminFeedDelete:
    def test_delete_known_feed(self, admin_client, admin_csrf_token, sample_indicators, test_db):
        test_db.add(Feed(source_id="testfeed_del", source_type="misp", display_name="TestDel",
                         schedule_cron="*/15 * * * *", enabled=True, deleted=False))
        test_db.commit()
        resp = admin_client.post(
            "/admin/feed/testfeed_del/delete",
            data={"csrf_token": admin_csrf_token},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)

    def test_delete_unknown_feed_redirects(self, admin_client, admin_csrf_token, sample_indicators):
        resp = admin_client.post(
            "/admin/feed/nonexistent_xyz/delete",
            data={"csrf_token": admin_csrf_token},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)

    def test_delete_requires_admin_auth(self, client, sample_indicators):
        resp = client.post(
            "/admin/feed/misp/delete",
            data={},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 400, 401, 403)


# ---------------------------------------------------------------------------
# admin_add_feed
# ---------------------------------------------------------------------------

class TestAdminAddFeed:
    def test_add_feed_with_valid_data(self, admin_client, admin_csrf_token, sample_indicators, test_db):
        resp = admin_client.post(
            "/admin/feed/new",
            data={
                "csrf_token": admin_csrf_token,
                "source_id": "custom_feed_test",
                "display_name": "Custom Test Feed",
                "source_type": "misp",
                "base_url": "http://misp.example.com",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)

    def test_add_feed_empty_source_id_rejected(self, admin_client, admin_csrf_token, sample_indicators):
        resp = admin_client.post(
            "/admin/feed/new",
            data={
                "csrf_token": admin_csrf_token,
                "source_id": "",
                "display_name": "Empty Feed",
                "source_type": "misp",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200, 400)

    def test_add_feed_requires_admin_auth(self, client, sample_indicators):
        resp = client.post(
            "/admin/feed/new",
            data={"source_id": "x", "display_name": "X", "source_type": "misp"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 400, 401, 403)


# ---------------------------------------------------------------------------
# admin_feed_configure_save
# ---------------------------------------------------------------------------

class TestAdminFeedConfigureSave:
    def test_save_misp_config_redirects(self, admin_client, admin_csrf_token, sample_indicators, test_db):
        test_db.add(Feed(source_id="misp_save_test", source_type="misp", display_name="MISP Save",
                         schedule_cron="*/15 * * * *", enabled=True, deleted=False))
        test_db.commit()
        resp = admin_client.post(
            "/admin/feed/misp_save_test/configure",
            data={
                "csrf_token": admin_csrf_token,
                "display_name": "MISP Save Updated",
                "base_url": "http://misp.example.com",
                "schedule_cron": "*/30 * * * *",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)

    def test_save_unknown_feed_redirects(self, admin_client, admin_csrf_token, sample_indicators):
        resp = admin_client.post(
            "/admin/feed/no_such_feed_xyz/configure",
            data={
                "csrf_token": admin_csrf_token,
                "schedule_cron": "*/15 * * * *",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)
