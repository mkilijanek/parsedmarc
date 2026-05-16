"""Tests for app/worker.py — pure-logic functions, no I/O."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# _safe_job
# ---------------------------------------------------------------------------

class TestSafeJob:
    def _make_safe_job(self, name, fn, shutdown=False):
        """Import and call _safe_job with controlled shutdown state."""
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = shutdown
        try:
            wrapped = _worker_mod._safe_job(name, fn)
            return wrapped
        finally:
            _worker_mod.shutdown_requested = original

    def test_calls_fn_on_success(self):
        fn = MagicMock()
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False
        try:
            with patch("app.worker.mark_job_start"), \
                 patch("app.worker.mark_job_success"), \
                 patch("app.worker.mark_job_failure"):
                wrapped = _worker_mod._safe_job("test", fn)
                wrapped()
        finally:
            _worker_mod.shutdown_requested = original
        fn.assert_called_once()

    def test_skips_fn_when_shutdown_requested(self):
        fn = MagicMock()
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = True
        try:
            wrapped = _worker_mod._safe_job("test_skip", fn)
            wrapped()
        finally:
            _worker_mod.shutdown_requested = original
        fn.assert_not_called()

    def test_catches_exception_and_logs(self):
        def bad_fn():
            raise RuntimeError("boom")

        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False
        try:
            with patch("app.worker.mark_job_start"), \
                 patch("app.worker.mark_job_failure") as mock_failure, \
                 patch("app.worker.mark_job_success"):
                wrapped = _worker_mod._safe_job("error_job", bad_fn)
                wrapped()  # should not raise
            mock_failure.assert_called_once_with("error_job", "boom")
        finally:
            _worker_mod.shutdown_requested = original

    def test_marks_job_start_before_fn(self):
        call_order = []
        def fn():
            call_order.append("fn")

        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False
        try:
            with patch("app.worker.mark_job_start", side_effect=lambda n: call_order.append("start")), \
                 patch("app.worker.mark_job_success"), \
                 patch("app.worker.mark_job_failure"):
                wrapped = _worker_mod._safe_job("ordered_job", fn)
                wrapped()
        finally:
            _worker_mod.shutdown_requested = original
        assert call_order == ["start", "fn"]

    def test_marks_job_success_on_completion(self):
        fn = MagicMock()
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False
        try:
            with patch("app.worker.mark_job_start"), \
                 patch("app.worker.mark_job_success") as mock_success, \
                 patch("app.worker.mark_job_failure"):
                wrapped = _worker_mod._safe_job("success_job", fn)
                wrapped()
            mock_success.assert_called_once_with("success_job")
        finally:
            _worker_mod.shutdown_requested = original

    def test_returns_callable(self):
        import app.worker as _worker_mod
        wrapped = _worker_mod._safe_job("check", MagicMock())
        assert callable(wrapped)


# ---------------------------------------------------------------------------
# _signal_handler
# ---------------------------------------------------------------------------

class TestSignalHandler:
    def test_sets_shutdown_requested(self):
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False
        try:
            with patch("app.worker.mark_shutdown_requested"):
                _worker_mod._signal_handler(15, None)
            assert _worker_mod.shutdown_requested is True
        finally:
            _worker_mod.shutdown_requested = original

    def test_calls_mark_shutdown_requested(self):
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False
        try:
            with patch("app.worker.mark_shutdown_requested") as mock_mark:
                _worker_mod._signal_handler(2, None)
            mock_mark.assert_called_once()
        finally:
            _worker_mod.shutdown_requested = original


# ---------------------------------------------------------------------------
# _refresh_proxy_settings
# ---------------------------------------------------------------------------

class TestRefreshProxySettings:
    def test_calls_update_proxy_settings(self):
        import app.worker as _worker_mod
        mock_db = MagicMock()
        mock_db.scalars.return_value.all.return_value = []

        with patch("app.worker.get_session", return_value=mock_db), \
             patch("app.worker.update_proxy_settings_from_mapping") as mock_update:
            _worker_mod._refresh_proxy_settings()

        mock_update.assert_called_once()

    def test_closes_db_on_success(self):
        import app.worker as _worker_mod
        mock_db = MagicMock()
        mock_db.scalars.return_value.all.return_value = []

        with patch("app.worker.get_session", return_value=mock_db), \
             patch("app.worker.update_proxy_settings_from_mapping"):
            _worker_mod._refresh_proxy_settings()

        mock_db.close.assert_called_once()

    def test_closes_db_on_exception(self):
        import app.worker as _worker_mod
        mock_db = MagicMock()
        mock_db.scalars.side_effect = RuntimeError("db error")

        with patch("app.worker.get_session", return_value=mock_db), \
             patch("app.worker.update_proxy_settings_from_mapping"):
            _worker_mod._refresh_proxy_settings()  # must not raise

        mock_db.close.assert_called_once()

    def test_maps_proxy_keys_from_settings(self):
        import app.worker as _worker_mod
        mock_setting = MagicMock()
        mock_setting.key = "proxy.http_url"
        mock_setting.value = "http://proxy:3128"
        mock_db = MagicMock()
        mock_db.scalars.return_value.all.return_value = [mock_setting]

        captured = {}
        def capture_settings(settings):
            captured.update(settings)

        with patch("app.worker.get_session", return_value=mock_db), \
             patch("app.worker.update_proxy_settings_from_mapping", side_effect=capture_settings):
            _worker_mod._refresh_proxy_settings()

        assert captured.get("proxy.http_url") == "http://proxy:3128"
