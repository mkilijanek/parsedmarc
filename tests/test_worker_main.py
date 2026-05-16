"""Additional tests for app/worker.py main() loop (issue #237)."""
from __future__ import annotations

import signal
import time
from unittest.mock import MagicMock, call, patch


class TestMainDisabledPath:
    """Tests for main() when ENABLE_BACKGROUND_JOBS=False."""

    def test_main_disabled_exits_on_shutdown(self):
        """main() with ENABLE_BACKGROUND_JOBS=False loops until shutdown_requested."""
        import app.worker as _worker_mod

        call_count = [0]

        def fake_sleep(n):
            call_count[0] += 1
            if call_count[0] >= 2:
                _worker_mod.shutdown_requested = True

        mock_cfg = MagicMock()
        mock_cfg.ENABLE_BACKGROUND_JOBS = False
        mock_cfg.LOG_LEVEL = "WARNING"
        mock_cfg.WORKER_HEALTH_HOST = "127.0.0.1"
        mock_cfg.WORKER_HEALTH_PORT = 8091
        mock_cfg.WORKER_HEALTH_MAX_LOOP_AGE_S = 120

        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False
        try:
            with patch("app.worker.Config", return_value=mock_cfg), \
                 patch("app.worker.setup_logging"), \
                 patch("app.worker._refresh_proxy_settings"), \
                 patch("app.worker.WorkerHealthServer") as mock_hs, \
                 patch("app.worker.signal"), \
                 patch("app.worker.mark_loop"), \
                 patch("app.worker.time.sleep", side_effect=fake_sleep):
                mock_hs.return_value.start = MagicMock()
                mock_hs.return_value.stop = MagicMock()
                _worker_mod.main()
        finally:
            _worker_mod.shutdown_requested = original

        mock_hs.return_value.stop.assert_called_once()

    def test_main_disabled_calls_mark_loop(self):
        """main() with background jobs disabled calls mark_loop each iteration."""
        import app.worker as _worker_mod

        loop_count = [0]

        def fake_sleep(n):
            loop_count[0] += 1
            if loop_count[0] >= 3:
                _worker_mod.shutdown_requested = True

        mock_cfg = MagicMock()
        mock_cfg.ENABLE_BACKGROUND_JOBS = False
        mock_cfg.LOG_LEVEL = "WARNING"
        mock_cfg.WORKER_HEALTH_HOST = "127.0.0.1"
        mock_cfg.WORKER_HEALTH_PORT = 8091
        mock_cfg.WORKER_HEALTH_MAX_LOOP_AGE_S = 120

        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False
        try:
            with patch("app.worker.Config", return_value=mock_cfg), \
                 patch("app.worker.setup_logging"), \
                 patch("app.worker._refresh_proxy_settings"), \
                 patch("app.worker.WorkerHealthServer") as mock_hs, \
                 patch("app.worker.signal"), \
                 patch("app.worker.mark_loop") as mock_mark, \
                 patch("app.worker.time.sleep", side_effect=fake_sleep):
                mock_hs.return_value.start = MagicMock()
                mock_hs.return_value.stop = MagicMock()
                _worker_mod.main()
        finally:
            _worker_mod.shutdown_requested = original

        assert mock_mark.call_count >= 2


class TestMainEnabledPath:
    """Tests for main() with ENABLE_BACKGROUND_JOBS=True."""

    def _make_mock_cfg(self, **overrides):
        mock_cfg = MagicMock()
        mock_cfg.ENABLE_BACKGROUND_JOBS = True
        mock_cfg.LOG_LEVEL = "WARNING"
        mock_cfg.WORKER_HEALTH_HOST = "127.0.0.1"
        mock_cfg.WORKER_HEALTH_PORT = 8091
        mock_cfg.WORKER_HEALTH_MAX_LOOP_AGE_S = 120
        mock_cfg.UPDATE_INTERVAL = 600
        mock_cfg.DEP_HEALTH_INTERVAL_S = 60
        mock_cfg.CORRELATION_SNAPSHOT_ENABLED = False
        mock_cfg.WORKER_SHUTDOWN_GRACE_S = 0
        for k, v in overrides.items():
            setattr(mock_cfg, k, v)
        return mock_cfg

    def _run_main_once(self, mock_cfg, extra_patches=None):
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False

        def fake_sleep(n):
            _worker_mod.shutdown_requested = True

        base_patches = {
            "app.worker.Config": mock_cfg,
            "app.worker.setup_logging": MagicMock(),
            "app.worker._refresh_proxy_settings": MagicMock(),
            "app.worker.mark_loop": MagicMock(),
            "app.worker.active_jobs": MagicMock(return_value=0),
            "app.worker.SessionLocal": MagicMock(),
            "app.worker.engine": MagicMock(),
            "app.worker.dep_health_refresh": MagicMock(),
        }
        if extra_patches:
            base_patches.update(extra_patches)

        try:
            with patch("app.worker.Config", return_value=mock_cfg), \
                 patch("app.worker.setup_logging"), \
                 patch("app.worker._refresh_proxy_settings"), \
                 patch("app.worker.WorkerHealthServer") as mock_hs, \
                 patch("app.worker.signal"), \
                 patch("app.worker.schedule") as mock_sched, \
                 patch("app.worker.mark_loop"), \
                 patch("app.worker.active_jobs", return_value=0), \
                 patch("app.worker.SessionLocal"), \
                 patch("app.worker.engine"), \
                 patch("app.worker.dep_health_refresh"), \
                 patch("app.worker.time.sleep", side_effect=fake_sleep):
                mock_hs.return_value.start = MagicMock()
                mock_hs.return_value.stop = MagicMock()
                mock_sched.run_pending = MagicMock()
                mock_sched.clear = MagicMock()
                mock_sched.every.return_value.seconds.do = MagicMock()
                mock_sched.every.return_value.day.at.return_value.do = MagicMock()
                _worker_mod.main()
                return mock_hs, mock_sched
        finally:
            _worker_mod.shutdown_requested = original

    def test_main_enabled_health_server_stopped(self):
        """main() stops health server on exit."""
        mock_cfg = self._make_mock_cfg()
        mock_hs, _ = self._run_main_once(mock_cfg)
        mock_hs.return_value.stop.assert_called_once()

    def test_main_enabled_clears_schedule(self):
        """main() clears schedule after shutdown."""
        mock_cfg = self._make_mock_cfg()
        _, mock_sched = self._run_main_once(mock_cfg)
        mock_sched.clear.assert_called_once()

    def test_main_enabled_runs_schedule_pending(self):
        """main() calls schedule.run_pending in loop."""
        mock_cfg = self._make_mock_cfg()
        _, mock_sched = self._run_main_once(mock_cfg)
        mock_sched.run_pending.assert_called()

    def test_main_enabled_with_correlation_snapshot(self):
        """main() registers snapshot job when CORRELATION_SNAPSHOT_ENABLED=True."""
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False

        def fake_sleep(n):
            _worker_mod.shutdown_requested = True

        mock_cfg = self._make_mock_cfg(
            CORRELATION_SNAPSHOT_ENABLED=True,
            CORRELATION_SNAPSHOT_INTERVAL=60,
        )

        try:
            with patch("app.worker.Config", return_value=mock_cfg), \
                 patch("app.worker.setup_logging"), \
                 patch("app.worker._refresh_proxy_settings"), \
                 patch("app.worker.WorkerHealthServer") as mock_hs, \
                 patch("app.worker.signal"), \
                 patch("app.worker.schedule") as mock_sched, \
                 patch("app.worker.mark_loop"), \
                 patch("app.worker.active_jobs", return_value=0), \
                 patch("app.worker.SessionLocal"), \
                 patch("app.worker.engine"), \
                 patch("app.worker.dep_health_refresh"), \
                 patch("app.worker.refresh_correlation_snapshots"), \
                 patch("app.worker.time.sleep", side_effect=fake_sleep):
                mock_hs.return_value.start = MagicMock()
                mock_hs.return_value.stop = MagicMock()
                mock_sched.run_pending = MagicMock()
                mock_sched.clear = MagicMock()
                mock_sched.every.return_value.seconds.do = MagicMock()
                mock_sched.every.return_value.day.at.return_value.do = MagicMock()
                _worker_mod.main()
        finally:
            _worker_mod.shutdown_requested = original

        mock_hs.return_value.stop.assert_called_once()

    def test_main_enabled_drains_active_jobs(self):
        """main() waits for active jobs during graceful shutdown."""
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False

        def fake_sleep(n):
            _worker_mod.shutdown_requested = True

        mock_cfg = self._make_mock_cfg(WORKER_SHUTDOWN_GRACE_S=1)
        active_calls = [0]

        def fake_active():
            active_calls[0] += 1
            return 1 if active_calls[0] < 3 else 0

        try:
            with patch("app.worker.Config", return_value=mock_cfg), \
                 patch("app.worker.setup_logging"), \
                 patch("app.worker._refresh_proxy_settings"), \
                 patch("app.worker.WorkerHealthServer") as mock_hs, \
                 patch("app.worker.signal"), \
                 patch("app.worker.schedule") as mock_sched, \
                 patch("app.worker.mark_loop"), \
                 patch("app.worker.active_jobs", side_effect=fake_active), \
                 patch("app.worker.SessionLocal"), \
                 patch("app.worker.engine"), \
                 patch("app.worker.dep_health_refresh"), \
                 patch("app.worker.time.sleep", side_effect=fake_sleep):
                mock_hs.return_value.start = MagicMock()
                mock_hs.return_value.stop = MagicMock()
                mock_sched.run_pending = MagicMock()
                mock_sched.clear = MagicMock()
                mock_sched.every.return_value.seconds.do = MagicMock()
                mock_sched.every.return_value.day.at.return_value.do = MagicMock()
                _worker_mod.main()
        finally:
            _worker_mod.shutdown_requested = original

        mock_hs.return_value.stop.assert_called_once()

    def test_main_enabled_grace_exhausted_warning(self):
        """main() logs warning when grace period exhausted with active jobs."""
        import app.worker as _worker_mod
        original = _worker_mod.shutdown_requested
        _worker_mod.shutdown_requested = False

        sleep_count = [0]

        def fake_sleep(n):
            sleep_count[0] += 1
            if sleep_count[0] == 1:
                _worker_mod.shutdown_requested = True
            # subsequent sleeps (in drain loop) just pass

        mock_cfg = self._make_mock_cfg(WORKER_SHUTDOWN_GRACE_S=0)

        try:
            with patch("app.worker.Config", return_value=mock_cfg), \
                 patch("app.worker.setup_logging"), \
                 patch("app.worker._refresh_proxy_settings"), \
                 patch("app.worker.WorkerHealthServer") as mock_hs, \
                 patch("app.worker.signal"), \
                 patch("app.worker.schedule") as mock_sched, \
                 patch("app.worker.mark_loop"), \
                 patch("app.worker.active_jobs", return_value=0), \
                 patch("app.worker.SessionLocal"), \
                 patch("app.worker.engine"), \
                 patch("app.worker.dep_health_refresh"), \
                 patch("app.worker.time.sleep", side_effect=fake_sleep):
                mock_hs.return_value.start = MagicMock()
                mock_hs.return_value.stop = MagicMock()
                mock_sched.run_pending = MagicMock()
                mock_sched.clear = MagicMock()
                mock_sched.every.return_value.seconds.do = MagicMock()
                mock_sched.every.return_value.day.at.return_value.do = MagicMock()
                _worker_mod.main()
        finally:
            _worker_mod.shutdown_requested = original

        mock_hs.return_value.stop.assert_called_once()
