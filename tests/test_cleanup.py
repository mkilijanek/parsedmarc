from __future__ import annotations

import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest


class TestCleanupEdgeCases:

    def test_cleanup_export_files_with_custom_extension(self):
        from app.services.cleanup import cleanup_export_files

        with tempfile.TemporaryDirectory() as tmpdir:
            old_file = os.path.join(tmpdir, "old.csv")
            open(old_file, "w").close()
            old_time = time.time() - (25 * 3600)
            os.utime(old_file, (old_time, old_time))
            with patch("app.services.cleanup.Config") as mock_cfg_cls:
                mock_cfg_cls.return_value.EXPORT_JOB_DIR = tmpdir
                deleted = cleanup_export_files(max_age_hours=24)
            assert deleted == 1

    def test_cleanup_export_files_with_new_file_not_deleted(self):
        from app.services.cleanup import cleanup_export_files

        with tempfile.TemporaryDirectory() as tmpdir:
            new_file = os.path.join(tmpdir, "new.json")
            open(new_file, "w").close()
            with patch("app.services.cleanup.Config") as mock_cfg_cls:
                mock_cfg_cls.return_value.EXPORT_JOB_DIR = tmpdir
                deleted = cleanup_export_files(max_age_hours=24)
            assert deleted == 0
            assert os.path.exists(new_file)
