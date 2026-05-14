from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


class TestCLIHelpers:

    def test_parse_time_date_only(self):
        from app.cli import _parse_time
        dt = _parse_time("2024-01-15")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.tzinfo is not None

    def test_parse_time_iso_datetime(self):
        from app.cli import _parse_time
        dt = _parse_time("2024-06-01T12:00:00")
        assert dt.year == 2024
        assert dt.hour == 12

    def test_parse_time_iso_with_z(self):
        from app.cli import _parse_time
        dt = _parse_time("2024-06-01T12:00:00Z")
        assert dt.tzinfo is not None

    def test_parse_time_iso_with_offset(self):
        from app.cli import _parse_time
        dt = _parse_time("2024-06-01T14:00:00+02:00")
        assert dt.tzinfo is not None

    def test_parse_time_empty_raises(self):
        from app.cli import _parse_time
        with pytest.raises(ValueError):
            _parse_time("")

    def test_load_config_file_json(self, tmp_path):
        from app.cli import _load_config_file
        f = tmp_path / "cfg.json"
        f.write_text('{"key": "value", "count": 42}')
        result = _load_config_file(str(f))
        assert result["key"] == "value"
        assert result["count"] == 42

    def test_load_config_file_env_style(self, tmp_path):
        from app.cli import _load_config_file
        f = tmp_path / "cfg.env"
        f.write_text("KEY=value\n# comment\nOTHER_KEY=other\n")
        result = _load_config_file(str(f))
        assert result["KEY"] == "value"
        assert result["OTHER_KEY"] == "other"
        assert "# comment" not in result

    def test_load_config_file_not_found_raises(self):
        from app.cli import _load_config_file
        with pytest.raises(FileNotFoundError):
            _load_config_file("/nonexistent/path/file.json")

    def test_load_config_file_empty_returns_empty(self, tmp_path):
        from app.cli import _load_config_file
        f = tmp_path / "empty.env"
        f.write_text("")
        result = _load_config_file(str(f))
        assert result == {}

    def test_merge_list_comma_separated(self):
        from app.cli import _merge_list
        result = _merge_list("a,b,c", None)
        assert result == ["a", "b", "c"]

    def test_merge_list_repeated_args(self):
        from app.cli import _merge_list
        result = _merge_list(None, ["x", "y"])
        assert result == ["x", "y"]

    def test_merge_list_dedup(self):
        from app.cli import _merge_list
        result = _merge_list("a,A,b", ["B", "c"])
        assert len(result) == 3  # a, b, c (case-insensitive dedup)

    def test_merge_list_empty(self):
        from app.cli import _merge_list
        result = _merge_list(None, None)
        assert result == []

    def test_main_no_tags_raises_systemexit(self):
        from app.cli import main
        with pytest.raises(SystemExit, match="No tags"):
            main(["fetch", "--data-source", "bazaar"])

    def test_main_since_after_until_raises(self):
        from app.cli import main
        with pytest.raises(SystemExit):
            main(["fetch", "--data-source", "bazaar", "--tags", "malware",
                  "--since", "2024-02-01", "--until", "2024-01-01"])

    def test_main_no_db_url_raises(self):
        from app.cli import main
        env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(SystemExit, match="DATABASE_URL"):
                main(["fetch", "--data-source", "bazaar", "--tags", "malware"])

    def test_main_dry_run_bazaar(self):
        from app.cli import main
        mock_rows = [{"ioc_value": "1.2.3.4", "ioc_type": "ip", "source": "bazaar"}]
        with patch("app.cli.fetch_malwarebazaar_by_tags", return_value=iter(mock_rows)):
            result = main(["fetch", "--data-source", "bazaar", "--tags", "malware", "--dry-run"])
        assert result == 0

    def test_main_dry_run_mwdb(self):
        from app.cli import main
        mock_rows = [{"ioc_value": "evil.com", "ioc_type": "domain", "source": "mwdb"}]
        with patch("app.cli.fetch_mwdb_by_tags", return_value=iter(mock_rows)):
            result = main(["fetch", "--data-source", "mwdb", "--tags", "apt", "--dry-run"])
        assert result == 0

    def test_main_with_config_file(self, tmp_path):
        from app.cli import main
        cfg = tmp_path / "test.env"
        cfg.write_text("TAGS=malware\n")
        mock_rows: list = []
        with patch("app.cli.fetch_malwarebazaar_by_tags", return_value=iter(mock_rows)):
            result = main(["--config-file", str(cfg), "fetch", "--data-source", "bazaar", "--dry-run"])
        assert result == 0

    def test_main_dry_run_with_since_until(self):
        from app.cli import main
        mock_rows: list = []
        with patch("app.cli.fetch_malwarebazaar_by_tags", return_value=iter(mock_rows)):
            result = main([
                "fetch", "--data-source", "bazaar",
                "--tags", "malware",
                "--since", "2024-01-01",
                "--until", "2024-12-31",
                "--dry-run",
            ])
        assert result == 0

    def test_upsert_iocs_basic(self):
        from app.cli import _upsert_iocs
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value.__enter__ = lambda s: mock_cur
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        rows = [{"ioc_value": "1.2.3.4", "ioc_type": "ip", "source": "test",
                 "source_ref": None, "first_seen": datetime.now(timezone.utc),
                 "last_seen": datetime.now(timezone.utc), "confidence": 80,
                 "tlp": "GREEN", "is_active": True, "tags": [], "comments": None, "metadata": {}}]
        ins, upd = _upsert_iocs(mock_conn, rows)
        assert ins == 1
        assert upd == 0
        mock_conn.commit.assert_called_once()
