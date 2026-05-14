from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestWebuiUtils:

    def test_split_csv_none_returns_none(self):
        from app.webui import _split_csv
        assert _split_csv(None) is None

    def test_split_csv_empty_returns_none(self):
        from app.webui import _split_csv
        result = _split_csv("")
        assert result is None

    def test_split_csv_single_value(self):
        from app.webui import _split_csv
        result = _split_csv("ip")
        assert result == ["ip"]

    def test_split_csv_multiple_values(self):
        from app.webui import _split_csv
        result = _split_csv("ip,domain,hash")
        assert result == ["ip", "domain", "hash"]

    def test_active_only_true_by_default(self):
        from app.webui import _active_only
        assert _active_only("1") is True
        assert _active_only("true") is True

    def test_active_only_false_values(self):
        from app.webui import _active_only
        assert _active_only("0") is False
        assert _active_only("false") is False
        assert _active_only("no") is False
        assert _active_only("off") is False

    def test_active_only_none_returns_true(self):
        from app.webui import _active_only
        assert _active_only(None) is True
