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

# ---------------------------------------------------------------------------
# _as_delimited
# ---------------------------------------------------------------------------

class TestAsDelimited:
    def _make_row(self, **kwargs):
        from app.webui import UnifiedRow
        defaults = dict(
            id=1, uuid="u1", ioc_value="1.2.3.4", ioc_type="ip",
            source="test", source_ref=None, confidence=80, tlp="white",
            is_active=True, tags=["malware", "c2"], comments=None, metadata=None,
            first_seen="2026-01-01T00:00:00Z", last_seen="2026-05-16T00:00:00Z",
        )
        defaults.update(kwargs)
        return UnifiedRow(**defaults)

    def test_csv_header_present(self):
        from app.webui import _as_delimited
        result = _as_delimited([], ",")
        assert result.startswith("uuid,ioc_value,ioc_type,source")

    def test_csv_row_serialized(self):
        from app.webui import _as_delimited
        row = self._make_row()
        result = _as_delimited([row], ",")
        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert "1.2.3.4" in lines[1]
        assert "ip" in lines[1]

    def test_tsv_uses_tab_separator(self):
        from app.webui import _as_delimited
        row = self._make_row()
        result = _as_delimited([row], "\t")
        assert "\t" in result.split("\n")[0]

    def test_list_field_joined_with_comma(self):
        from app.webui import _as_delimited
        row = self._make_row(tags=["a", "b", "c"])
        result = _as_delimited([row], ",")
        assert "a,b,c" in result

    def test_none_field_becomes_empty_string(self):
        from app.webui import _as_delimited
        row = self._make_row(source_ref=None, comments=None)
        result = _as_delimited([row], ",")
        lines = result.strip().split("\n")
        # None values should produce empty fields (consecutive commas)
        assert ",," in lines[1] or lines[1].endswith(",")

    def test_newlines_in_value_stripped(self):
        from app.webui import _as_delimited
        row = self._make_row(ioc_value="foo\nbar")
        result = _as_delimited([row], ",")
        assert "\n" not in result.split("\n")[1]


# ---------------------------------------------------------------------------
# Route tests via test client (mocking engine.connect)
# ---------------------------------------------------------------------------

def _make_unified_row_mapping(**kwargs):
    """Return a dict that UnifiedRow(**r) can unpack."""
    defaults = dict(
        id=1, uuid="u1", ioc_value="1.2.3.4", ioc_type="ip",
        source="test", source_ref=None, confidence=80, tlp="white",
        is_active=True, tags=[], comments=None, metadata=None,
        first_seen="2026-01-01T00:00:00Z", last_seen="2026-05-16T00:00:00Z",
        platform=None, package_name=None, app_version=None,
        permissions=None, cert_fingerprint=None, store_metadata=None,
    )
    defaults.update(kwargs)
    return defaults


class TestWebuiRoutes:
    """Tests for /ui/* routes — engine.connect() is mocked to avoid real DB."""

    def _mock_engine_empty(self):
        """Patch app.webui.engine so connect() yields no rows."""
        from unittest.mock import MagicMock, patch
        mock_conn = MagicMock()
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.execute.return_value.mappings.return_value = iter([])
        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_conn
        return patch("app.webui.engine", mock_engine)

    def _mock_engine_rows(self, rows):
        from unittest.mock import MagicMock, patch
        mock_conn = MagicMock()
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.execute.return_value.mappings.return_value = iter(rows)
        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_conn
        return patch("app.webui.engine", mock_engine)

    def test_index_returns_200(self, client):
        resp = client.get("/ui/")
        assert resp.status_code == 200

    def test_unified_returns_200_no_results(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/unified")
            assert resp.status_code == 200

    def test_unified_with_query_param(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/unified?q=malware&types=ip&tlps=white")
            assert resp.status_code == 200

    def test_unified_renders_row(self, client):
        row = _make_unified_row_mapping()
        with self._mock_engine_rows([row]):
            resp = client.get("/ui/unified")
            assert resp.status_code == 200
            assert b"1.2.3.4" in resp.data

    def test_mobile_returns_200(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/mobile")
            assert resp.status_code == 200

    def test_mobile_with_query_param(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/mobile?q=test&sources=mwdb")
            assert resp.status_code == 200

    def test_stats_returns_200(self, client):
        from unittest.mock import MagicMock, patch
        mock_conn = MagicMock()
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.execute.return_value.mappings.return_value.all.return_value = []
        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_conn
        with patch("app.webui.engine", mock_engine):
            resp = client.get("/ui/stats")
            assert resp.status_code == 200

    def test_download_unified_csv(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/download/unified.csv")
            assert resp.status_code == 200
            assert b"uuid,ioc_value" in resp.data
            assert resp.headers["Content-Type"].startswith("text/csv")

    def test_download_unified_tsv(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/download/unified.tsv")
            assert resp.status_code == 200
            assert resp.headers["Content-Type"].startswith("text/tab-separated-values")

    def test_download_unified_json(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/download/unified.json")
            assert resp.status_code == 200
            assert resp.headers["Content-Type"].startswith("application/json")

    def test_download_unified_unsupported_format(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/download/unified.xml")
            assert resp.status_code == 400

    def test_download_mobile_csv(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/download/mobile.csv")
            assert resp.status_code == 200

    def test_download_unified_with_row(self, client):
        row = _make_unified_row_mapping()
        with self._mock_engine_rows([row]):
            resp = client.get("/ui/download/unified.csv")
            assert resp.status_code == 200
            assert b"1.2.3.4" in resp.data

    def test_active_only_false_passed_through(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/unified?active_only=0")
            assert resp.status_code == 200

    def test_limit_offset_params(self, client):
        with self._mock_engine_empty():
            resp = client.get("/ui/unified?limit=50&offset=100")
            assert resp.status_code == 200
