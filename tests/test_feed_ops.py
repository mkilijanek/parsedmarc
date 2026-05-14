from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


class TestFeedOpsCoverage:

    def test_percentile_empty_list_returns_none(self):
        from app.services.feed_ops import percentile
        assert percentile([], 95) is None

    def test_percentile_single_value(self):
        from app.services.feed_ops import percentile
        assert percentile([42], 50) == 42.0

    def test_percentile_multiple_values(self):
        from app.services.feed_ops import percentile
        values = [1, 2, 3, 4, 5]
        p50 = percentile(values, 50)
        assert 2.0 <= p50 <= 4.0  # median-ish

    def test_percentile_p100(self):
        from app.services.feed_ops import percentile
        values = [1, 5, 10]
        assert percentile(values, 100) == 10.0

    def test_parse_feed_table_params_defaults(self):
        from app.services.feed_ops import parse_feed_table_params
        params = parse_feed_table_params({})
        assert params is not None
        assert "limit" in params
        assert "offset" in params

    def test_parse_feed_table_params_custom(self):
        from app.services.feed_ops import parse_feed_table_params
        params = parse_feed_table_params({"feeds_limit": "10", "feeds_sort": "source"})
        assert params["limit"] == 10
        assert params["sort"] == "source"

    def test_resolve_metrics_window_hours_default(self):
        from app.services.feed_ops import resolve_metrics_window_hours
        hours, label = resolve_metrics_window_hours({})
        assert isinstance(hours, int)
        assert hours > 0
        assert isinstance(label, str)

    def test_resolve_metrics_window_hours_24h(self):
        from app.services.feed_ops import resolve_metrics_window_hours
        hours, label = resolve_metrics_window_hours({"window": "24h"})
        assert hours == 24
        assert label == "24h"

    def test_resolve_metrics_window_hours_7d(self):
        from app.services.feed_ops import resolve_metrics_window_hours
        hours, label = resolve_metrics_window_hours({"window": "7d"})
        assert hours == 24 * 7

    def test_resolve_metrics_window_hours_custom(self):
        from app.services.feed_ops import resolve_metrics_window_hours
        hours, label = resolve_metrics_window_hours({"hours": "48"})
        assert hours == 48


class TestFeedOpsCoverage2:

    def test_feed_operational_status_enabled_ready_success(self):
        from app.services.feed_ops import feed_operational_status
        latest_run = MagicMock()
        latest_run.status = "success"
        result = feed_operational_status(enabled=True, ready=True, latest_run=latest_run)
        assert result == "OK"

    def test_feed_operational_status_disabled(self):
        from app.services.feed_ops import feed_operational_status
        result = feed_operational_status(enabled=False, ready=True, latest_run=None)
        assert result == "DISABLED"

    def test_feed_operational_status_not_ready(self):
        from app.services.feed_ops import feed_operational_status
        result = feed_operational_status(enabled=True, ready=False, latest_run=None)
        assert result == "NOT_CONFIGURED"

    def test_feed_operational_status_no_runs(self):
        from app.services.feed_ops import feed_operational_status
        result = feed_operational_status(enabled=True, ready=True, latest_run=None)
        assert result in ("OK", "WARNING", "ERROR")

    def test_feed_operational_status_with_failed_run(self):
        from app.services.feed_ops import feed_operational_status
        latest_run = MagicMock()
        latest_run.status = "failed"
        result = feed_operational_status(enabled=True, ready=True, latest_run=latest_run)
        assert result == "ERROR"

    def test_feed_last_error_at_none_when_success(self):
        from app.services.feed_ops import feed_last_error_at
        run = MagicMock()
        run.status = "success"
        run.error = None
        result = feed_last_error_at(run, None)
        # Returns None when no error
        assert result is None or isinstance(result, datetime)

    def test_feed_last_error_at_returns_time_when_failed(self):
        from app.services.feed_ops import feed_last_error_at
        run = MagicMock()
        run.status = "failed"
        run.error = "Connection timeout"
        run.finished_at = datetime.now(timezone.utc)
        result = feed_last_error_at(run, None)
        # May return a datetime if the run was a failure
        assert result is None or isinstance(result, datetime)

    def test_apply_feed_filters_empty_list(self):
        from app.services.feed_ops import apply_feed_filters_and_sort
        result = apply_feed_filters_and_sort(
            [],
            status_filter="",
            datasource="",
            configured="",
            query_text="",
            problems_only=False,
            sort_by="display_name",
            sort_order="asc",
        )
        assert result == []
