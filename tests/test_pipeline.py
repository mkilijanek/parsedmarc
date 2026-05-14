from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestAdapterPipelineCoverage:

    def test_pipeline_db_retry_success(self):
        from app.adapters.pipeline import db_retry
        call_count = [0]

        def op():
            call_count[0] += 1
            return "ok"

        result = db_retry(op, attempts=3, base_delay_s=0.0)
        assert result == "ok"
        assert call_count[0] == 1

    def test_pipeline_db_retry_retries_on_db_error(self):
        from sqlalchemy.exc import OperationalError
        from app.adapters.pipeline import db_retry
        call_count = [0]

        def op():
            call_count[0] += 1
            if call_count[0] < 3:
                raise OperationalError("transient", None, None)
            return "recovered"

        result = db_retry(op, attempts=3, base_delay_s=0.0)
        assert result == "recovered"
        assert call_count[0] == 3

    def test_pipeline_db_retry_raises_after_all_attempts(self):
        from sqlalchemy.exc import OperationalError
        from app.adapters.pipeline import db_retry

        def op():
            raise OperationalError("permanent", None, None)

        with pytest.raises(OperationalError):
            db_retry(op, attempts=3, base_delay_s=0.0)

    def test_pipeline_invalidate_feed_caches(self):
        from app.adapters.pipeline import invalidate_feed_caches
        mock_redis = MagicMock()
        mock_redis.scan.return_value = (0, [])
        with patch("app.adapters.pipeline.get_redis", return_value=mock_redis):
            invalidate_feed_caches()

    def test_pipeline_prepare_items_empty(self):
        from app.adapters.pipeline import _prepare_items
        result = _prepare_items("test_source", ())
        assert isinstance(result, list)
        assert result == []
