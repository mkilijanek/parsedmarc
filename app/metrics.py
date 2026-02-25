from __future__ import annotations

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

request_count = Counter('http_requests_total', 'Total HTTP requests', ['method','endpoint','http_status'])
request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration', ['endpoint'])
active_indicators = Gauge('active_indicators_total', 'Total active indicators')
feed_update_errors = Counter('feed_update_errors_total', 'Feed update errors', ['source'])
feed_fetch_total = Counter('feed_fetch_total', 'Feed fetch attempts', ['source', 'status'])
feed_fetched_rows_total = Counter('feed_fetched_rows_total', 'Fetched rows per feed', ['source'])
feed_deactivated_rows_total = Counter('feed_deactivated_rows_total', 'Deactivated rows per feed', ['source'])
feed_update_duration_seconds = Histogram('feed_update_duration_seconds', 'Feed update duration', ['source'])
quality_normalized_total = Counter('quality_normalized_total', 'Rows normalized by quality pipeline', ['source'])
quality_dropped_invalid_total = Counter('quality_dropped_invalid_total', 'Rows dropped by quality pipeline', ['source', 'reason'])
quality_dedup_merged_total = Counter('quality_dedup_merged_total', 'Rows merged during batch deduplication', ['source'])
correlation_queries_total = Counter('correlation_queries_total', 'Correlation API queries', ['status'])
correlation_query_duration_seconds = Histogram('correlation_query_duration_seconds', 'Correlation query duration')
correlation_groups_returned_total = Counter('correlation_groups_returned_total', 'Correlation groups returned')
