from __future__ import annotations

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

request_count = Counter('http_requests_total', 'Total HTTP requests', ['method','endpoint','http_status'])
request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration', ['endpoint'])
active_indicators = Gauge('active_indicators_total', 'Total active indicators')
feed_update_errors = Counter('feed_update_errors_total', 'Feed update errors', ['source'])
