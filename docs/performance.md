# Performance & SLO

Status: updated for `1.9.x` (2026-05-19).

---

## SLO Targets

Service-level targets for production baseline (mixed API traffic, not health-only):

| Metric | Target |
|--------|--------|
| Availability | ≥ 99.9% successful (non-5xx) responses |
| Error budget | ≤ 1% 5xx rate over any 5-minute window |
| Latency p50 | < 150 ms |
| Latency p95 | < 500 ms |
| Latency p99 | < 1 000 ms |
| Cache error rate | < 1 error/s sustained |

Cached endpoints (`/api/v1/indicators`, `/api/v1/indicators/<fmt>`) should stay well inside p95.

---

## Degradation Behaviour

### Redis unavailable

- `/api/v1/indicators` and export endpoints continue serving from the DB path.
- `cache_access_total{status="error"}` counter increases in Prometheus.
- Warning logs contain `cache_unavailable` or `cache_write_failed`.

### DB slow

- Connection pool (`DB_POOL_SIZE`, `DB_MAX_OVERFLOW`) absorbs short bursts.
- Requests that exceed `DB_POOL_TIMEOUT` (default 30 s) return 503.
- `DB_POOL_RECYCLE` (default 1 800 s) prevents stale connections after failover.

---

## Tuning Reference

| Variable | Default | Guidance |
|----------|---------|----------|
| `WORKERS` | `3` | Formula: `2 × CPU_CORES + 1`. Increase on I/O-heavy workloads. |
| `DB_POOL_SIZE` | `6` | Set to ≥ `WORKERS`. Add headroom for background jobs. |
| `DB_MAX_OVERFLOW` | `4` | Burst capacity above pool; keep low to avoid DB saturation. |
| `GUNICORN_TIMEOUT` | `120` | Raise only for large async exports. |
| `CACHE_TTL` | `300` | Lower for fresher results; raises DB load. |
| `EXPORT_ASYNC_THRESHOLD` | `5000` | Requests above this row count run as async jobs (202 Accepted). |
| `UPDATE_INTERVAL` | `600` | Feed polling interval; lower values increase external API pressure. |

---

## Monitoring

Alert rules and dashboard are in the `monitoring/` directory:

```
monitoring/alerts/slo-alerts.yml     # Prometheus alert rules (error rate, p95, cache)
monitoring/grafana/dashboard.json    # Grafana dashboard template
```

Import `slo-alerts.yml` into your Prometheus `rule_files` and `dashboard.json` into Grafana.

Key metrics to watch:

| Metric | Description |
|--------|-------------|
| `http_request_duration_seconds` | Gunicorn/Flask request latency histogram |
| `http_requests_total{status=~"5.."}` | 5xx error rate |
| `cache_access_total{status}` | Cache hit/miss/error counts |
| `db_pool_size` / `db_pool_checked_out` | Connection pool utilisation |
| `feed_sync_duration_seconds` | Per-feed sync job latency |
| `feed_sync_total{status}` | Feed sync success/failure counts |

---

## Operational Runbook

1. **Detect** — SLO alert fires (error rate, p95 spike, cache error burst). Confirm affected endpoints via `/metrics`.
2. **Isolate** — Check Redis (`PING`, memory, evictions). Check DB latency and active connections (`db_pool_checked_out`).
3. **Mitigate** — Reduce concurrency at edge, scale app replicas, or temporarily raise `EXPORT_ASYNC_THRESHOLD` to push large requests async.
4. **Recover** — Cache error metric returns near zero, p95 drops below target. Verify `/healthz` and `/deps` return healthy.

---

## See Also

- [Configuration](configuration.md) — tuning variables
- [Runbook](runbook.md) — production deployment and incident response
