# Performance & SLO (M12)

## Scope

M12 introduces:
- Benchmark harness for mixed API traffic (`scripts/benchmark_m12.py`)
- SLO-oriented latency/error budget targets
- Degradation handling for cache failures (serve from DB path)
- Alert rules and dashboard templates for ongoing operations

## SLO Targets

Service-level targets for production baseline:

- Availability: `>= 99.9%` successful responses (non-5xx)
- Error budget: `<= 1%` 5xx over 5-minute windows
- Latency:
  - p50 `< 150 ms`
  - p95 `< 500 ms`
  - p99 `< 1000 ms`
- Cache stability: cache access error rate `< 1 req/s` sustained

Notes:
- Targets apply to mixed traffic profile (not only `/health`).
- Endpoint-specific targets can be stricter for cached endpoints.

## Benchmark Harness

Run benchmark against local stack:

```bash
sudo RATE_LIMITS_ENABLED=false docker compose up -d postgres redis app
python scripts/benchmark_m12.py \
  --base-url http://127.0.0.1:8080 \
  --duration 30 \
  --concurrency 64 \
  --output-json /tmp/m12-benchmark.json
```

Default traffic profile:
- `/health`
- `/metrics`
- `/indicators?limit=100&offset=0`
- `/indicators/json?type=ip&limit=500&offset=0`
- `/correlations?min_sources=2&limit=100`

The tool returns:
- total throughput (req/s)
- error rate
- p50/p95/p99 latency
- per-endpoint breakdown

## Docker Cluster Benchmark

To compare single-instance vs scaled app replicas in Docker:

```bash
bash scripts/benchmark_cluster_m12.sh 4 20 64
```

Parameters:
- arg1: number of `app` replicas (default `4`)
- arg2: benchmark duration seconds (default `20`)
- arg3: concurrency (default `64`)

Artifacts:
- `/tmp/m12-baseline.json`
- `/tmp/m12-cluster.json`
- `/tmp/m12-cluster-summary.json`

Implementation notes:
- Uses `docker compose` for shared dependencies (`postgres`, `redis`) and starts app replicas as separate containers in the same Docker network.
- Benchmark traffic is distributed across replica container IPs (client-side balancing).

## Entrypoint Switch

Container supports one-shot benchmark mode:

```bash
docker compose run --rm -e BENCHMARK_BASE_URL=http://app:8080 app --benchmark
```

Supported env vars:
- `BENCHMARK_BASE_URL` (default: `http://app:8080`)
- `BENCHMARK_DURATION` (default: `30`)
- `BENCHMARK_CONCURRENCY` (default: `64`)
- `BENCHMARK_TIMEOUT` (default: `5`)
- `BENCHMARK_OUTPUT_JSON` (default: `/tmp/m12-benchmark.json`)

## Degradation Behavior

If Redis cache is unavailable:
- `/indicators` and `/indicators/<fmt>` continue serving responses from DB path
- cache metric `cache_access_total{status="error"}` increases
- warning logs include `cache_unavailable` or `cache_write_failed`

## Monitoring Artifacts

- Alert rules: `monitoring/alerts/m12-slo-alerts.yml`
- Dashboard template: `monitoring/grafana/m12-dashboard.json`

Both artifacts are intentionally generic and can be imported into existing Prometheus/Grafana deployment.

## Operational Runbook

1. Detect
- Check SLO alerts (error rate, p95 latency, cache error spike).
- Confirm affected endpoints via `/metrics`.

2. Isolate
- Verify Redis health (`PING`, memory pressure, evictions).
- Verify DB latency and active connections.

3. Mitigate
- Reduce worker pressure (temporary rate controls at edge).
- Scale app replicas horizontally.
- Disable expensive traffic patterns or reduce export limits temporarily.

4. Recover
- Ensure cache error metric returns near zero.
- Validate latency returns below p95 target.
- Re-run benchmark profile to confirm recovery.
