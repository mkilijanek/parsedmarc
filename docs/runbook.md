# Operations Runbook

Status: updated for `1.9.x` (2026-05-19).

## Scope

Operational playbook for the IOC service in production-like environments with shared resources. Covers DBCircuitBreaker monitoring, Dead Letter Queue operations, SSE stream troubleshooting, and cache warming verification added in `1.8.0`, plus `1.8.1` hardening corrections.

## Quick Triage

1. Check liveness and readiness:
```bash
curl -s http://127.0.0.1:8080/healthz    # liveness: always fast, no external calls
curl -s http://127.0.0.1:8080/readyz     # readiness: DB + Redis only
curl -s http://127.0.0.1:8080/health     # full health including DBCircuitBreaker state
```
2. Check DBCircuitBreaker state (1.8.0):
```bash
# Requires authenticated admin session if called over HTTP.
# For unauthenticated triage, prefer /health and inspect db_circuit_state.
curl -s http://127.0.0.1:8080/health | jq '.db_circuit_state'
```
If `state` is `"open"`, the circuit breaker has tripped — see incident section below.
3. Check job backlog (queued/running sync jobs and DLQ):
```bash
curl -s http://127.0.0.1:8080/metrics | grep -E "sync_jobs|dlq"
```
If `sync_jobs_queued` stays > 10 for more than a few minutes, restart the worker.
4. Check container status:
```bash
docker compose ps
docker compose logs --tail=200 app worker redis postgres
```
5. Validate current resource limits:
```bash
docker inspect <app-container-id> --format 'cpus={{.HostConfig.NanoCpus}} mem={{.HostConfig.Memory}}'
```

## Incident: DBCircuitBreaker Open (1.8.0)

Symptoms:
- `/health` reports `db_circuit: "open"` with `failures >= 5`
- `/admin/api/db-circuit` returns `{"state": "open", ...}`
- Most endpoints return 503 with circuit-breaker messaging

Actions:
1. Confirm circuit state:
```bash
curl -s http://127.0.0.1:8080/health | jq '.db_circuit_state'
```
2. Check PostgreSQL health:
```bash
docker compose ps postgres
docker compose logs --tail=200 postgres
docker compose exec postgres pg_isready -U threatfeed
```
3. Once PostgreSQL is healthy, the circuit breaker will automatically transition to `half_open` after the cooldown period (default 30 s), allowing one probe request.
4. If the probe succeeds, the circuit closes and normal operation resumes. No manual reset is needed.
5. Monitor recovery:
```bash
watch -n 2 'curl -s http://127.0.0.1:8080/health | jq .db_circuit_state.state'
```

Thresholds (configurable via env):
- `DB_CIRCUIT_FAIL_THRESHOLD` (default 5)
- `DB_CIRCUIT_COOLDOWN_S` (default 30)

## Incident: Dead Letter Queue Accumulation (1.8.0)

Symptoms:
- `dlq_size` metric grows over time
- Sync jobs fail permanently and land in the DLQ

Actions:
1. Inspect DLQ inventory:
```bash
# Requires authenticated admin session if called directly over HTTP.
curl -s http://127.0.0.1:8080/admin/api/dead-letter-jobs | jq .
```
2. Review job details (feed, error, timestamp, retry count) to identify recurring failure patterns.
3. For transient upstream issues that have resolved, manually requeue:
```bash
# Requires authenticated admin session + CSRF token.
curl -X POST http://127.0.0.1:8080/admin/api/dead-letter-jobs/<job_id>/requeue \
  -H "Content-Type: application/json"
```
4. If DLQ grows rapidly (> 10 jobs/hour), investigate the affected feed:
   - Check feed credentials are valid.
   - Verify upstream API is reachable.
   - Test feed connection from the admin UI.
5. The requeue action creates a fresh sync job and removes the entry from the DLQ. Each requeue is audit-logged.

## Incident: Redis Degraded/Down

Symptoms:
- Cache hit ratio drops
- `cache_access_total{status="error"}` grows
- Cache warming logs show connection errors

Actions:
1. Confirm Redis state:
```bash
docker compose ps redis
docker compose logs --tail=200 redis
```
2. Keep service online (fallback already implemented for key endpoints).
3. Restart Redis:
```bash
docker compose restart redis
```
4. Verify cache warming resumes:
```bash
docker compose logs --tail=50 worker | grep "cache_warm"
```

## Incident: SSE Stream Interruption (1.8.0)

Symptoms:
- `/api/events` clients report connection drops or `503 sse_requires_non_sync_workers`
- No heartbeat events received

Actions:
1. Verify SSE endpoint is reachable:
```bash
curl -s -N -H "Accept: text/event-stream" http://127.0.0.1:8080/api/events &
sleep 3; kill %1
```
Expected events: `heartbeat`, `active_indicator_count`, `sync_status`, `feed_health`.
2. Check app logs for SSE-related errors:
```bash
docker compose logs --tail=200 app | grep -i "sse\|event-stream"
```
3. If no events are emitted, restart the app container:
```bash
docker compose restart app
```
4. Verify clients reconnect with exponential backoff (clients should implement reconnection logic).

## Incident: DB Slow / Pool Saturation

Symptoms:
- p95/p99 latency increase
- `db_query_duration_seconds` grows
- DBCircuitBreaker may open if failures accumulate

Actions:
1. Check DB health and active queries.
2. Check DBCircuitBreaker state (it may still be open during cooldown, then briefly half-open for a single probe):
```bash
curl -s http://127.0.0.1:8080/health | jq '.db_circuit_state'
```
3. Temporarily lower expensive traffic pressure (smaller export limits or stricter edge limits).
4. Tune:
- `DB_POOL_SIZE`
- `DB_MAX_OVERFLOW`
- `WORKERS`

## Incident: Upstream Source Outage

Symptoms:
- Worker errors for source updates
- Stale feed stats
- DLQ accumulation for affected feed

Actions:
1. Verify API key/network/certs.
2. Keep ingestion running for unaffected sources.
3. Track outage in logs and feed stats.
4. Review affected jobs in DLQ and only requeue once the upstream is verified healthy.

## Cache Warming Verification (1.8.0)

Check that the scheduler is pre-populating Redis cache for dashboard widgets:

```bash
# Check active indicator type counts in Redis
docker compose exec redis redis-cli KEYS "cache:warm:*"

# Check worker logs for warming activity
docker compose logs --tail=100 worker | grep -i "warming\|cache_warm"

# Verify dashboard widgets are served from cache
curl -s http://127.0.0.1:8080/metrics | grep cache_warm
```

If cache warming is not running, the scheduler may be stuck — restart the worker.

## SSE `/api/events` Field Reference (1.8.0)

| Event type | Fields | Frequency |
|---|---|---|
| `heartbeat` | `timestamp` | every 30 s |
| `active_indicator_count` | `total`, `by_type` | on change or every 60 s |
| `sync_status` | `feed_name`, `status`, `last_sync`, `next_sync` | on sync completion |
| `feed_health` | `feed_name`, `healthy`, `last_error` | every 120 s |

## Release Gate

Before merge/release:
```bash
# Run CI gate locally
pytest tests/ -v --cov=app --cov-report=term-missing
ruff check app/ tests/
mypy app/
bandit -r app --severity-level high --confidence-level medium
pip-audit -r requirements.txt
```

Recommended thresholds:
- All tests pass
- Lint and type checks pass
- No high-severity SAST or dependency findings

## Audit Integrity Verification (compliance-1.0)

Verify the HMAC-SHA256 audit log hash chain:

```bash
# Current implementation exposes this endpoint without admin auth.
# Treat it as internal-only and protect it at the reverse proxy.
curl -s http://127.0.0.1:8080/admin/audit/verify | jq .
```

If `valid` is `false`, investigate potential audit log tampering. Run the detailed report:

```bash
curl -s http://127.0.0.1:8080/admin/audit/report | jq .
```

Schedule automated verification via cron or the scheduler (runs every 24 h by default).

## Upgrade Procedure

Always run migrations before app/worker restart:

```bash
docker compose -f docker-compose-release.yml pull
docker compose -f docker-compose-release.yml up -d app worker
```

Post-upgrade verification:

```bash
docker compose logs --tail=200 app worker | grep -E "sync_job_enqueued|feed_sync_completed|circuit_closed|cache_warm_complete"
```

`app` and `worker` execute database upgrade automatically on start (`AUTO_MIGRATE_ON_START=true` by default).

## Rollback

1. Deploy previous stable image/tag.
2. Restart app and worker.
3. Re-run smoke checks:
```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/health | jq .db_circuit_state.state
curl -fsS http://127.0.0.1:8080/indicators?limit=10
```

## Backup

Database backup with encryption (compliance-1.0):

```bash
bash scripts/backup.sh
```

Manual backup:
```bash
docker compose exec postgres pg_dump -U threatfeed threatfeed | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

## F5 / Load Balancer Health Monitor

Configure F5 (or any L4/L7 load balancer) to use `/healthz`:
- **Monitor path:** `/healthz`
- **Expected response:** `200 OK` with body `{"status":"ok"}`
- **Do NOT use `/health`** for liveness — it checks DB/Redis on every call.

`/readyz` is appropriate for load-balancer readiness (removes node when DB/Redis are unreachable).

For full F5 Send String configuration, SELinux setup, and Nginx upstream troubleshooting, see:
[docs/troubleshooting/502-bad-gateway.md](troubleshooting/502-bad-gateway.md)
