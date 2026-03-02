# Operations Runbook (M15)

Status: updated for `1.1.x` (2026-03-01).

## Scope

Operational playbook for the IOC service in production-like environments with shared resources.

## Quick Triage

1. Check liveness and readiness (use `/healthz` for F5/Nginx/Kubernetes monitors — no external calls):
```bash
curl -s http://127.0.0.1:8080/healthz    # liveness: always fast, no external calls
curl -s http://127.0.0.1:8080/readyz     # readiness: DB + Redis only
curl -s http://127.0.0.1:8080/deps       # external dep status snapshot (no live calls)
```
2. Check health and error ratio:
```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/metrics | rg -n "http_requests_total|db_query_duration_seconds|cache_access_total"
```
3. Check job backlog (queued/running sync and export jobs):
```bash
curl -s http://127.0.0.1:8080/metrics | grep -E "sync_jobs|export_jobs"
```
If `sync_jobs_queued` stays > 10 for more than a few minutes, restart the worker.
4. Check container status:
```bash
docker compose ps
docker compose logs --tail=200 app worker redis postgres
```
3. Validate current resource limits:
```bash
docker inspect <app-container-id> --format 'cpus={{.HostConfig.NanoCpus}} mem={{.HostConfig.Memory}}'
```

## Incident: Redis Degraded/Down

Symptoms:
- cache hit ratio drops
- `cache_access_total{status="error"}` grows

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
4. Run chaos smoke:
```bash
bash scripts/m15_chaos_check.sh
```

## Incident: DB Slow / Pool Saturation

Symptoms:
- p95/p99 latency increase
- `db_query_duration_seconds` grows

Actions:
1. Check DB health and active queries.
2. Temporarily lower expensive traffic pressure (smaller export limits or stricter edge limits).
3. Tune:
- `DB_POOL_SIZE`
- `DB_MAX_OVERFLOW`
- `WORKERS`
4. Re-run benchmark gate:
```bash
bash scripts/m15_premerge_gate.sh
```

## Incident: Upstream Source Outage

Symptoms:
- worker errors for source updates
- stale feed stats

Actions:
1. Verify API key/network/certs.
2. Keep ingestion running for unaffected sources.
3. Track outage in logs and feed stats.

#### Circuit Breaker State

Check worker logs for `circuit_open` / `circuit_recovered` events (field: `source`).
Thresholds are controlled by environment variables:
- `MWDB_CIRCUIT_FAIL_THRESHOLD` / `MWDB_CIRCUIT_COOLDOWN_S`
- `MISP_CIRCUIT_FAIL_THRESHOLD` / `MISP_CIRCUIT_COOLDOWN_S`
- `ABUSECH_CIRCUIT_FAIL_THRESHOLD` / `ABUSECH_CIRCUIT_COOLDOWN_S`

The circuit resets automatically after `COOLDOWN_S` seconds. To force an immediate
reset, restart the worker container.

## Release Gate

Before merge/release:
```bash
bash scripts/m15_premerge_gate.sh
```

Recommended thresholds:
- mixed throughput >= 700 req/s
- mixed p95 <= 350 ms
- mixed error rate <= 1%

## Upgrade Procedure (Required Since 1.1.x)

Always run migrations before app/worker restart:

```bash
docker compose -f docker-compose-release.yml pull
docker compose -f docker-compose-release.yml up -d app worker
```

Post-upgrade verification:

```bash
docker compose -f docker-compose-release.yml logs --tail=200 app worker | rg "UndefinedTable|DetachedInstanceError|sync_job_enqueued|feed_sync_completed"
```

## Rollback

1. Deploy previous stable image/tag.
2. Restart app and worker.
3. Re-run smoke checks:
```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/indicators?limit=10
```

## F5 / Load Balancer Health Monitor

Configure F5 (or any L4/L7 load balancer) to use `/healthz`:
- **Monitor path:** `/healthz`
- **Expected response:** `200 OK` with body `{"status":"ok"}`
- **Do NOT use `/health`** for liveness — it checks DB/Redis on every call.

`/readyz` is appropriate for load-balancer readiness (removes node when DB/Redis are unreachable).

For full F5 Send String configuration, SELinux setup, and Nginx upstream troubleshooting, see:
[docs/troubleshooting/502-bad-gateway.md](troubleshooting/502-bad-gateway.md)
