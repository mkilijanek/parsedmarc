# Operations Runbook (M15)

Status: updated for `1.1.x` (2026-02-26).

## Scope

Operational playbook for the IOC service in production-like environments with shared resources.

## Quick Triage

1. Check health and error ratio:
```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/metrics | rg -n "http_requests_total|db_query_duration_seconds|cache_access_total"
```
2. Check container status:
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
docker compose -f docker-compose-release.yml run --rm migrate
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
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/indicators?limit=10
```
