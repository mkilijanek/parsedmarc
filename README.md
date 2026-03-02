# Threat Intelligence Feed Aggregator

Updated for release line `1.2.x` (2026-03-02).

Production-ready threat feed aggregation and export service:
- Ingests **CrowdSec** blocklists and **MISP** (IDS-flagged only, warninglist enforced)
- Stores IOCs in **PostgreSQL 16** (JSONB + pg_trgm) with audit trail and feed stats
- Caches exports/views in **Redis 7** (AOF, 512MB, LRU)
- Serves HTTPS via **Nginx** (TLS 1.2+, HTTP/2, security headers, rate limiting)
- Web UI: `/indicators` (Kibana-like search) with WCAG/ARIA attributes
- Source shortcuts: `/sources/<src>` (e.g. `/sources/bazaar`, `/sources/mwdb`)
- 17 export formats via `/indicators/<format>`
- Queue-based sync jobs with per-feed idempotency (`sync_jobs`)
- Admin feed configuration with `Test connection`, per-feed settings, and optional `custom filter`
- Unified light/dark theme across overview, indicators, admin, logs, and feed forms
- MISP integration is disabled by default and can be enabled from Admin feed controls

## Release Highlights (1.2.x)

- Runtime schema creation removed from app startup.
- Alembic migrations introduced (`scripts/db-migrate.sh`, `migrate` compose service).
- `app` and `worker` now auto-run `alembic upgrade head` on container start (`AUTO_MIGRATE_ON_START=true` by default).
- Scheduler/manual sync refactored to enqueue jobs (`/api/sync` -> `202` with job metadata).
- Logs API supports `job_id` filtering.
- Feed configuration extended:
  - abuse.ch service selectors (`threatfox`, `urlhaus`, `bazaar`, `feodotracker`, `yaraify`)
  - MWDB: organizations, tags, days/no-time-limit, optional custom filter.
- MISP safety guard:
  - sync timeout watchdog (`MISP_SYNC_TIMEOUT_S`, default `30s`)
  - automatic MISP feed disable on connectivity timeout/failure to avoid blocking workers.
- **MWDB "My MWDB group" selector** — configure `MWDB_MY_GROUP` or use the Admin UI dropdown; indicators from that group are tagged `TLP:AMBER`.
- **Prometheus job backlog metrics** — `sync_jobs_queued`, `sync_jobs_running`, `export_jobs_pending` Gauges refreshed on each `/metrics` scrape.
- **Export file cleanup** — scheduled job at 03:00 UTC removes stale files from `EXPORT_JOB_DIR` (prevents unbounded `/tmp` growth).
- **CircuitBreaker** for MWDB, MISP, and abuse.ch — configurable fail threshold and cooldown; state logged with `circuit_open`/`circuit_recovered` events.

## Quickstart (Docker Compose)

1) Copy env template and generate secrets:
```bash
cp .env.example .env
./scripts/generate-secrets.sh >> .env
```

2) Configure integrations (optional):
- CrowdSec: set `CROWDSEC_API_KEY` and `CROWDSEC_LISTS` (comma-separated list IDs)
- MISP: set `MISP_URL`, `MISP_API_KEY`, and `MISP_VERIFY_SSL`

3) Start automated deploy (DB + Redis + app, host port `7003` by default):
```bash
bash scripts/deploy-compose.sh
```

Alternative:
```bash
docker compose up -d --build postgres redis
docker compose up -d --build app worker
```

4) Validate:
```bash
curl http://localhost:7003/health
curl http://localhost:7003/indicators
curl http://localhost:7003/indicators/arcsight | head
```

Optional TLS edge (`nginx` profile):
```bash
./scripts/setup-ssl.sh
docker compose --profile edge up -d nginx
curl -k https://localhost:7003/health
```

## Endpoints

- `GET /health` – health + integration checks
- `GET /` – status overview
- `GET /indicators` – unified view (HTML)
- `GET /indicators/<fmt>` – export (TXT/CSV/JSON/XML + vendor formats)
- `GET /correlations` – cross-source IOC correlation view (JSON)
- `GET /metrics` – Prometheus metrics (deploy behind internal network/VPN if needed)

### Export formats (17)

Basic:
- `txt`, `csv`, `json`, `xml`

Firewall / blocklists:
- `fortigate` (external block list)
- `fortigate_ips`
- `checkpoint`
- `paloalto`

SIEM / platforms:
- `sentinel` (STIX wrapper JSON)
- `defender` (CSV)
- `f5` (iRule data group)
- `imperva` (JSON)
- `arcsight` (CEF)
- `elasticsearch` (bulk NDJSON)
- `cribl` (NDJSON)
- `splunk` (HEC JSON)
- `fidelis` (STIX 2.1 bundle)

## Search syntax

Kibana-like:
- Operators: `AND`, `OR`, `NOT`
- Predicates:
  - `value:192.168.*`
  - `confidence:>70` (also `<`, `>=`, `<=`, `:`)
  - `type:ip`, `tlp:AMBER`, `source:misp`
  - `tags:apt`

## Notes / Security

- No hardcoded secrets; all secrets via environment variables.
- DB queries compiled via SQLAlchemy expressions (parameterized).
- Rate limiting: Nginx + Flask-Limiter (Redis backend).
- App-level hard safety cap: `REQUESTS_PER_SECOND_MAX` (default `1_000_000` req/s).
- Defense-in-depth validation of query strings (`max 500` chars, rejects obvious injection markers).
- CrowdSec indicators are **always** enforced as `TLP:AMBER`.

## Development

Create local dev environment (venv):
```bash
bash scripts/dev-bootstrap.sh
```

Run tests locally:
```bash
bash scripts/dev-test.sh
```

Run compile + tests:
```bash
bash scripts/dev-check.sh
```

Quality backfill (re-normalize existing indicators):
```bash
PYTHONPATH=. python scripts/backfill_quality_normalization.py
```

M12 performance benchmark (mixed traffic profile):
```bash
python scripts/benchmark_m12.py --base-url http://127.0.0.1:8080 --duration 30 --concurrency 64
```

M14 benchmark suite (3 runs, multiple traffic profiles, median summary):
```bash
python scripts/benchmark_suite_m14.py --base-url http://127.0.0.1:8080 --duration 20 --concurrency 64 --runs 3
```

M15 release gate (tests + perf thresholds):
```bash
bash scripts/m15_premerge_gate.sh
```

M15 chaos check (Redis outage fallback validation):
```bash
bash scripts/m15_chaos_check.sh
```

M16 readiness report:
```bash
bash scripts/m16_release_readiness.sh
```

Docker cluster benchmark (1 replica vs N replicas):
```bash
bash scripts/benchmark_cluster_m12.sh 4 20 64
```

One-shot benchmark via container entrypoint switch:
```bash
docker compose run --rm -e BENCHMARK_BASE_URL=http://app:8080 app --benchmark
```

Contribution and quality gate:
- See `CONTRIBUTING.md` for merge policy and smoke-test checklist.
- CI (`.github/workflows/ci.yml`) enforces tests on Python 3.11/3.12 for pushes and PRs.
- Performance artifacts: `docs/performance.md`, `monitoring/alerts/m12-slo-alerts.yml`, `monitoring/grafana/m12-dashboard.json`.
- Confluence package (pages/subpages for Confluence 9.2.13): `Confluence/README.md`, `Confluence/manifest.yaml`, `Confluence/pages/*.wiki`.
- UML diagrams and generation guide: `docs/uml/README.md`.


## Configuration

- `MALWAREBAZAAR_SINCE_DATE` (optional): ISO date `YYYY-MM-DD`. When set, MALWAREBAZAAR_SINCE_DATE: ISO date `YYYY-MM-DD` (UTC). MalwareBazaar ingestion pulls entries from this date (inclusive) onward.
- query/response safety limits:
  - `REQUESTS_PER_SECOND_MAX` (default: `1000000`)
  - `QUERY_RESULT_LIMIT_MAX` (default: `10000`)
  - `EXPORT_RESULT_LIMIT_MAX` (default: `200000`)
  - `CORRELATION_LIMIT_MAX` (default: `5000`)
- `MALWAREBAZAAR_TAGS` (optional): comma-separated tags for worker auto-ingestion.
- `MALWAREBAZAAR_LIMIT` (optional): max rows per run (default: `1000`).
- `MWDB_TAGS` (optional): comma-separated tags for worker auto-ingestion.
- `MWDB_LIMIT` (optional): max rows per run (default: `1000`).
- outbound feed throttle (optional, enabled by default): `FEED_REQUESTS_PER_SECOND` (default: `10`), `FEED_REQUESTS_PER_MINUTE` (default: `55`), `FEED_RATE_LIMIT_ENABLED`.
- abuse.ch extended integrations (optional): `THREATFOX_*`, `URLHAUS_*`, `YARAIFY_*`, `FEODOTRACKER_*`, `HUNTING_FPLIST_*`, with shared `ABUSECH_AUTH_KEY`.
- startup migration control (optional): `AUTO_MIGRATE_ON_START` (default: `true`).


## CLI (IOC ingestion)

Run locally:

```bash
export DATABASE_URL='postgresql://iocuser:pass@localhost:5432/iocdb'
python -m app.cli fetch --data-source bazaar --tags TrickBot --since 2025-01-01 --until 2025-01-31
python -m app.cli fetch --data-source mwdb --tags EvilTag --since 2025-01-01 --config-file ./config/cli.env
```

### Config file
`--config-file` supports JSON (`.json`) or `.env` style `KEY=VALUE`.
Supported keys:
- `DATABASE_URL`
- `TAGS` (comma-separated)
- `SINCE` (YYYY-MM-DD or ISO datetime)
- `UNTIL` (YYYY-MM-DD or ISO datetime)
- `MALWAREBAZAAR_API_URL`
- `MWDB_URL`
- `MWDB_AUTH_KEY`
- `ABUSECH_AUTH_KEY` (shared key for abuse.ch services, including MalwareBazaar)

Precedence:
- CLI flags override values from `--config-file`.
- For `DATABASE_URL`, current precedence is: environment variable first, then `--config-file`.
