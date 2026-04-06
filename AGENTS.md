# Repository Guidelines - IOC Threat Intelligence Service

## Project Overview

This is a **production-ready Threat Intelligence Feed Aggregator and Export Service** (version 1.1.x). It aggregates IOCs (Indicators of Compromise) from multiple sources and exports them in 17+ vendor formats.

### Key Capabilities
- **Feed Sources**: CrowdSec blocklists, MISP, MalwareBazaar, MWDB, abuse.ch (ThreatFox, URLhaus, FeodoTracker, YARAify)
- **Export Formats**: 17 formats including STIX, CEF, CSV, JSON, and vendor-specific (FortiGate, Palo Alto, Splunk, Elasticsearch, etc.)
- **Web UI**: Kibana-like search interface at `/indicators`
- **API**: RESTful API with Prometheus metrics endpoint
- **Storage**: PostgreSQL 16 with JSONB + pg_trgm, Redis 7 for caching

---

## Architecture

### Service Architecture
```
┌─────────────────┐     ┌─────────────┐     ┌─────────────────┐
│   Nginx (Edge)  │────▶│  Flask App  │────▶│  PostgreSQL 16  │
│   TLS 1.2+/H2   │     │   (Gunicorn)│     │   (Primary)     │
└─────────────────┘     └──────┬──────┘     └─────────────────┘
                               │
                        ┌──────┴──────┐     ┌─────────────────┐
                        │    Redis 7  │     │  Worker (BG)    │
                        │   (Cache)   │     │  (Scheduler)    │
                        └─────────────┘     └─────────────────┘
```

### Core Components

| Component | Purpose | Entry Point |
|-----------|---------|-------------|
| `app/main.py` | Flask application factory, API routes, web UI handlers | `create_app()` |
| `app/worker.py` | Background job scheduler using `schedule` library | `python -m app.worker` |
| `app/models.py` | SQLAlchemy ORM models with PostgreSQL-specific types | - |
| `app/db.py` | Database engine configuration with connection pooling | - |
| `app/config.py` | Dataclass-based configuration from environment variables | `Config()` |
| `app/formatters.py` | 17 export format implementations | `FORMATTERS` dict |
| `app/cache.py` | Redis cache abstraction | `get_redis()` |

### Service Modules (`app/services/`)
Each feed source has its own service module:

| Module | Source | Key Function |
|--------|--------|--------------|
| `crowdsec.py` | CrowdSec blocklists | `update_crowdsec_list()`, `update_all_crowdsec_lists()` |
| `misp.py` | MISP instances | `update_misp_indicators()` |
| `malwarebazaar.py` | Abuse.ch MalwareBazaar | `update_malwarebazaar_indicators()` |
| `mwdb.py` | CERT.pl MWDB | `update_mwdb_indicators()` |
| `abusech.py` | Abuse.ch services | `update_abusech_indicators()` |
| `correlation.py` | Cross-source correlation | `query_correlations()` |
| `correlation_snapshot.py` | Cached correlation data | `refresh_correlation_snapshots()` |
| `cleanup.py` | Data lifecycle | `cleanup_old_indicators()`, `cleanup_export_files()` |
| `common.py` | Shared utilities | `retry_with_backoff()`, `throttle_external_request()`, `CircuitBreaker` |
| `quality.py` | Data quality | Quality scoring, normalization |
| `enrichment.py` | IOC enrichment | Enrichment service |

---

## Database Schema

### Core Tables

#### `indicators` - Main IOC storage
```python
Indicator(
    id: int PK
    uuid: UUID unique
    value: str                # IOC value (IP, domain, hash, etc.)
    type: str                 # ip, domain, url, hash, email
    source: str               # misp, crowdsec, malwarebazaar, mwdb, abusech
    source_id: str            # Source-specific identifier
    confidence: int           # 0-100 score
    tlp: str                  # TLP level (WHITE, GREEN, AMBER, RED)
    is_active: bool           # Soft delete flag
    tags: list[str]           # String array
    metadata: dict            # JSONB additional data
    first_seen, last_seen: datetime
)
```

**Key Indexes**:
- `idx_indicators_value_type_active` - For lookups
- `idx_indicators_active_last_seen` - For feed exports
- `idx_indicators_active_type_last_seen` - Type-filtered queries
- `idx_indicators_active_tlp_conf_last_seen` - TLP/confidence filtering

#### `sync_jobs` - Async job queue
```python
SyncJob(
    job_id: str unique        # UUID for job tracking
    feed_source_id: str       # Which feed
    trigger_type: str         # manual, scheduled, api
    status: str               # queued, running, success, failed
    idempotency_key: str      # Duplicate prevention
    created_at, started_at, finished_at: datetime
)
```

#### Other Tables
- `feed_stats` - Per-feed statistics
- `audit_log` - Security audit trail with IP tracking
- `app_settings` - Encrypted configuration storage
- `export_jobs` - Async export job tracking
- `feeds` - Feed configuration
- `feed_runs` - Feed execution history
- `app_logs` - Structured application logging

---

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check + integration status |
| GET | `/readyz` | Kubernetes-style readiness probe |
| GET | `/` | Status overview page |
| GET | `/indicators` | Web UI (HTML) |
| GET | `/indicators/<fmt>` | Export in specified format |
| GET | `/correlations` | Cross-source correlation view |
| GET | `/metrics` | Prometheus metrics (auth optional) |

### Export Formats (`/indicators/<fmt>`)

**Basic**: `txt`, `csv`, `json`, `xml`

**Firewall/Blocklists**: `fortigate`, `fortigate_ips`, `checkpoint`, `paloalto`

**SIEM/Platforms**: `sentinel` (STIX), `defender`, `f5`, `imperva`, `arcsight` (CEF), `elasticsearch`, `cribl`, `splunk`, `fidelis` (STIX 2.1)

### Search Syntax (Kibana-like)
- Operators: `AND`, `OR`, `NOT`
- Predicates: `value:192.168.*`, `confidence:>70`, `type:ip`, `tlp:AMBER`, `tags:apt`
- Wildcards: `*` and `?` supported

### Admin API (HTML UI)
- `/admin` - Feed configuration
- `/admin/feeds/<source>/sync` - Trigger sync
- `/admin/logs` - Application logs

### Prometheus Metrics (`/metrics`)
Key metrics exposed (see `docs/api.md` for full list):
- `active_indicators` — active IOC count
- `sync_jobs_queued` — SyncJobs in queued status (refreshed each scrape)
- `sync_jobs_running` — SyncJobs in running status (refreshed each scrape)
- `export_jobs_pending` — ExportJobs in queued or running status (refreshed each scrape)
- `http_requests_total`, `http_request_duration_seconds` — request telemetry
- `db_query_duration_seconds`, `cache_access_total` — DB/cache telemetry

---

## Build, Test, and Development

### Environment Setup
```bash
# Bootstrap development environment (creates .venv, installs deps)
bash scripts/dev-bootstrap.sh

# Or manual:
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Local Execution Notes
- Prefer running Python tooling inside the project virtual environment (`.venv`) when it exists or when dependencies need to be installed.
- Use `sudo` only when a task genuinely requires elevated system privileges (for example, system package installation or service management).
- For implementation work, maintain a root-level `change.log` file:
  - use it as a running journal of actions actually performed by the agent,
  - record important commands, observations, decisions, blockers, and follow-up notes,
  - after each meaningful change, append what changed and why,
  - record mistakes or near-misses together with a short lesson to avoid repeating them,
  - keep the current project stage and active implementation context visible there.

### Testing
```bash
# Run full test suite
bash scripts/dev-test.sh
# Or: PYTHONPATH=. pytest -q

# Run compile check + tests
bash scripts/dev-check.sh

# Focused smoke checks
PYTHONPATH=. pytest -q \
  tests/test_api.py::TestHealthEndpoint::test_health_success \
  tests/test_api.py::TestIndicatorsViewEndpoint::test_indicators_view_basic
```

### Docker Deployment
```bash
# Automated deploy with health checks
make deploy
# Or: bash scripts/deploy-compose.sh

# Manual compose
make up          # Start services
make down        # Stop services
make logs        # Follow logs
```

### Performance Benchmarking
```bash
# M12 benchmark (mixed traffic profile)
python scripts/benchmark_m12.py --base-url http://127.0.0.1:8080 --duration 30 --concurrency 64

# M14 benchmark suite (3 runs, multiple profiles)
python scripts/benchmark_suite_m14.py --base-url http://127.0.0.1:8080 --duration 20 --concurrency 64 --runs 3

# Cluster benchmark
bash scripts/benchmark_cluster_m12.sh 4 20 64

# Pre-merge gate
make gate        # bash scripts/m15_premerge_gate.sh
make readiness   # bash scripts/m16_release_readiness.sh
```

---

## Configuration

### Required Environment Variables
```bash
SECRET_KEY=<min 32 chars>          # App encryption key
DATABASE_URL=postgresql+psycopg2://...  # Primary DB
REDIS_URL=redis://:pass@host:6379/0     # Cache
```

### Feed Configuration
```bash
# CrowdSec
CROWDSEC_API_KEY=<key>
CROWDSEC_LISTS=list1,list2,list3

# MISP (disabled by default)
MISP_URL=https://misp.example.com
MISP_API_KEY=<key>
MISP_VERIFY_SSL=true
MISP_DAYS=7
MISP_CIRCUIT_FAIL_THRESHOLD=3    # consecutive failures to open circuit breaker
MISP_CIRCUIT_COOLDOWN_S=300      # cooldown seconds after circuit opens

# MalwareBazaar
MALWAREBAZAAR_AUTH_KEY=<key>
MALWAREBAZAAR_TAGS=trickbot,emotet
MALWAREBAZAAR_SINCE_DATE=2025-01-01

# MWDB
MWDB_URL=https://mwdb.example.com
MWDB_AUTH_KEY=<key>
MWDB_TAGS=apt,malware
MWDB_DAYS=30
MWDB_MY_GROUP=                   # group name; objects from this group get TLP:AMBER
MWDB_CIRCUIT_FAIL_THRESHOLD=3    # consecutive failures to open circuit breaker
MWDB_CIRCUIT_COOLDOWN_S=300      # cooldown seconds after circuit opens

# abuse.ch circuit breaker
ABUSECH_CIRCUIT_FAIL_THRESHOLD=3
ABUSECH_CIRCUIT_COOLDOWN_S=300
```

### Safety Limits
```bash
REQUESTS_PER_SECOND_MAX=1000000      # Global RPS cap
QUERY_RESULT_LIMIT_MAX=10000         # Max query results
EXPORT_RESULT_LIMIT_MAX=200000       # Max export results
CORRELATION_LIMIT_MAX=5000           # Max correlation results
```

---

## Coding Style & Conventions

### Python
- **4-space indentation**
- **PEP 8** style with type hints where practical
- **Naming**:
  - `snake_case` for functions/variables/files
  - `PascalCase` for classes
  - `UPPER_SNAKE_CASE` for constants

### Imports
```python
from __future__ import annotations  # Always first

# Standard library
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

# Third-party
from flask import Flask
from sqlalchemy import select

# Local
from .config import Config
from .models import Indicator
```

### Error Handling Pattern
```python
logger = logging.getLogger(__name__)

try:
    result = some_operation()
    logger.info("operation_success", extra={"detail": value})
except Exception as e:
    logger.error("operation_failed", extra={"error": str(e)}, exc_info=True)
    raise  # or handle gracefully
```

### Database Patterns
```python
from .db import SessionLocal
from .models import Indicator

db = SessionLocal()
try:
    db.add(instance)
    db.commit()
finally:
    db.close()

# Or use get_session() for read/write separation
db = get_session(read_only=True)
```

---

## Testing Guidelines

### Test Structure
```
tests/
├── conftest.py           # Fixtures (test_db, fake_redis, app, client, sample_indicators)
├── test_api.py           # API endpoint tests
├── test_database.py      # Database/ORM tests
├── test_formatters.py    # Export format tests
├── test_security.py      # Security-related tests
├── test_services.py      # Feed service tests
├── test_query_parser.py  # Search parser tests
├── test_correlation.py   # Correlation tests
└── test_m*.py            # Milestone-specific tests
```

### Key Fixtures (from conftest.py)
- `test_db` - SQLite in-memory session
- `fake_redis` - FakeRedis instance
- `app` - Flask app with mocked DB/Redis
- `client` - Flask test client
- `sample_indicators` - Pre-populated test data

### Writing Tests
```python
def test_endpoint_success(client, sample_indicators):
    response = client.get("/api/endpoint")
    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == len(sample_indicators)
```

---

## Security Considerations

### Input Validation
- All search queries validated by `validate_search_query()` (max 500 chars, no SQL meta-markers)
- Host header validation via `enforce_allowed_hosts()`
- Rate limiting via Flask-Limiter (Redis backend)

### Secrets Management
- Never commit secrets to git
- Use `.env` file or external secret files
- Secrets encrypted at rest in `app_settings` table using AES-GCM

### TLP Handling
- CrowdSec indicators always enforced as `TLP:AMBER`
- TLP levels: WHITE, GREEN, AMBER, RED

### Security Headers
All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `Permissions-Policy`

---

## Database Migrations (Alembic)

### Creating Migrations
```bash
# After model changes
cd /app
alembic revision --autogenerate -m "Description"

# Review generated migration
# Apply migration
alembic upgrade head
```

### Migration Scripts
- `scripts/db-migrate.sh` - Production migration runner
- Uses PostgreSQL advisory lock for concurrent safety
- Auto-migration on container start: `AUTO_MIGRATE_ON_START=true`

---

## Release & Deployment

### Release Checklist
1. Version bump in relevant files
2. Update `roadmap.md` with completed items
3. Run full test suite: `make gate`
4. Run readiness check: `make readiness`
5. Tag release: `git tag v1.1.x`

### Docker Images
- Build context: project root
- Base: `python:3.11-slim` or similar
- Multi-service: app, worker, migrate
- Health checks configured

### CI/CD
GitHub Actions (`.github/workflows/ci.yml`):
- Tests on Python 3.11 and 3.12
- Must be green before merge

---

## Common Tasks

### Adding a New Export Format
1. Add formatter function in `app/formatters.py`
2. Register in `FORMATTERS` dict with MIME type
3. Add test in `tests/test_formatters.py`

### Adding a New Feed Source
1. Create service module in `app/services/<source>.py`
2. Implement `update_<source>_indicators()` function
3. Add to worker scheduler in `app/worker.py`
4. Add feed template in `app/main.py:_source_templates()`
5. Add configuration in `app/config.py`
6. Add tests in `tests/test_services.py`

### Database Schema Changes
1. Update model in `app/models.py`
2. Create Alembic migration
3. Update related queries in `app/main.py`
4. Add/update tests

---

## Troubleshooting

### Common Issues

**Migration fails on startup**:
```bash
# Check logs
docker compose logs migrate

# Manual migration
docker compose run --rm migrate
```

**Redis connection errors**:
- Check `REDIS_URL` format: `redis://:password@host:port/db`
- Verify Redis password matches `REDIS_PASSWORD`

**Feed sync failures**:
- Check feed configuration in Admin UI
- Verify API keys in environment variables
- Check `feed_stats` table for error details
- Review `app_logs` table for detailed error messages

**Performance issues**:
- Check database indexes exist
- Review `active_indicators` gauge metric
- Run `EXPLAIN ANALYZE` on slow queries
- Consider `DATABASE_READ_URL` for read replicas

---

## References

- `README.md` - User-facing documentation
- `roadmap.md` - Development milestones
- `QUICKSTART.md` - Quick deployment guide
- `CONTRIBUTING.md` - Contribution guidelines
- `SECURITY.md` - Security policies
- `docs/` - Technical documentation
- `Confluence/` - Confluence export pages
