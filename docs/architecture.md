# Architecture

Status: updated for `1.8.0` + `compliance-1.0`, post-refactor cleanup (2026-05-16).

## Overview

The Threat Feed Aggregator follows a **database-first** architecture where PostgreSQL serves as the central hub for data storage, transformation, and export operations. This design prioritizes performance, consistency, and reliability over application-level complexity.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Nginx (Reverse Proxy)                   │
│         TLS 1.2+, HTTP/2, Security Headers, Rate Limiting       │
└──────────────────┬──────────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────────┐
│                  Flask Application (Gunicorn)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐   │
│  │   Main API  │  │   Web UI    │  │  Background Worker   │   │
│  │  (REST/HTML)│  │  (Blueprint)│  │  (Scheduled Updates) │   │
│  └─────────────┘  └─────────────┘  └──────────────────────┘   │
│         │                │                     │                │
│         └────────────────┴─────────────────────┘                │
│                          │                                       │
└──────────────────────────┼───────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌──────────────┐  ┌──────────────┐
│  PostgreSQL   │  │    Redis     │  │   External   │
│   Database    │  │    Cache     │  │  TI Sources  │
│               │  │              │  │              │
│ - Indicators  │  │ - Response   │  │ - MISP       │
│ - Feed Stats  │  │   Cache      │  │ - CrowdSec   │
│ - Audit Log   │  │ - Rate Limit │  │ - Malware    │
│ - Functions   │  │   State      │  │   Bazaar     │
│ - Indexes     │  │              │  │ - MWDB       │
└───────────────┘  └──────────────┘  └──────────────┘
```

---

## Core Components

### 1. Web Application Layer

**Technology:** Flask 3.0 + Gunicorn

**Responsibilities:**
- HTTP request handling
- Query parsing and validation
- Response formatting and caching
- Security enforcement (headers, rate limiting)
- Audit logging

**Key Files:**
- `app/factory.py` - App factory, composition root, and wiring only
- `app/routes/public.py` - Public HTML/export routes
- `app/routes/auth.py` - Admin authentication and CSRF protection
- `app/routes/ops_admin.py` - Admin panel HTML routes (feeds, config, sync-job details)
- `app/routes/ops_api.py` - Admin operational API routes (sync, DLQ, cancel, retry)
- `app/routes/events.py` - SSE live event stream
- `app/routes/logs.py` - Logs UI and log API routes
- `app/routes/health.py` - Health/readiness/dependency routes
- `app/webui.py` - Web UI Blueprint
- `app/security.py` - Security middleware and validation
- `app/services/common.py` - Shared resilience (CircuitBreaker, DBCircuitBreaker, retry, throttle)
- `app/audit_integrity.py` - HMAC-SHA256 audit log hash chain

**Characteristics:**
- Stateless design for horizontal scalability
- `app/factory.py` is the composition root — defines 30+ shared helper closures injected as a `deps` dict to each route registrar; no route module imports from another
- Immutable configuration (frozen dataclass hierarchy)
- Structured logging with context
- DBCircuitBreaker opens after 5 consecutive DB failures, enforces cooldown, then allows one half-open probe

**Template Architecture (Jinja2):**
All HTML is rendered through Jinja2 templates — no HTML is constructed as Python strings in route handlers.
- `app/templates/layout.html` — base layout; `{% block extra_css %}` is inside `<style>`, `{% block extra_js %}` is inside `<script>` — child blocks inject raw CSS/JS without wrapper tags
- `app/templates/legacy/` — indicator search and landing pages
- `app/templates/admin/` — admin panel, feed configure, sync job details
- `app/templates/partials/` — reusable fragments included via `{% include %}`:
  - `startup_loader.html` / `startup_loader_css.html` / `startup_loader_js.html`
  - `feed_metrics_widget.html` / `feed_metrics_widget_js.html`
- No Python view module constructs HTML strings; `app/views/widgets.py` deleted post-refactor

### 2. Database Layer (PostgreSQL 16+)

**Why Database-First:**
- **Performance:** SQL functions eliminate round-trips
- **Consistency:** Database handles transactions and constraints
- **Reliability:** ACID guarantees for concurrent writes
- **Scalability:** Query optimization at database level
- **Simplicity:** Less application code = fewer bugs

**Schema Design:**

```sql
ti.indicators (
    -- Identity
    id BIGSERIAL PRIMARY KEY,
    uuid UUID UNIQUE,

    -- IOC Data
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,

    -- Provenance (unique constraint)
    source TEXT NOT NULL,
    source_ref TEXT,

    -- Metadata
    confidence SMALLINT CHECK (0-100),
    tlp TEXT CHECK (WHITE|GREEN|AMBER|RED),
    is_active BOOLEAN DEFAULT TRUE,
    tags TEXT[],
    metadata JSONB,

    -- Timestamps
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,

    UNIQUE (ioc_value, ioc_type, source, source_ref)
)
```

**Database Functions:**
- `ti.export_indicators()` - Native format export
- `ti.search_unified()` - Unified search with filtering
- `ti.upsert_indicator()` - Atomic upsert operations
- Triggers for `updated_at` maintenance

**Indexes:**
- B-tree on `(source, source_id, is_active)`
- GIN on `tags` array
- GIN on `metadata` JSONB
- pg_trgm for wildcard searches
- Partial indexes for active indicators

**Performance Optimizations:**
- Prepared statements via SQLAlchemy
- Connection pooling (10 + 20 overflow)
- Pool pre-ping for stale connection detection
- Query result caching in Redis

### 3. Cache Layer (Redis 7)

**Purpose:**
- HTTP response caching (HTML, exports)
- Rate limit state storage
- Session management (future)

**Configuration:**
- **Persistence:** AOF (Append-Only File)
- **Memory:** 512MB max with LRU eviction
- **TTL:** 5 minutes default (CACHE_TTL)
- **Connection:** Single connection pool

**Cache Keys:**
```
indicators_html|q=value:*|type=ip|tlp=AMBER|...
export|fmt=csv|q=...|type=...
```

**Benefits:**
- Reduces database load
- Improves response latency
- Enables horizontal scaling
- Adds visibility via cache hit/miss metrics (`cache_access_total`)

### 4. Background Worker

**Technology:** Python schedule library + threading

**Responsibilities:**
- Periodic threat feed updates
- Feed health monitoring
- Stale indicator cleanup
- Statistics calculation

**Update Cycle:**
```python
# Default: 10 minutes (UPDATE_INTERVAL=600)
schedule.every(10).minutes.do(update_all_feeds)
```

**Feed Update Process:**
1. Fetch from external API (with retry/backoff)
2. Normalize IOC format
3. Upsert to database (ON CONFLICT handling)
4. Mark missing indicators as inactive
5. Update feed_stats table
6. Log metrics

**Error Handling:**
- Exponential backoff for transient errors
- CircuitBreaker (`app/services/common.py`) — opens after N consecutive failures, recovers after cooldown; used by abusech, mwdb, misp
- ExternalFeedConnector (`app/services/common.py`) — shared request wrapper used by connectors to apply consistent throttle + retry behavior
- Failed feed updates don't block others
- Errors logged with structured context
- `feed_stats.last_fetch_error` tracking

### 5. Resilience Layer (`1.8.0`)

**DBCircuitBreaker** (`app/services/common.py`):
- Thread-safe circuit breaker wrapping every `_db()` call.
- Opens after 5 consecutive database failures, blocking further calls for 30 s.
- Half-open probe mechanism: after cooldown, exactly one request is allowed through to test recovery.
- State (`closed` / `open` / `half_open`) exposed at `/admin/api/db-circuit` and `db_circuit_state` in `/health`.
- Real query/statement failures feed the breaker through SQLAlchemy engine observers, not only session acquisition failures.

**Dead Letter Queue** (`DeadLetterJob` model, `app/models.py`):
- Sync jobs that exhaust all retries (default: 3) are moved to the DLQ.
- DLQ entries preserve the original job ID, feed, failure class, error, retry count, and payload.
- Manual requeue via `POST /admin/api/dead-letter-jobs/<id>/requeue` records requeue count, last-requeued timestamp, and the replacement sync job ID; repeated requeue of the same row is idempotent.
- Inventory endpoint `GET /admin/api/dead-letter-jobs` supports filtering by feed.

**Cache Warming** (scheduler loop in `app/factory.py`):
- Runs at most twice per cache TTL (default: every 10 minutes when `CACHE_TTL=300`).
- Pre-populates Redis keys `warm:indicator_type_counts` and `warm:total_active` for dashboard widgets.

**SSE Event Stream** (`/api/events`, `app/routes/events.py`):
- Pushes heartbeat, active indicator count, latest sync run statuses, and feed health every 15 s.
- Bounded by runtime config (`SSE_MAX_DURATION_S`, `SSE_MAX_CONNECTIONS`); sync workers are rejected by default unless explicitly allowed.

### 6. Adapter Boundary and Runtime Settings (`1.6.1`)

The integration layer now has an explicit repository-local adapter boundary:
- `app/adapters/contracts.py` defines the feed/export adapter protocols,
- `app/adapters/types.py` defines shared DTOs (`CanonicalIOC`, `FetchBatch`, `AdapterCapabilities`),
- `app/adapters/registry.py` provides repo-local registration/discovery,
- `app/adapters/pipeline.py` provides the shared persistence path for migrated feed batches.

Runtime feed configuration no longer depends on mutating process-global environment variables during sync execution.

Instead:
- `app/runtime_env.py` stores scoped runtime overrides for the active sync job,
- `app/config.py` reads those overrides before falling back to process env,
- `app/services/common.py` applies proxy/TLS behavior per session,
- app and worker startup refresh the same proxy settings cache instead of rewriting `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`.

This keeps provider configuration isolated to the current execution scope and removes cross-job/process leakage risk from mutable global env state.

### 7. Sync Scheduler / Queue (1.1.x)

The application now uses a DB-backed sync queue:
- `sync_jobs` table for job lifecycle tracking
- idempotent enqueue per feed (prevents duplicate queued/running jobs)
- manual and scheduled sync paths both use the same queue runner
- logs include `run_id/job_id` for traceability

Startup is migration-first (Alembic), no runtime `create_all`.

---

## Data Flow

### Ingestion Flow (Background Worker)

```
External Source → API Fetch → Normalization → Database Upsert → Feed Stats
     (MISP)                                         ↓
     (CrowdSec)                              Audit Logging
     (MalwareBazaar)                              ↓
     (MWDB)                                  Cache Invalidation
```

**Steps:**
1. **Fetch:** HTTP GET with auth headers, retry logic
2. **Normalize:** Map source format to internal schema
3. **Transform:** Calculate confidence, extract TLP, parse tags
4. **Upsert:** `ON CONFLICT DO UPDATE` for idempotency
5. **Audit:** Log ingestion stats and errors
6. **Cache:** Clear relevant cache keys
7. **Quality/Enrichment:** Canonical normalization, dedup, and metadata enrichment

### Query Flow (API Request)

```
Client Request → Nginx → Flask → Cache Check → Database Query → Format → Response
                   ↓         ↓                        ↓
              Rate Limit   Security            Result Cache
              Check       Validation           (Redis)
```

**Steps:**
1. **Nginx:** TLS termination, rate limiting, security headers
2. **Global Guardrail:** In-process hard cap `REQUESTS_PER_SECOND_MAX` (default 1,000,000 req/s)
3. **Flask:** Parse query, validate syntax (max 500 chars)
4. **Cache:** Check Redis for cached response
5. **Database:** Execute parameterized SQL query with latency metrics (`db_query_duration_seconds`)
6. **Correlation (optional):** Aggregate active IOCs across distinct sources via `/correlations`
7. **Format:** Apply output formatter (txt/csv/json/...)
8. **Cache:** Store result in Redis (TTL: 5 minutes)
9. **Response:** Return with security headers

---

## Security Architecture

### Defense Layers

**Layer 1: Network (Nginx)**
- TLS 1.2+ only, modern cipher suites
- Rate limiting (nginx + redis)
- Request size limits
- DDoS mitigation

**Layer 2: Application (Flask)**
- Host header validation
- Query syntax validation (max length, blacklist)
- Input sanitization
- Secure session cookies
- CSRF protection (SameSite)

**Layer 3: Database**
- Parameterized queries only (SQLAlchemy ORM)
- Connection credentials via environment
- Read-only query user (optional)
- Row-level security (future)

**Security Headers:**
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; ...
Strict-Transport-Security: max-age=31536000
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Authentication & Authorization

**Current State (1.8.x):**
- `/admin` surface requires session-based login (`ADMIN_API_TOKEN`), protected with CSRF tokens.
- Admin sessions carry `admin_authenticated`, `admin_user_id`, and `admin_role`.
- State-changing admin requests are CSRF-validated (token injected by `_inject_admin_csrf` `after_request` hook).
- Login endpoint is rate-limited; rate limit exceeded returns an HTML operator-facing response.
- `/api/sync`, `/api/v1/sync`, `/api/sentinel/export` require `X-Admin-Token: <token>` header.
  - Token may also be passed as `admin_token` in a POST form body.
  - **Query string (`?admin_token=`) is NOT accepted** — tokens in URLs appear in server access logs.
- `/api/v1/*` public query surface is unauthenticated for read operations (GET indicators, GET feeds).
- `auth_mode` for Sentinel export is read from `AZURE_SENTINEL_AUTH_MODE` app config — callers cannot override it.
- Public `/healthz`, `/readyz`, `/api/events` are unauthenticated operational probes.

**Recommended for Production:**
1. Deploy `/metrics` behind internal network/VPN
2. Set `ALLOWED_HOSTS` to your domain
3. Enable `MISP_VERIFY_SSL=true` (default)
4. Rotate `SECRET_KEY` and `ADMIN_API_TOKEN` per policy (see `docs/asset-management.md`)

**Future Enhancements:**
- JWT-based machine-client authentication for `/api/v1/*`
- TLP-based filtering per user/role
- API key rotation automation

---

## Scalability

### Horizontal Scaling

**Stateless Design:**
- No application state (all in Redis/PostgreSQL)
- Session storage in Redis
- Load balancer ready (nginx, HAProxy)

**Scaling Strategy:**
```
┌────────┐    ┌────────┐    ┌────────┐
│ App 1  │    │ App 2  │    │ App N  │
└───┬────┘    └───┬────┘    └───┬────┘
    │             │             │
    └─────────────┼─────────────┘
                  │
            ┌─────▼─────┐
            │   Redis   │
            └───────────┘
                  │
            ┌─────▼─────┐
            │PostgreSQL │
            └───────────┘
```

**Considerations:**
- Shared Redis for cache consistency
- Database connection pooling per instance
- Worker runs on single instance only (leader election needed for multi-worker)

### Vertical Scaling

**Database:**
- Increase `shared_buffers` (25% of RAM)
- Tune `work_mem` for complex queries
- Enable parallel query execution
- Add more indexes for specific workloads

**Application:**
- Increase Gunicorn workers (2-4 × CPU cores)
- Increase database connection pool size
- Tune Redis maxmemory

**Performance Targets:**
- < 100ms for cached responses
- < 500ms for database queries
- < 2s for large exports (100k IOCs)
- 1000+ req/s with caching

---

## Monitoring & Observability

### Metrics (Prometheus)

```
# Request metrics
http_requests_total{method, endpoint, status}
http_request_duration_seconds{endpoint}

# Application metrics
active_indicators
database_connection_pool_size
redis_cache_hit_ratio

# Job backlog metrics (Gauge, refreshed on each /metrics scrape)
sync_jobs_queued      # SyncJobs in status=queued
sync_jobs_running     # SyncJobs in status=running
export_jobs_pending   # ExportJobs in status=queued or running

# System metrics (via node_exporter)
node_cpu_usage
node_memory_usage
node_disk_io
```

### Logging

**Format:** JSON structured logging

**Levels:**
- DEBUG: Query details, cache operations
- INFO: Request logging, feed updates
- WARNING: Retry attempts, degraded performance
- ERROR: Failed requests, database errors

**Context:**
```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "level": "INFO",
  "message": "misp_updated",
  "extra": {
    "fetched": 1234,
    "events": 45,
    "duration_ms": 2345
  }
}
```

### Health Checks

**Endpoints:**
- `/healthz` (liveness, no external calls)
- `/readyz` (readiness, DB+Redis)
- `/deps` (external dependency snapshot, cached)
- `/api/events` (SSE live operational stream, unauthenticated)
- `/health` (legacy combined check including `db_circuit_state`)

### Grafana Dashboard

Provided at `grafana/dashboard.json` (UID `ioc-service-ops`), 10 panels:
Active IOC count (stat), HTTP request rate (timeseries), sync jobs queued (stat),
feed fetch rate by source and status (timeseries), error rate (timeseries),
P95 HTTP latency (timeseries), cache hit ratio (timeseries), DB query P99 (timeseries),
sync retries (timeseries), export jobs pending (gauge).

**Checks:**
- Liveness: process + HTTP stack
- Readiness: database connectivity and Redis availability
- Dependency snapshot: last known status for external feeds/services

**Docker Healthcheck:**
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -fsS http://localhost:8080/readyz || exit 1
```

---

## Technology Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Application | Python | 3.12 | Runtime |
| Web Framework | Flask | 3.1.3 | HTTP server |
| WSGI Server | Gunicorn | 22.0.0 | Production server |
| Database | PostgreSQL | 16+ | Data storage |
| Cache | Redis | 7+ | Response cache |
| Reverse Proxy | Nginx | 1.24+ | TLS, rate limiting |
| ORM | SQLAlchemy | 2.0.36 | Database abstraction |
| HTTP Client | requests | 2.32.4 | External API calls |
| Rate Limiting | Flask-Limiter | 3.7.0 | API rate limiting |
| Metrics | prometheus-client | 0.20.0 | Metrics export |
| MISP Client | pymisp | 2.4.179 | MISP integration |
| JSON | stdlib `json` | Python 3.12+ | JSON serialization |

---

## Design Principles

1. **Database-First:** Offload complexity to PostgreSQL
2. **Immutability:** Configuration is immutable (dataclass)
3. **Fail-Fast:** Validate early, fail with clear errors
4. **Defense-in-Depth:** Multiple security layers
5. **Observability:** Structured logging, metrics, health checks
6. **Simplicity:** Minimal abstractions, explicit over implicit
7. **Performance:** Caching, indexing, connection pooling
8. **Idempotency:** Upsert operations, safe retries

---

## Future Enhancements

### High Priority
- [x] API authentication (session-based admin auth delivered in 1.4.2)
- [x] Real-time updates (SSE delivered in 1.8.0 — `/api/events`)
- [ ] Machine-client authentication for `/api/v1/*` (JWT / API keys)
- [ ] Multi-tenancy support

### Medium Priority
- [ ] GraphQL API
- [ ] Bulk import API
- [ ] Indicator enrichment pipeline
- [ ] Machine learning confidence scoring

### Low Priority
- [ ] Mobile app
- [ ] ChatOps integration (Slack, Teams)
- [ ] Threat intel sharing (TAXII 2.1)
- [ ] Blockchain provenance tracking

---

## Development

### Local Setup

```bash
# Clone and setup
git clone <repo>
cd ioc-service
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Database setup
docker compose up -d postgres redis
psql -h localhost -U threatfeed -d threatfeed -f database/init.sql

# Run app
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export DATABASE_URL="postgresql://..."
python -m flask --app app.main run --debug
```

### Testing

```bash
# Unit tests
pytest tests/ -v

# Integration tests
docker compose up -d
pytest tests/integration/ -v

# Load tests
python scripts/benchmark_m12.py --base-url http://127.0.0.1:8080 --duration 30 --concurrency 64
```

---

## Deferred: Async SQLAlchemy

Milestone 1.8.0 considered migrating the ORM layer to `AsyncSession` (SQLAlchemy async)
to reduce thread-pool pressure under high concurrency.  This was deferred because:

- The migration requires replacing every `db.scalar()`, `db.execute()`, and
  `db.scalars()` call with `await` equivalents across 3 000+ lines of application code.
- Flask 3.x supports async view functions but background threads (the scheduler loop,
  `ThreadPoolExecutor` for export jobs) are incompatible with asyncio coroutines —
  a full rewrite of the scheduler would be required.
- The current architecture achieves the required SLOs (p99 < 500 ms) through connection
  pooling, read replicas, and Redis caching without async I/O.

**Revisit when:** p99 latency consistently exceeds 800 ms at steady-state load, or
when the project migrates from Flask to an ASGI framework.

---

## See Also

- [API Documentation](api.md) - API endpoints and formats
- [Database Schema](database.md) - Database design
- [Configuration](configuration.md) - Environment variables
- [SECURITY_AUDIT_REPORT.md](../SECURITY_AUDIT_REPORT.md) - Security analysis

---

## Architecture Diagrams

Five formal diagrams document the system structure and data flows for v1.9.0.
Mermaid source files are in [`docs/diagrams/`](diagrams/README.md).
PlantUML source files (with pre-rendered PNG/SVG) are in [`docs/uml/`](uml/README.md).

### 1. Core Domain Model (Class Diagram)
[`diagrams/class-domain.mmd`](diagrams/class-domain.mmd)

Key entities: `Indicator`, `Feed`, `FeedRun`, `SyncJob`, `ExportJob`, `AppSetting`, `AppLog`, `AuditLog`, `DeadLetterJob`.
Relationships: Feed → FeedRun (produces), Feed → SyncJob (drives), SyncJob → DeadLetterJob (on permanent failure).

See also: [`uml/generated/IOC_Service_Domain_Model.png`](uml/generated/IOC_Service_Domain_Model.png)

### 2. Feed Ingestion Data Flow
[`diagrams/data-flow.mmd`](diagrams/data-flow.mmd)

Pipeline: External Feed API → Feed Adapter → `persist_batches` → PostgreSQL → Redis cache invalidation.
Worker loop enqueues jobs via cron matching, dequeues with `FOR UPDATE SKIP LOCKED`, and writes `FeedRun` records.

See also: [`uml/generated/IOC_Service_Ingestion_Activity.png`](uml/generated/IOC_Service_Ingestion_Activity.png)

### 3. API v1 Request Lifecycle (Sequence Diagram)
[`diagrams/request-flow.mmd`](diagrams/request-flow.mmd)

Full request path: Nginx TLS → Auth token check → Flask-Limiter → QueryParser → Redis cache → PostgreSQL → Response Formatter → cache store.

See also: [`uml/generated/IOC_Service_Auth_Sequence.png`](uml/generated/IOC_Service_Auth_Sequence.png)

### 4. Admin Manual Sync Flow (Sequence Diagram)
[`diagrams/admin-sync-flow.mmd`](diagrams/admin-sync-flow.mmd)

POST `/admin/sync` → CSRF validation → `enqueue_sync_for_source` → `SyncJob(queued)` → Worker dequeues → Feed Adapter → External API → `FeedRun(success)`.

See also: [`uml/generated/IOC_Service_Sync_Sequence.png`](uml/generated/IOC_Service_Sync_Sequence.png)

### 5. Architecture Overview (C4 Context)
[`diagrams/architecture-overview.mmd`](diagrams/architecture-overview.mmd)

Components: Nginx (TLS/rate-limit), Flask App (API + Admin UI), Background Worker (scheduler), PostgreSQL (primary DB), Redis (cache + rate-limit).
External feeds: CrowdSec CTI, MISP, abuse.ch, MWDB. Export target: Microsoft Sentinel.

See also: [`uml/generated/IOC_Service_Component.png`](uml/generated/IOC_Service_Component.png)

### 6. Service Layer Structure (v1.9.1)
[`diagrams/service-layer.mmd`](diagrams/service-layer.mmd)

New in v1.9.1: the monolithic `factory.py` composition root has been decomposed into dedicated
service modules in `app/services/`. Each service exposes a `make_*_service()` factory that
receives its dependencies via injection, keeping `factory.py` as a thin wiring layer.

Key services: `query_svc` (indicator FTS/RPN engine), `feed_ops` (feed listing + enqueue),
`audit_svc` (tamper-evident audit chain), `app_log_svc` (structured app logs),
`scheduler_svc` (cron job lifecycle + DLQ), `export_svc` (async export + artifact TTL),
`feed_config_svc` (config read/write + secret resolution), `settings_svc` (AppSetting CRUD).
