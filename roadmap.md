# IOC Service -- Roadmap (GitHub Milestones + Issue Checklist)

Versioning scheme: A.B.C - C (patch): small fixes, minor improvements -
B (minor): significant features and functional milestones - A (major):
architectural changes or major stack evolution

------------------------------------------------------------------------

# Milestone 1.1.0 -- Critical Stabilization

## Goals

-   Remove runtime DDL
-   Fix sync 500 errors
-   Make logs operational
-   Deterministic startup

## Issues Checklist

### Database & Migrations

-   [x] Remove metadata.create_all() from production runtime
-   [x] Introduce Alembic baseline migration
-   [x] Add migration entrypoint/init container
-   [x] Add Postgres advisory lock for migration step

### Sync Refactor

-   [x] Introduce sync_jobs table
-   [x] Change "Sync now" to enqueue job (202 + job_id)
-   [x] Change "Sync all" to bulk enqueue
-   [x] Add per-feed idempotency guard
-   [x] Persist job status (queued/running/success/failed)

### Logging & Observability

-   [x] Implement structured logging (JSON)
-   [x] Add log persistence (DB-backed or structured API log endpoint)
-   [x] Expose logs per job via API
-   [x] Replace generic 500 with JSON error + correlation_id

------------------------------------------------------------------------

# Milestone 1.1.x -- Stabilization Patch Series

## Typical Patch Items

-   [x] HTTP timeout + retry/backoff per feed
-   [x] Improve feed config validation
-   [x] Add abuse.ch service selectors in feed config (checkboxes: yaraify, urlhaus, bazaar, feodotracker, threatfox) with persisted per-feed settings
-   [x] Add DB indexes for sync_jobs
-   [x] Improve UI loading/disabled states
-   [x] Graceful worker shutdown handling
-   [x] Feed-level rate limiting

------------------------------------------------------------------------

# Milestone 1.2.0 -- Observability & Operations

## Goals

-   Production-grade monitoring
-   Better operator control

## Issues Checklist

### Metrics

-   [x] Add Prometheus metrics endpoint
-   [x] Expose sync duration metrics
-   [x] Expose success/failure rate per feed
-   [x] Expose job backlog size (`sync_jobs_queued`, `sync_jobs_running`, `export_jobs_pending` Gauges)

### Control & Retry

-   [ ] Add retry failed job button
-   [ ] Add cancel running job
-   [ ] Add job details page

### Health

-   [x] Add /healthz endpoint (`/health` endpoint implemented)
-   [x] Add /readyz endpoint (`/readyz` endpoint implemented)

------------------------------------------------------------------------

# Milestone 1.2.x -- Observability Refinement

-   [ ] Log filtering and pagination improvements
-   [ ] Export logs (CSV/JSON)
-   [ ] Feed stale detection alerts
-   [ ] Query optimization for dashboard

------------------------------------------------------------------------

# Milestone 1.3.0 -- API Modernization (FastAPI + ASGI)

## Goals

-   Clean API contracts
-   Async-ready backend
-   OpenAPI documentation

## Issues Checklist

-   [ ] Migrate API to FastAPI (if not already)
-   [ ] Define Pydantic models as canonical schema
-   [ ] Implement POST /feeds/{id}/sync → 202 job_id
-   [ ] Implement GET /jobs and GET /jobs/{id}
-   [ ] Add OpenAPI documentation
-   [ ] Introduce role-based access control

------------------------------------------------------------------------

# Milestone 1.3.x -- API Stabilization

-   [ ] Async I/O optimization
-   [ ] Structured error taxonomy
-   [ ] Improve validation errors
-   [ ] Add request tracing IDs

------------------------------------------------------------------------

# Milestone 1.4.0 -- Production Job Queue & Scheduler

## Goals

-   Reliable background execution
-   Deterministic scheduling

## Issues Checklist

-   [ ] Introduce job queue (RQ / Dramatiq / Celery)
-   [ ] Implement cron-based scheduler per feed
-   [ ] Add concurrency limits per source_type
-   [ ] Implement automatic retry policy
-   [ ] Add dead-letter queue support
-   [ ] Add priority handling (manual \> scheduled)

------------------------------------------------------------------------

# Milestone 1.4.x -- Queue Optimization

-   [ ] Backpressure handling
-   [ ] Worker autoscaling tuning
-   [ ] Improve failure diagnostics

------------------------------------------------------------------------

# Milestone 1.5.0 -- Modular Pipeline Architecture

## Goals

-   Enable plugin-style feed modules
-   Normalize IOC pipeline

## Issues Checklist

-   [ ] Define canonical IOC schema
-   [ ] Implement pipeline stages (fetch → parse → normalize → enrich →
    store)
-   [ ] Add feed adapter registry
-   [ ] Introduce parser manifest definition
-   [ ] Add configuration schema per plugin

------------------------------------------------------------------------

# Milestone 1.5.x -- Module Expansion

-   [ ] Add new feed adapters
-   [ ] Improve parser testing coverage
-   [ ] Add regression tests for normalization

------------------------------------------------------------------------

# Milestone 1.6.0 -- Integrations & Export

## Goals

-   Operational integration readiness

## Issues Checklist

-   [ ] Implement outbound webhook support
-   [ ] Add export API endpoints
-   [ ] Add integration modules (MISP/OpenCTI/SIEM-ready)
-   [ ] Add audit trail for admin actions

------------------------------------------------------------------------

# Milestone 2.0.0 -- Service Architecture Hardening (Major)

## Goals

-   Multi-instance reliability
-   Clean separation of concerns

## Issues Checklist

-   [ ] Separate API, scheduler, worker services
-   [ ] Implement leader election for scheduler
-   [ ] Remove all runtime schema creation
-   [ ] Implement production-grade logging pipeline (Loki/ELK optional)
-   [ ] Harden configuration and secrets management

------------------------------------------------------------------------

# Milestone 3.0.0 -- Performance Core Optimization (Optional Major)

## Goals

-   Improve high-volume ingestion and correlation

## Issues Checklist

-   [ ] Identify performance bottlenecks
-   [ ] Rewrite heavy components (optional Go/Rust core)
-   [ ] Preserve plugin contract compatibility
-   [ ] Benchmark and validate performance gains

------------------------------------------------------------------------

End of roadmap.
