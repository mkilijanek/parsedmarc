# IOC Service Milestones

This file translates the 2026-04-06 deep assessment into implementation milestones that can be tracked locally and mirrored in GitHub milestones.

## Planning Principles

- Fix critical security and deployment risks before large refactors.
- Remove architectural bottlenecks that block safe maintenance.
- Converge schema, tests, and runtime behavior before adding new public surface.
- Make product UX changes only after the system has clear ownership boundaries.

## Priority Mapping From Assessment

- Critical now:
  - Admin authentication and authorization
  - CSRF protection
  - Stable `SECRET_KEY` handling in container/runtime
- High next:
  - Break up `app/main.py` and `app/routes/ops.py`
  - Eliminate SQL/ORM schema drift
  - Add PostgreSQL integration tests
  - Move inline HTML into Jinja templates
- Medium after that:
  - API versioning and OpenAPI
  - `.dockerignore`
  - Config consolidation and dependency hygiene

## Prompt-to-Milestone Mapping

The architecture prompt bundle in [ref/ioc-architecture-prompt](/home/kili/Repo/ioc-service/ref/ioc-architecture-prompt) maps into the execution plan like this:

| Prompt | Delivery mapping |
|--------|------------------|
| `01-executive-summary.md` | anchors the full `1.4.2` → `1.7.0` sequence and v2.0 success criteria |
| `02-architecture-vision.md` | informs the target architecture for `1.5.0`, `1.5.1`, `1.6.0`, `1.6.1` |
| `03-integration-architecture.md` | defines the detailed implementation target for `1.6.1` |
| `04-iso27001-compliance.md` | defines the critical delivery baseline for `1.4.2` |
| `05-technology-stack.md` | informs tooling and dependency choices for `1.6.0` and scheduler/runtime work in `1.6.1` |
| `06-milestones-roadmap.md` | serves as the reference breakdown for `1.4.2` → `1.7.0`, but needed gap-filling for `1.6.0` |
| `07-roles/*` | distribute responsibilities across each milestone rather than creating separate milestone work |
| `08-best-practices.md` | supplies implementation standards, especially for `1.5.0` and `1.6.0` |
| `09-quality-metrics.md` | defines CI and quality gates for `1.5.0`, `1.5.1`, `1.6.1` |
| `10-risk-management.md` | defines milestone-level mitigation strategy, especially around `1.4.2` and `1.6.1` |
| `11-appendices/*` | contains endpoint/schema/diagram detail consumed by `1.5.1`, `1.6.0`, and `1.6.1` |

Gaps corrected while mapping:
- `1.6.0` is explicitly preserved as its own deliverable milestone rather than being implied by other docs.
- The auth target is treated as one model: protected admin/web UI with session/RBAC and a separate API authentication path for machine clients.
- Adapter work includes registry/discovery, capability metadata, and contract tests, because those requirements were distributed across prompts `03`, `05`, `09`, and `11`.

## Version Plan

### 1.4.2 — Security & Runtime Hardening

Problem focus:
- Publicly reachable admin surface without authentication
- Missing CSRF protection
- Runtime `SECRET_KEY` auto-generation and unsafe operational defaults
- Missing `.dockerignore`
- Weak/implicit admin audit trail and role model

Implementation items:
- Add authentication and authorization for `/admin` and privileged admin actions.
- Introduce CSRF protection for HTML forms and state-changing routes.
- Remove per-container `SECRET_KEY` auto-generation and require explicit secret provisioning.
- Review dangerous admin operations and preserve auditability for destructive flows.
- Add `.dockerignore` and tighten container build inputs.
- Introduce a minimal RBAC model and standardized audit logging for admin actions.

Definition of done:
- Admin routes are not publicly usable without authentication.
- POST admin flows are CSRF-protected.
- Container startup fails fast when `SECRET_KEY` is not explicitly configured.
- Docker build context excludes non-runtime noise by default.
- Admin actions are audit-logged with actor, target, timestamp, source IP, and result.
- The admin authorization baseline is explicitly documented, including the current `admin` role and future extension path.

Status:
- Done on 2026-04-07.

### 1.5.0 — Core Modularization & Template Extraction

Problem focus:
- `app/main.py` as God Object
- Oversized `app/routes/ops.py`
- HTML embedded as Python f-strings
- Inconsistent placement of business logic
- No automated protection against complexity regression

Implementation items:
- Split `app/routes/ops.py` into focused route modules: `admin`, `sync_jobs`, `settings`, `metrics`.
- Reduce `app/main.py` to app factory, composition root, and registration only.
- Move HTML rendering into Jinja templates under `app/templates/`.
- Extract crypto/settings/export/query helpers into dedicated modules or service packages.
- Add regression tests that enforce module boundaries.
- Add quality gates for linting, typing, coverage, and cyclomatic complexity.

Definition of done:
- `app/main.py` is wiring-only.
- Inline HTML no longer lives in large route/business modules.
- Route handlers delegate to extracted route modules, render helpers, and focused service/helper modules instead of concentrating orchestration in one monolith.
- CI flags structural regression through quality and complexity thresholds.

Status:
- Done on 2026-04-07.

### 1.5.1 — Database Convergence & PostgreSQL Validation

Problem focus:
- Dual SQL/ORM schema definitions
- Risk of `ti.*` vs `public.*` divergence
- No integration tests against real PostgreSQL
- Weak relational integrity modeling
- No automated schema drift detection

Implementation items:
- Choose and document one schema source of truth, with the second layer generated or verified from it.
- Reconcile Alembic, ORM models, SQL functions, triggers, views, and schema namespace usage.
- Add PostgreSQL integration tests for triggers, views, JSONB, ARRAY, FTS, export SQL functions, and migrations.
- Introduce missing foreign keys/relationships where they are part of the domain model.
- Remove hardcoded export limits that bypass runtime configuration.
- Add a database-backed override model for composite feed subcomponents, starting with `abusech`, so operators can enable/disable `ThreatFox`, `URLhaus`, `FeodoTracker`, `YARAify`, and `Hunting` per feed without depending only on process env.
- Add schema drift detection to CI/CD.

Definition of done:
- Schema initialization paths produce equivalent database behavior.
- PostgreSQL-only features are exercised in CI/integration tests.
- ORM and SQL schema drift is automatically detectable.
- Inconsistent schema changes fail CI before merge.
- Composite feed component overrides are persisted in DB and take precedence in runtime over static env defaults where configured.

Status:
- Done on 2026-04-20.

### 1.6.0 — API & Configuration Modernization

Status: completed on `2026-04-21`

Problem focus:
- No API versioning
- No OpenAPI specification
- Single giant `Config` object and duplicated env parsing
- Dev/prod dependency separation missing
- No explicit migration story for existing clients

Implementation items:
- Introduce versioned API routes, starting with `/api/v1/`.
- Publish an OpenAPI spec and keep it versioned with the implementation.
- Refactor configuration into grouped sections such as database, security, feeds, and runtime.
- Remove direct env parsing duplication outside the config layer.
- Move the project toward `pyproject.toml` and split production vs development dependencies.
- Define compatibility and migration guidance for the unversioned API surface.

Execution notes:
- Start with the stable subset of public API routes; do not version every historical endpoint in one batch.
- Keep `/api/v1/` additive until migration notes and compatibility labels are published.
- Scope OpenAPI to the supported versioned surface only.
- Preserve existing environment variable names during the config refactor; grouping is internal first, deprecation second.

Acceptance additions:
- Each versioned endpoint must have an owner, request/response contract, and migration note from legacy behavior where applicable.
- Legacy endpoints must be labeled `stable`, `deprecated`, or `internal-only` in docs.

Out of scope:
- Full redesign of payload shapes for already working clients.
- Replacing the current security model solely because versioning is introduced.

Definition of done:
- Public API has a stable, versioned contract.
- Integrators have machine-readable API documentation.
- Configuration has one source of truth with typed grouping.
- Packaging/dependency management is modernized.
- Existing API consumers have a documented migration path.
- Legacy and versioned surfaces are no longer mixed implicitly in documentation.

### 1.6.1 — Integration Adapter Boundary & Runtime Resilience

Status: completed on `2026-04-21`

Problem focus:
- External integrations too tightly embedded in implementation
- Runtime mutation of process environment
- Shared bootstrap logic duplicated
- Missing DB retry/invalidation strategy
- No registry/discovery or capability metadata for adapters

Implementation items:
- Introduce explicit adapter contracts for feed connectors and export targets.
- Move provider-specific mapping and transport details behind adapter implementations.
- Eliminate runtime mutation of global `os.environ` for proxy behavior.
- Consolidate shared proxy/bootstrap logic into one reusable module.
- Add bounded retry patterns for selected DB operations and invalidate caches on state-changing flows.
- Add adapter registry, capability metadata, discovery hooks, fake adapters, and contract tests.

Execution notes:
- Define DTOs and contracts first: `CanonicalIOC`, `FetchResult`, `AdapterCapabilities`, `FeedAdapter`, and `ExportAdapter`.
- Build one shared ingestion pipeline before migrating multiple providers.
- Migrate adapters one provider at a time and retain a temporary fallback path per feed during rollout.
- Keep registry/discovery repo-local first; do not introduce external plugin loading in this milestone.

Acceptance additions:
- Every migrated feed must pass the same contract-test suite.
- Adapters must not persist directly outside the shared pipeline.
- Capabilities metadata must be queryable without reading provider-specific code paths.

Out of scope:
- Community plugin marketplace.
- Big-bang migration of all connectors in a single cutover.
- Broad retry policies that make provider failures harder to diagnose.

Definition of done:
- Provider integrations follow one adapter model.
- Runtime behavior does not depend on mutable global environment changes.
- Shared infra/bootstrap logic is not duplicated across app and worker.
- Cache and retry behavior is explicit and test-covered.
- Adapters are discoverable, introspectable, and validated against one protocol.
- The ingestion pipeline is shared by migrated adapters rather than reimplemented per provider.

### 1.7.0 — Product UX & Scope Rationalization

Status: completed on `2026-04-28`

Problem focus:
- UI was operator-centric rather than product-centric
- No clear primary interface
- Scope exceeded the highest-value daily workflows

Delivered:
- Redesigned UI around primary operator workflows.
- Separated business-facing views from admin/debug tooling.
- Introduced configuration priority model (env-var wins in dev, DB wins in prod).
- Unified layout with sticky topbar, toast notifications, mobile-responsive nav, theme toggle.

Definition of done:
- UI supports primary workflows without operator-level knowledge.
- Admin/debug capabilities remain available but intentionally separated.
- The roadmap distinguishes core product scope from power-user surface.

### 1.8.0 — Resilience, Real-Time Ops & Onboarding

Status: completed on `2026-04-29`

Problem focus:
- Operational resilience was reactive rather than explicit
- No first-class live operator telemetry surface
- Cold caches and failed sync retries degraded operator experience

Delivered:
- DBCircuitBreaker with half-open probing, surfaced at `/health` and `/admin/api/db-circuit`.
- Dead Letter Queue for permanently-failed sync jobs with manual requeue.
- Cache warming for Redis dashboard widgets.
- SSE `/api/events` live operational stream.
- Grafana operational dashboard (10 panels, `grafana/dashboard.json`).
- Onboarding tour (5 steps) and keyboard shortcuts in `layout.html`.

Definition of done:
- Database outages degrade gracefully via DBCircuitBreaker.
- Exhausted sync retries are retained and recoverable through the DLQ.
- Operators have a live event stream and dashboard for current system state.
- UX onboarding and shortcuts are available without regressing existing flows.

### 1.8.1 — Post-1.8 Hardening & Runtime Corrections

Status: completed on `2026-04-30`

Problem focus:
- Production auth bypass remains possible through `ADMIN_AUTH_ENABLED=false`
- DBCircuitBreaker semantics do not match the intended cooldown/probe model
- Public SSE can exhaust sync Gunicorn workers in default deployments
- DLQ requeue and backup handling need hardening after the `1.8.0` / `compliance-1.0` delivery

Delivered:
- Block `ADMIN_AUTH_ENABLED=false` in production by default and require an explicit unsafe override for non-test use.
- Fix DBCircuitBreaker cooldown and half-open transitions.
- Make the DBCircuitBreaker observe real query/commit failures, not only session acquisition.
- Prevent `/api/events` from exhausting the default worker pool.
- Make DLQ requeue idempotent or stateful.
- Harden `scripts/backup.sh` so DB credentials are not exposed via process arguments.

Tracked issues:
- `#181`
- `#182`
- `#183`
- `#184`
- `#185`
- `#186`

Definition of done:
- Production cannot silently run with admin auth disabled unless the explicit unsafe override is enabled.
- DB outage handling matches documented breaker semantics and is exercised by tests.
- Default deployment tolerates a small number of SSE clients without starving normal traffic.
- DLQ requeue no longer fans out duplicate jobs from one dead-letter row.
- Backup execution no longer leaks DB credentials through argv/process listing.

### compliance-1.0 — ISO 27001 / NIST CSF Baseline

Status: completed on `2026-04-29`

Problem focus:
- Compliance controls existed partially in code but were fragmented or undocumented
- Backup, IR, SSDLC, and audit-integrity procedures needed a maintained baseline

Delivered:
- ISO 27001 controls matrix and NIST CSF mapping (`docs/compliance.md`).
- SSDLC documentation and CI security gates (`docs/ssdlc.md`).
- Incident response plan with severity classification (`docs/incident-response.md`).
- Disaster recovery plan with RTO/RPO and backup procedures (`docs/disaster-recovery.md`, `scripts/backup.sh`).
- SIEM integration guide (`docs/siem-integration.md`).
- Asset management and classification inventory (`docs/asset-management.md`).
- HMAC-SHA256 audit log hash chain with scheduled integrity verification.

Definition of done:
- Compliance evidence is documented and traceable to implementation artifacts.
- Backup, disaster recovery, incident response, and SSDLC procedures are maintained in-repo.
- Audit log integrity can be verified operationally.

## Tracking Notes

- These milestones are mirrored into GitHub milestones for issue-level tracking.
- Existing issues should be reassigned to the new version milestones as they are refined.
- New implementation issues should reference both the version milestone and the assessment problem they address.
- Historical cleanup completed on 2026-04-07:
  - closed GitHub milestones: `1.1.x`, `1.2.1`, `1.3.0`, `1.4.0`
  - created missing GitHub releases for existing tags: `1.4.0`, `1.4.1`
- Active delivery cleanup:
  - closed GitHub milestone `1.5.0` and released `1.5.0` on 2026-04-07
  - closed GitHub milestone `1.5.1` and released `1.5.1` on 2026-04-20
  - closed GitHub milestone `1.6.0` and released `1.6.0` on 2026-04-21
  - closed GitHub milestone `1.6.1` and released `1.6.1` on 2026-04-21
  - closed GitHub milestone `1.7.0` and released `1.7.0` on 2026-04-28
  - closed GitHub milestone `1.8.0` and released `1.8.0` on 2026-04-29
  - closed GitHub milestone `compliance-1.0` and released the associated compliance baseline on 2026-04-29
