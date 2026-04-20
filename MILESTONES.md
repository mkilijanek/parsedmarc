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

Definition of done:
- Public API has a stable, versioned contract.
- Integrators have machine-readable API documentation.
- Configuration has one source of truth with typed grouping.
- Packaging/dependency management is modernized.
- Existing API consumers have a documented migration path.

### 1.6.1 — Integration Adapter Boundary & Runtime Resilience

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

Definition of done:
- Provider integrations follow one adapter model.
- Runtime behavior does not depend on mutable global environment changes.
- Shared infra/bootstrap logic is not duplicated across app and worker.
- Cache and retry behavior is explicit and test-covered.
- Adapters are discoverable, introspectable, and validated against one protocol.

### 1.7.0 — Product UX & Scope Rationalization

Problem focus:
- UI is operator-centric rather than product-centric
- No clear primary interface
- Scope may exceed high-value user workflows

Implementation items:
- Identify the top 3 operator/business workflows and redesign UI around them.
- Separate admin/debug UI from business-facing workflows.
- State clearly which interface is primary for new users and integrators.
- Audit features by maintenance cost and user value; mark candidates for simplification or deprecation.
- Add UX acceptance criteria for search, export, sync visibility, and troubleshooting.
- Explicitly map features into core product scope vs power-user/administrative surface.

Definition of done:
- UI supports primary workflows without operator-level knowledge.
- Admin/debug capabilities remain available but intentionally separated.
- The roadmap distinguishes core product scope from power-user surface.

## Tracking Notes

- These milestones are mirrored into GitHub milestones for issue-level tracking.
- Existing issues should be reassigned to the new version milestones as they are refined.
- New implementation issues should reference both the version milestone and the assessment problem they address.
- Historical cleanup completed on 2026-04-07:
  - closed GitHub milestones: `1.1.x`, `1.2.1`, `1.3.0`, `1.4.0`
  - created missing GitHub releases for existing tags: `1.4.0`, `1.4.1`
  - left `1.6.0`, `1.6.1`, `1.7.0` open because they are not yet fully delivered
- Active delivery cleanup:
  - closed GitHub milestone `1.5.0` and released `1.5.0` on 2026-04-07
  - closed GitHub milestone `1.5.1` and released `1.5.1` on 2026-04-20
