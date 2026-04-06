# IOC Service Milestones

This file translates the April 2026 project assessment into implementation milestones that can be tracked both locally and in GitHub milestones.

## Planning Principles

- Reduce codebase complexity before adding new end-user features.
- Make the primary user path obvious before redesigning secondary interfaces.
- Separate domain/use-case logic from transport and infrastructure code.
- Treat connector decoupling and onboarding simplification as first-class deliverables.

## Version Plan

### 1.5.0 — Modular Decomposition & Service Ownership

Problem focus:
- Monolithic `app/main.py` and `app/routes/ops.py`
- Inconsistent placement of business logic

Implementation items:
- Split `app/routes/ops.py` into focused route modules: `admin`, `sync_jobs`, `settings`, `metrics`.
- Remove remaining orchestration logic from `app/main.py` into route registration and dedicated services.
- Introduce explicit use-case/service modules for sync orchestration, export orchestration, admin operations, and logs queries.
- Define a consistent rule: routes validate/serialize, services execute business logic, adapters talk to infrastructure.
- Add regression tests that enforce route-module boundaries.

Definition of done:
- `app/main.py` is wiring-only.
- `app/routes/ops.py` is reduced to a thin compatibility shim or removed.
- New business logic lands only in service/use-case modules.

### 1.5.1 — Onboarding, Configuration & Primary Interface

Problem focus:
- Heavy onboarding
- Too much configuration to start
- No clear primary interface

Implementation items:
- Create a "quickstart mode" with a minimal `.env` profile and sample local stack defaults.
- Introduce configuration profiles: `minimal`, `production`, `integrations`.
- Publish one canonical primary interface for first-time users and document fallback interfaces.
- Add a single guided bootstrap flow in docs and scripts.
- Reduce mandatory setup for demo and local development paths.

Definition of done:
- A new contributor can start the app from one documented path in under 15 minutes.
- README and Quickstart clearly state the recommended interface.
- Minimal local mode does not require configuring every feed/integration.

### 1.6.0 — Domain Model & Use-Case Clarity

Problem focus:
- Weakly exposed domain model
- Hard to understand core flows and use-cases

Implementation items:
- Introduce a `domain/` or equivalent package for core concepts: indicator lifecycle, feed run, sync job, export job, correlation group.
- Document the top use-cases with sequence diagrams and short narratives.
- Add a domain glossary to docs and align naming across API, services, and UI.
- Isolate use-case-level orchestration from HTTP/CLI specifics.
- Add architecture tests or conventions that protect domain/service boundaries.

Definition of done:
- A new engineer can identify the core use-cases and data flow from one document tree.
- Domain terms are consistent across code and documentation.
- Core orchestration is readable without opening route handlers.

### 1.6.1 — External Adapter Boundary

Problem focus:
- External integrations too tightly embedded in implementation

Implementation items:
- Introduce adapter interfaces/contracts for feed connectors and export targets.
- Move provider-specific request/response mapping behind adapter implementations.
- Add adapter test fixtures and fake provider harnesses.
- Standardize connector capability metadata and registration.
- Make connector replacement/extensibility possible without editing route or domain code.

Definition of done:
- New provider integrations follow one adapter template.
- Domain/use-case code does not depend on provider-specific payload shapes.
- Integration tests run against stable adapter contracts.

### 1.7.0 — Product UX & Scope Rationalization

Problem focus:
- UI is too technical
- Product scope may exceed real user needs

Implementation items:
- Identify the top 3 operator and business workflows, then redesign the UI around them.
- Separate admin/debug UI from business-facing workflows.
- Audit features by usage and maintenance cost; mark candidates for simplification or deprecation.
- Rework navigation and terminology around primary tasks instead of internal implementation details.
- Add UX acceptance criteria for search, export, sync visibility, and troubleshooting.

Definition of done:
- UI supports primary workflows without requiring operator-level knowledge.
- Admin/debug capabilities are still available but clearly separated.
- The roadmap explicitly marks what is core product scope vs optional power-user surface.

## Tracking Notes

- These milestones are mirrored into GitHub milestones for issue-level tracking.
- Existing issues should be reassigned to the new version milestones as they are refined.
- New implementation issues should reference both the version milestone and the assessment problem they address.
