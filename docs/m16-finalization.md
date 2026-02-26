# M16 Finalization

Status: updated for 1.1.x (2026-02-26).

## Scope Completed

- M14 performance/capacity tuning and benchmark suite.
- M15 operational hardening (release gate, chaos checks, runbook, CI gate).
- M16 closure package (readiness script, maintenance plan, backlog v2).

## Go / No-Go Checklist

1. Tests pass (`pytest -q`): required
2. Release gate passes (`scripts/m15_premerge_gate.sh`): required
3. Chaos fallback check passes (`scripts/m15_chaos_check.sh`): required for production release
4. M16 readiness report generated (`scripts/m16_release_readiness.sh`): required
5. Documentation updated (`configuration`, `performance`, `runbook`, `maintenance-plan`): required

## Current Decision

- **GO (conditional)** for production-like rollout with current host budget (`4 vCPU / 12 GB` for app container test profile).

Conditions:
- Keep Redis and PostgreSQL healthy and monitored.
- Keep M15 gate in CI as mandatory check.
- Address known dependency vulnerabilities tracked by GitHub/Dependabot before public exposure increase.

## Residual Risks

1. Tail latency under highly DB-heavy spikes (`/indicators` large limits) can still rise (p99).
2. Upstream source instability can reduce feed freshness despite app health.
3. Dependency vulnerabilities currently reported in default branch need remediation planning.

## Backlog v2 (Priority Order)

1. Implement async export job for very large responses (queue + downloadable artifact).
2. Introduce DB read replica routing for heavy read endpoints.
3. Add authenticated access tier for `/metrics` and privileged exports.
4. Expand chaos matrix (DB restart, packet loss, slow Redis).
5. Add automatic weekly benchmark trend report persisted to artifacts.
6. Add dark mode switch with preference persisted in browser local storage/cache.
7. Unify all legacy and template UI pages under one shared layout/component system (single topbar, shared theme script, shared style tokens).
8. Add robust table UX: explicit pagination controls (prev/next/page), total result count, and sticky filter summary for `/indicators`.
9. Add structured validation and feedback states in admin forms (inline required-field errors, success toasts, actionable sync-block reasons).
10. Improve accessibility to WCAG 2.1 AA baseline (consistent focus states, aria-live status updates, contrast audit, keyboard-first interactions).
11. Add responsive/mobile-optimized data views (card/list fallback for tables, horizontal overflow affordances, touch-friendly action sizing).

## Roadmap v2 Implementation Status (2026-02-26)

1. Implemented async export jobs with generated downloadable artifacts (`/export-jobs/<job_id>`).
2. Implemented read-replica aware DB routing for read-heavy operations (`DATABASE_READ_URL` support).
3. Implemented optional authenticated `/metrics` access via bearer token (`METRICS_AUTH_TOKEN`).
4. Expanded chaos checks to include DB restart, Redis pause/slow simulation, and optional packet-loss simulation.
5. Implemented weekly benchmark trend artifact generation (`make benchmark-weekly`).
6. Implemented dark mode persistence with shared theme storage key (`localStorage`).
7. Unified global topbar/navigation and theme controls across legacy UI pages.
8. Added pagination controls, result counts, and sticky filter summary for `/indicators`.
9. Added improved admin form feedback, readiness gating, and clearer configuration state.
10. Added accessibility upgrades (live regions, improved focus handling, keyboard-first actions).
11. Added responsive/mobile table behavior and compact view adaptations.
