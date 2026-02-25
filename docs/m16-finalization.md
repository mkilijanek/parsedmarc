# M16 Finalization

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
