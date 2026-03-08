# Upstream Tracking (dev)

This file tracks upstream `domainaware/parsedmarc` items mapped to local issues in `mkilijanek/parsedmarc`.

## Local issue mapping

1. Local #26: MS Graph transient failures and retry behavior
- Upstream refs: `domainaware/parsedmarc#593`, `#479`
- Local status: mitigated operationally in this repo (`restart` policy + compose health gate + runbook), awaiting upstream code-level retry behavior.
- Local artifacts: `OPERATIONS.md` (graph reliability runbook), `docker-compose.yml`, `.env.example`

2. Local #27: `since` and `watch` mailbox behavior/performance
- Upstream refs: `domainaware/parsedmarc#581`, `#584`
- Local status: mitigated operationally; awaiting upstream behavior fixes.
- Local artifacts: `OPERATIONS.md` (backfill/steady-state split and mailbox sizing guidance)

3. Local #28: non-zero exit on downstream sink failures
- Upstream refs: `domainaware/parsedmarc#574`, `#367`
- Local status: mitigated in this repo with wrapper and regression checks; awaiting upstream core behavior fix.
- Local artifacts: `scripts/run-parsedmarc-safe.sh`, `scripts/test-run-parsedmarc-safe.sh`, `OPERATIONS.md`

4. Local #29: DMARCbis migration readiness
- Upstream refs: `domainaware/parsedmarc` PR `#659`
- Local status: readiness checklist in place with status timestamps; waiting for upstream merge/release.
- Local artifacts: `DMARCBIS_MIGRATION.md`

## Out of scope for this wrapper repository

- Upstream PR `#658` and `#650` (Google SecOps integrations). These are core feature additions and do not require container-wrapper changes right now.
