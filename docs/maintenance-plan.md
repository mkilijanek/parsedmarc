# Maintenance Plan (Post-M16)

## Horizon

Operational plan for the next 90 days after M16 completion.

## Weekly

1. Review alerts:
- `m12-slo-alerts.yml`
- `m15-operations-alerts.yml`
2. Check benchmark drift:
- run `python scripts/benchmark_suite_m14.py --base-url http://127.0.0.1:8080 --duration 20 --concurrency 64 --runs 1`
3. Validate ingestion health:
- verify worker logs and source update freshness.

## Biweekly

1. Run chaos check:
```bash
bash scripts/m15_chaos_check.sh
```
2. Review top latency contributors from `/metrics` (`db_query_duration_seconds`, endpoint p95/p99).

## Monthly

1. Run release gate:
```bash
bash scripts/m15_premerge_gate.sh
```
2. Execute final readiness smoke:
```bash
bash scripts/m16_release_readiness.sh
```
3. Review dependencies and security advisories (including Dependabot findings).

## Capacity Policy

- Baseline test profile: app constrained to `4 vCPU / 12 GB RAM`.
- Scale-up trigger:
  - sustained mixed p95 > 350 ms for 30+ min, or
  - sustained mixed throughput demand > 1100 req/s.
- First expansion step: `+2 vCPU`, then `+8 GB RAM` if memory pressure persists.

## KPI Targets

- mixed throughput: >= 700 req/s (gate threshold)
- mixed p95: <= 350 ms
- mixed error rate: <= 1%
- soak 180s error rate: 0%
