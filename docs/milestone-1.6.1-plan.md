# Milestone 1.6.1 - Integration Adapter Boundary & Runtime Resilience

Status: delivered on `2026-04-21`

## Need and justification

`1.6.1` addressed two maintenance risks that remained after `1.6.0`:
- provider integrations were still orchestrated mostly as hardcoded service entry points,
- sync execution still relied on mutable process environment overrides for feed-specific runtime configuration.

That combination made provider evolution harder, increased coupling between app and worker runtime behavior, and created unnecessary risk for multi-job/process execution.

## Planned change

The milestone was executed as documentation-driven work with this sequence:
1. define the adapter/runtime boundary,
2. introduce shared DTOs, contracts, and registry,
3. add a shared ingestion pipeline,
4. replace runtime env mutation with scoped runtime overrides,
5. add adapter contract and pipeline tests,
6. update architecture and milestone documentation.

## Delivered implementation

- `app/adapters/contracts.py`
  - feed/export adapter protocols
- `app/adapters/types.py`
  - `CanonicalIOC`, `FetchBatch`, `AdapterCapabilities`
- `app/adapters/registry.py`
  - repo-local adapter registry
- `app/adapters/pipeline.py`
  - shared persistence pipeline, bounded DB retry, cache invalidation
- `app/adapters/feeds.py`
  - registered adapters for `crowdsec`, `misp`, `malwarebazaar`, `mwdb`, `abusech`
- `app/runtime_env.py`
  - scoped runtime override context and shared proxy settings cache
- `app/config.py`
  - config reads runtime overrides before process env
- `app/factory.py`, `app/worker.py`
  - no sync-job proxy/config mutation via `os.environ`
- `app/services/common.py`
  - runtime-aware sessions apply proxy/TLS behavior per session

## Acceptance summary

- provider execution now crosses one adapter boundary in scheduler runtime,
- shared pipeline is used for migrated adapter persistence,
- proxy/bootstrap behavior is consolidated,
- runtime env mutation is removed from sync execution and worker/app proxy bootstrap,
- fake adapter and pipeline tests exist in `tests/test_adapters.py`,
- full repository test suite passed after the change.

## Verification

- `ruff check ...`
- `python -m compileall -q app`
- `PYTHONPATH=. pytest -q`
