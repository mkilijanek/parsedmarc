# Milestone 1.6.0 Execution Plan

Status: active on 2026-04-21.

This milestone is delivered as documentation-driven work. The intended order is:
1. define need and scope,
2. document target changes,
3. implement,
4. update user/developer documentation,
5. run tests and fix regressions,
6. finish with documentation that matches the delivered state.

## Goal

Deliver `1.6.0` in full by introducing:
- an additive versioned API surface under `/api/v1/`,
- a published OpenAPI contract for the supported versioned surface,
- grouped configuration with one source of truth,
- modernized project metadata and runtime/dev dependency separation,
- a documented migration path from legacy API routes.

## Constraints

- Do not rewrite the full historical API in one batch.
- Do not mix unsupported legacy/internal endpoints into the supported OpenAPI contract.
- Do not break current deployment environment variable names during the first config refactor.
- Keep the rollout additive: legacy routes remain available until explicitly deprecated.

## Planned Work Packages

### 1. API surface definition

Need:
- the repository currently exposes useful API endpoints, but without a versioned public contract.

Deliverables:
- define the supported `/api/v1/` subset,
- explicitly label legacy routes as `stable`, `deprecated`, or `internal-only`,
- keep unsupported or admin-only routes outside the public versioned contract.

Initial `v1` candidate routes:
- `GET /api/v1/indicators`
- `POST /api/v1/sync`
- `GET /api/v1/feeds`
- `GET /api/v1/feeds/metrics`
- `GET /api/v1/runs/current`
- `GET /api/v1/logs`

### 2. OpenAPI contract

Need:
- `docs/api.md` is useful for humans but not a formal integration contract.

Deliverables:
- publish an OpenAPI file for the supported `v1` routes only,
- expose the spec from the application,
- validate the spec in tests/CI,
- add a simple documentation landing page for the contract.

### 3. Configuration refactor

Need:
- `app/config.py` is monolithic and `app/db.py` still reads env directly, which violates single-source-of-truth expectations.

Deliverables:
- split config into grouped sections,
- preserve `Config()` as the application entrypoint for backward compatibility,
- keep current env names working,
- route DB/runtime consumers through the grouped config model instead of raw env parsing.

### 4. Packaging and dependency split

Need:
- project metadata is missing from `pyproject.toml`,
- runtime and development dependencies are currently mixed in `requirements.txt`.

Deliverables:
- add `pyproject.toml` with project/tool metadata,
- keep `requirements.txt` as runtime-only,
- add `requirements-dev.txt` for test/lint/type dependencies,
- update bootstrap/CI scripts accordingly without breaking Docker runtime builds.

### 5. Documentation and migration notes

Need:
- clients and operators need a clear statement of which API surface is supported.

Deliverables:
- update `docs/api.md`,
- add migration notes for legacy vs `/api/v1/`,
- update configuration docs for the grouped config model,
- update developer instructions where packaging/bootstrap changed.

## Acceptance Criteria

- `/api/v1/` exists and is additive.
- OpenAPI is published only for supported `v1` routes.
- config has grouped sections and one source of truth.
- `app/db.py` no longer parses env directly.
- runtime/dev dependencies are separated.
- docs clearly distinguish versioned, legacy, and internal-only API surfaces.

## Verification Plan

- focused tests for `/api/v1/` contract and response shape,
- config unit tests for grouped config and backward compatibility,
- OpenAPI artifact validation test,
- full regression test run,
- compile/lint/type checks for touched modules.
