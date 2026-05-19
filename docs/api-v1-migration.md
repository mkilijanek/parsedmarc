# API v1 Migration Guide

Status: updated for `1.9.x` (2026-05-19).

This guide documents the additive migration from selected legacy `/api/*` endpoints to the supported versioned API surface under `/api/v1/*`.

## Migration policy

- `/api/v1/*` is the supported contract for programmatic clients starting with milestone `1.6.0`.
- legacy `/api/*` endpoints remain available during the migration window.
- legacy endpoints with a `/api/v1/*` replacement return deprecation headers.
- payload semantics are intentionally kept close to the legacy behavior in this milestone to avoid unnecessary client breakage.

## Route mapping

| Legacy route | Supported successor | Notes |
|---|---|---|
| `POST /api/sync` | `POST /api/v1/sync` | same enqueue model; versioned route uses `trigger_type=api_v1` |
| `GET /api/feeds` | `GET /api/v1/feeds` | inventory/state surface is preserved additively |
| `GET /api/feeds/metrics` | `GET /api/v1/feeds/metrics` | metrics window logic preserved |
| `GET /api/runs/current` | `GET /api/v1/runs/current` | same scheduler/job semantics |
| `GET /api/logs` | `GET /api/v1/logs` | same filter model |

## Legacy status labels

- `stable`: route remains supported and has no planned versioned replacement in this milestone.
- `deprecated`: route has a `/api/v1/*` successor and should be migrated.
- `internal-only`: route is operational or admin-specific and not part of the public machine contract.

## Response headers on deprecated routes

Deprecated legacy routes now include:

```http
Deprecation: true
Sunset: Wed, 31 Dec 2026 23:59:59 GMT
Link: </api/v1/...>; rel="successor-version"
```

## Recommended client migration steps

1. Switch integrations from legacy `/api/*` routes to their `/api/v1/*` successors.
2. Treat `/api/v1/openapi.yaml` as the contract source for the supported versioned subset.
3. Keep legacy fallback support only during the transition window.
4. Do not assume admin or HTML routes will be versioned or supported as machine-client contracts.

## Non-goals in `1.6.0`

- No broad payload redesign.
- No new machine-client auth scheme introduced solely because versioning now exists.
- No commitment that every historical operational route will move under `/api/v1/*`.
