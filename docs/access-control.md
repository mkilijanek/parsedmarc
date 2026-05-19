# Access Control Baseline

Status: updated for `1.9.x` (2026-05-19).

This document defines the minimum access-control model currently enforced by IOC Service for the admin surface and the supported versioned API surface.

## Current Enforcement Model

- The `/admin` surface requires a successful session-based login.
- Login uses the configured `ADMIN_API_TOKEN`.
- Direct access to the plain HTTP app port for `/auth/*` and `/admin/*` is redirected to the canonical HTTPS edge entrypoint.
- After a successful login, the session is marked with:
  - `admin_authenticated=true`
  - `admin_user_id=admin`
  - `admin_role=<ADMIN_ROLE>`
- State-changing `/admin` requests also require a valid CSRF token.
- The login surface is rate-limited and now returns an operator-facing HTML response when the limit is exceeded.
- `/admin` requests are checked against a role-permission matrix before route execution.
- `/api/v1/*` is the supported machine-facing API contract and remains unauthenticated in `1.6.0`, matching the legacy public API model.
- Legacy `/api/*` routes with `/api/v1/*` successors are transitional compatibility routes, not a separate privilege plane.

## Supported surface boundary

| Surface | Access model | Notes |
|---|---|---|
| `/api/v1/indicators` | public read | versioned contract for programmatic queries |
| `/api/v1/feeds` | public read | operational metadata, not admin session-backed |
| `/api/v1/feeds/metrics` | public read | telemetry surface matching current public API posture |
| `/api/v1/runs/current` | public read | scheduler/job state view |
| `/api/v1/logs` | public read | structured logs API, same visibility model as legacy API |
| `/api/v1/sync` | **admin token required** | `X-Admin-Token` header; 401 without valid token |
| `/api/events` | public read | SSE stream: heartbeat, indicator count, sync status, feed health |
| `/api/sync` | **admin token required** | legacy; prefer `/api/v1/sync` |
| `/api/sentinel/export` | **admin token required** | `X-Admin-Token` header; 401 without valid token |
| `/admin/*` | authenticated session + CSRF for writes | protected operator/admin plane |
| `/admin/api/dead-letter-jobs` | authenticated session | DLQ inventory and manual requeue |
| `/admin/api/db-circuit` | authenticated session | DBCircuitBreaker state query |
| `/admin/audit/*` | no authentication enforced (gap SEC-1) | audit verify/report; should be admin-only |

Rationale for `1.8.0` (updated 2026-05-16):
- admin surface is fully session-protected (since 1.4.2), with CSRF tokens on all state-changing flows,
- `/api/v1/*` read surfaces remain publicly readable, matching the legacy API posture,
- **`POST /api/v1/sync`, `POST /api/sync`, `POST /api/sentinel/export`** now require `X-Admin-Token` header; these are write/trigger operations — unauthenticated access was a security gap,
- **Admin token is not accepted via query string** (`?admin_token=`); tokens in URLs appear in access logs, browser history, and `Referer` headers,
- **Async export jobs** (`GET /indicators/<fmt>?async=1`, `POST /api/sentinel/export`) return a per-job `access_token` in the response. Status and download endpoints require this token via `?token=<access_token>`. Without a valid token the endpoints return `403 Forbidden`. The token is not an admin credential and is scoped to one job only. Artifacts expire after `EXPORT_JOB_TTL_HOURS` (default 24 h); expired jobs return `410 Gone`.
- `auth_mode` for Sentinel export is read from server config (`AZURE_SENTINEL_AUTH_MODE`), not from caller parameters,
- `/api/events` SSE stream is publicly readable (operational transparency). In `1.8.1` it is bounded by explicit duration/capacity limits and rejected on sync workers by default,
- machine-client auth for `/api/v1/*` read routes remains a future milestone,
- known gap: `/admin/audit/*` endpoints not covered by admin auth middleware (SEC-1).

## Active Roles

### `admin`

Capabilities:
- view `/admin`
- create, update, delete, and enable/disable feeds
- test feed connections
- trigger syncs
- retry and cancel sync jobs
- requeue dead-letter jobs from the DLQ
- inspect DBCircuitBreaker state
- verify audit log integrity (`/admin/audit/verify`)
- access dangerous admin operations only after entering a valid `ADMIN_API_TOKEN`
  and the required confirmation values in the Web UI

### `operator`

Capabilities:
- view admin dashboards
- trigger syncs
- inspect jobs/logs
- no destructive configuration or wipe operations

### `viewer`

Capabilities:
- read-only access to status, feeds, and logs
- no state-changing admin actions

## Operational Requirements

- `ADMIN_API_TOKEN` must be explicitly provisioned before using `/admin`.
- Operators should use the HTTPS edge URL for admin login so the secure session cookie is preserved.
- `SECRET_KEY` must be explicitly provisioned; container startup must fail without it.
- Admin actions must be written to `audit_log` with actor, action, target, timestamp, and source IP.
- Destructive operations require CSRF validation, the admin token, the `WIPE` confirmation phrase,
  and the current instance name. They no longer require a separate `.env` feature flag.

## Permission Matrix

| Permission | admin | operator | viewer |
|---|---:|---:|---:|
| `admin:read` | yes | yes | yes |
| `feed:configure` | yes | no | no |
| `feed:sync` | yes | yes | no |
| `indicator:read` | yes | yes | yes |
| `indicator:export` | yes | yes | no |
| `logs:view` | yes | yes | yes |
| `audit:view` | yes | yes | no |
| `system:dangerous` | yes | no | no |

## Scope Note

`1.6.1` keeps RBAC in the current token-backed admin model and explicitly documents the public/versioned API boundary. It does not add a multi-user database yet; that remains a larger identity-management project. The effective role is selected with `ADMIN_ROLE` and defaults to `admin`.
