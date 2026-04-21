# Access Control Baseline

Status: updated for `1.6.0` (2026-04-21).

This document defines the minimum access-control model currently enforced by IOC Service for the admin surface and the supported versioned API surface.

## Current Enforcement Model

- The `/admin` surface requires a successful session-based login.
- Login uses the configured `ADMIN_API_TOKEN`.
- After a successful login, the session is marked with:
  - `admin_authenticated=true`
  - `admin_user_id=admin`
  - `admin_role=<ADMIN_ROLE>`
- State-changing `/admin` requests also require a valid CSRF token.
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
| `/api/v1/sync` | public write | queue trigger path preserved additively from legacy `/api/sync` |
| `/admin/*` | authenticated session + CSRF for writes | protected operator/admin plane |

Rationale for `1.6.0`:
- the milestone stabilizes and documents the existing API boundary rather than introducing a new machine-client auth system mid-migration,
- protected administration remains on `/admin/*`,
- future stronger machine-client auth can be layered onto `/api/v1/*` in a later milestone without changing the current compatibility story.

## Active Roles

### `admin`

Capabilities:
- view `/admin`
- create, update, delete, and enable/disable feeds
- test feed connections
- trigger syncs
- retry and cancel sync jobs
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

`1.6.0` keeps RBAC in the current token-backed admin model and explicitly documents the public/versioned API boundary. It does not add a multi-user database yet; that remains a larger identity-management project. The effective role is selected with `ADMIN_ROLE` and defaults to `admin`.
