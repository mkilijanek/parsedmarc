# Access Control Baseline

Status: introduced for `1.4.2` (2026-04-07).

This document defines the minimum access-control model currently enforced by IOC Service for the admin surface.

## Current Enforcement Model

- The `/admin` surface requires a successful session-based login.
- Login uses the configured `ADMIN_API_TOKEN`.
- After a successful login, the session is marked with:
  - `admin_authenticated=true`
  - `admin_user_id=admin`
  - `admin_role=admin`
- State-changing `/admin` requests also require a valid CSRF token.

## Active Roles

### `admin`

This is the only active role implemented in `1.4.2`.

Capabilities:
- view `/admin`
- create, update, delete, and enable/disable feeds
- test feed connections
- trigger syncs
- retry and cancel sync jobs
- access dangerous admin operations only after entering a valid `ADMIN_API_TOKEN`
  and the required confirmation values in the Web UI

## Reserved Future Roles

These roles are documented now so future work can extend the model without redefining the baseline:

### `operator`

Planned intent:
- view admin dashboards
- trigger syncs
- inspect jobs/logs
- no destructive configuration or wipe operations

### `viewer`

Planned intent:
- read-only access to status, feeds, and logs
- no state-changing admin actions

## Operational Requirements

- `ADMIN_API_TOKEN` must be explicitly provisioned before using `/admin`.
- `SECRET_KEY` must be explicitly provisioned; container startup must fail without it.
- Admin actions must be written to `audit_log` with actor, action, target, timestamp, and source IP.
- Destructive operations require CSRF validation, the admin token, the `WIPE` confirmation phrase,
  and the current instance name. They no longer require a separate `.env` feature flag.

## Scope Note

`1.4.2` establishes the baseline protection model, not a full user database or multi-user RBAC system. A richer role system remains future work, but this milestone removes the previously public admin surface and formalizes the current authorization boundary.
