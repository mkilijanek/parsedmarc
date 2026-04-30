# Data Protection Baseline

Status: updated for `1.8.0` + `compliance-1.0` (2026-04-30).

## Classification

| Class | Examples | Required Controls |
|---|---|---|
| public | health checks, public docs | integrity checks |
| internal | IOC values, feed statistics | access control and audit |
| confidential | admin sessions, runtime configuration | restricted admin access and audit |
| restricted | API keys, encrypted app settings, admin token | encryption at rest, redaction, rotation plan |

## In Transit

- Public application traffic is expected to terminate TLS at the nginx edge profile.
- External feed requests use HTTPS endpoints and explicit timeout handling.
- MISP SSL verification defaults to enabled.
- Internal PostgreSQL and Redis connections should stay on an isolated container or host network; remote deployments must use TLS or a private tunnel.

## At Rest

- `app_settings` rows marked as secrets are encrypted with AES-GCM derived from `SECRET_KEY`.
- Audit rows are chained with HMAC-SHA256 integrity hashes.
- Export files are written under `EXPORT_JOB_DIR`; production deployments must place this path on encrypted storage and enforce short retention.
- PostgreSQL and Redis volume encryption is an infrastructure control and must be enabled by the host, VM, or storage provider.

## Key Management

- `SECRET_KEY` must be explicitly provisioned and at least 32 characters.
- Rotate `SECRET_KEY` only with a planned maintenance window because it protects encrypted app settings and audit hash verification.
- Feed API keys should be changed at the provider and then updated through the admin settings path.

## Runtime and configuration posture in `1.6.0`

- Security-relevant configuration is now centralized through `app.config` grouped sections instead of parallel environment parsing in multiple runtime modules.
- `app/db.py` consumes `DatabaseConfig.from_env()` so database transport settings and pooling policy come from the same configuration layer as the rest of runtime policy.
- `requirements.txt` is limited to runtime dependencies, while `requirements-dev.txt` holds development and audit tooling; this makes the runtime package boundary explicit.
- `pyproject.toml` now carries project and tool metadata so packaging and quality controls are documented in one place.

## Resilience Controls (`1.8.0`)

- **DBCircuitBreaker**: database unavailability trips the circuit open after `DB_CIRCUIT_FAIL_THRESHOLD` (default 5) consecutive failures, protecting the application from connection-storm cascades. In `1.8.1` the cooldown is enforced before a single half-open probe is allowed, and real statement failures are observed through SQLAlchemy engine hooks.
- **Dead Letter Queue**: sync jobs that exhaust retries are persisted as `DeadLetterJob` rows with full error context, source feed, and timestamp. Operators can inspect the DLQ inventory and manually requeue jobs via the admin API once the root cause is resolved; repeated requeue attempts on the same DLQ row are now idempotent.

## Release Gate

Before a release:
- confirm dependency audit is clean,
- confirm audit integrity verification returns valid,
- confirm no secrets are present in logs or committed files,
- confirm production storage encryption is enabled by deployment policy,
- confirm DBCircuitBreaker thresholds are tuned for the target environment.
