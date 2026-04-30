# Configuration

Status: updated for `1.8.0` + `compliance-1.0` (2026-04-30).

## Environment Variables

All configuration is done via environment variables. No config files are required, but milestone `1.6.0` reorganizes the runtime config model into grouped sections while preserving backward compatibility for existing environment variable names.

---

## Setting priority model

Certain settings are overridable at runtime via the database (`app_settings` table, managed through
the admin panel). The **resolution order depends on `APP_ENV`**:

| `APP_ENV` | Priority order |
|-----------|---------------|
| `development` (default) | **env var → DB → coded default** |
| `production` | **DB → env var → coded default** |

### Rationale

- **Development**: operators iterate quickly with `.env` files. An env var set in the shell or
  `.env` should take immediate effect without touching the database.
- **Production**: administrators change settings live through the admin panel (DB). A container
  restart must not silently overwrite a DB-stored value with a stale env var from the compose file.

### Which settings use DB-override

The following settings can be stored in the `app_settings` table and are resolved with the
priority model above:

| Setting | DB key | Type |
|---------|--------|------|
| `ADMIN_PANEL_ENABLED` | `feedcfg.security.admin_panel_enabled` | bool |
| `ADMIN_AUTH_ENABLED` | `feedcfg.security.admin_auth_enabled` | bool |
| `ADMIN_API_TOKEN` | `feedsecret.security.admin_api_token` | secret |
| `ADMIN_LOGIN_RATE_LIMIT` | `feedcfg.security.admin_login_rate_limit` | string |
| `ADMIN_LOGIN_RATE_LIMIT_WINDOW_MINUTES` | `feedcfg.security.admin_login_rate_limit_window_minutes` | int |

Settings **not** in this table (e.g. `DATABASE_URL`, `SECRET_KEY`, `REDIS_URL`) are always
read from the environment only and are never overridable via the database.

---

## Image variants

Two published images cover different deployment topologies:

### `ghcr.io/mkilijanek/ioc-service` — HTTP variant (plain upstream)

Use behind an external TLS terminator (F5, VS, Cloudflare, nginx outside this stack) or in
trusted internal networks. The app itself speaks plain HTTP.

Required / recommended env overrides:

```bash
APP_ENV=production           # or development for lab
EDGE_HTTPS_ENABLED=false     # disable internal HTTPS redirect and Secure cookie
SESSION_COOKIE_SECURE_ENABLED=false
HSTS_ENABLED=false

# Admin panel — choose one:
ADMIN_PANEL_ENABLED=false    # hide /admin entirely (recommended for read-only deployments)
ADMIN_PANEL_ENABLED=true
ADMIN_AUTH_ENABLED=false     # panel open without login (dev/lab only)
ADMIN_AUTH_ENABLED=true      # panel requires ADMIN_API_TOKEN
ADMIN_API_TOKEN=<token>      # required when ADMIN_AUTH_ENABLED=true
ADMIN_AUTH_ALLOW_DISABLED_IN_PRODUCTION=false
```

### `ghcr.io/mkilijanek/ioc-service-tls` — TLS edge (nginx sidecar)

Bundles an nginx TLS terminator. The app container still speaks plain HTTP internally;
nginx handles TLS towards clients.

Required / recommended env overrides:

```bash
APP_ENV=production
EDGE_HTTPS_ENABLED=true      # enable HTTPS redirect and Secure cookie (default)
SESSION_COOKIE_SECURE_ENABLED=true
NGINX_TLS_ENABLED=true       # nginx speaks TLS (default)

# HSTS — optional, enable only after verifying HTTPS works end-to-end
HSTS_ENABLED=true            # app-level HSTS header
NGINX_HSTS_ENABLED=true      # nginx-level HSTS header

# Admin panel
ADMIN_PANEL_ENABLED=true     # (default) panel is visible
ADMIN_AUTH_ENABLED=true      # (default) panel requires login
ADMIN_API_TOKEN=<token>      # required — set a strong random token
# or to allow panel without login (lab only, explicit unsafe override required):
ADMIN_AUTH_ENABLED=false
ADMIN_AUTH_ALLOW_DISABLED_IN_PRODUCTION=true
```

SSL certificate sourcing for the TLS variant: see `docs/deployment.md`.

## Configuration model in `1.6.0`

`app/config.py` now exposes grouped sections:
- `runtime`
- `database`
- `feeds`
- `worker`
- `security`

Example:

```python
from app.config import Config

cfg = Config()
cfg.database.DATABASE_URL
cfg.security.ADMIN_SESSION_COOKIE_NAME
cfg.worker.UPDATE_INTERVAL
```

Compatibility note:
- existing code that still reads `cfg.DATABASE_URL` or `cfg.UPDATE_INTERVAL` continues to work through compatibility accessors.
- environment variable names remain unchanged in `1.6.0`.

## Runtime hardening in `1.8.1`

- `ADMIN_AUTH_ENABLED=false` is blocked in `APP_ENV=production` unless `ADMIN_AUTH_ALLOW_DISABLED_IN_PRODUCTION=true` is also set.
- `/api/events` is enabled by `SSE_ENABLED=true` and now has explicit safety bounds:
  - `SSE_HEARTBEAT_INTERVAL_S`
  - `SSE_MAX_DURATION_S`
  - `SSE_MAX_CONNECTIONS`
  - `SSE_ALLOW_SYNC_WORKERS`
- Default container runtime now uses Gunicorn `gthread` workers to avoid trivial starvation from long-lived SSE clients.

## Configuration source of truth

`app/db.py` no longer parses database environment variables independently. Database engine setup now reads from `DatabaseConfig.from_env()` in `app.config`, so runtime configuration has one parsing layer instead of duplicated environment reads.

## Packaging and dependency split

Milestone `1.6.0` introduces:
- `pyproject.toml` for project metadata and tool configuration
- `requirements.txt` for runtime dependencies only
- `requirements-dev.txt` for local development, test, lint, and audit tooling

Recommended local bootstrap:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## New in `1.8.0` — Resilience and retention

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_TTL` | `300` | Redis cache TTL in seconds (also drives cache warming cadence) |
| `LOG_RETENTION_DAYS` | `90` | Auto-purge `app_logs` rows older than N days (0 = disabled) |
| `AUDIT_INTEGRITY_VERIFY_INTERVAL_S` | `3600` | Interval between scheduled audit hash chain verifications |
| `SYNC_JOB_MAX_RETRIES` | `3` | Max retries before a sync job moves to the DLQ |

DBCircuitBreaker thresholds (hardcoded in `app/services/common.py`):
- `fail_threshold=5` — consecutive DB failures before circuit opens
- `cooldown_s=30` — seconds before half-open probe after open

---

## New in 1.1.x (Feeds & Sync)

### Feed Transport / Retry

```bash
FEED_HTTP_TIMEOUT_S=30
FEED_RETRY_ATTEMPTS=4
FEED_RETRY_BASE_DELAY_S=1
```

### Feed-level Rate Limits (global defaults + optional per-source override)

```bash
FEED_RATE_LIMIT_ENABLED=true
FEED_REQUESTS_PER_SECOND=10
FEED_REQUESTS_PER_MINUTE=55
```

Optional per source (example for MWDB):

```bash
FEED_REQUESTS_PER_SECOND_MWDB=5
FEED_REQUESTS_PER_MINUTE_MWDB=40
```

### MISP Feed Options

```bash
MISP_MAX_TLP=AMBER          # Maximum TLP level to ingest; attributes above this are skipped silently.
                             # Valid: WHITE, GREEN, AMBER, RED. Default: AMBER (TLP:RED not ingested).
MISP_HEALTH_TIMEOUT_S=3     # Timeout (seconds) for the lightweight MISP connectivity check in /health.
                             # Does not affect full sync timeout (MISP_SYNC_TIMEOUT_S).
```

### MWDB Feed Options

```bash
MWDB_TAGS=apt,malware
MWDB_DAYS=30
MWDB_NO_TIME_LIMIT=false
MWDB_ORGANIZATIONS=
MWDB_CUSTOM_FILTER=
MWDB_MY_GROUP=          # MWDB group name; indicators uploaded by this group receive TLP:AMBER
MWDB_DEFAULT_QUERY=type:*  # Fallback Lucene query when no MWDB_TAGS or MWDB_CUSTOM_FILTER set
```

`MWDB_CUSTOM_FILTER` is optional and appended to MWDB query expression.

`MWDB_MY_GROUP` can also be set via the Admin → Feed configuration UI (persisted in DB settings).

`MWDB_DEFAULT_QUERY` prevents empty-query edge cases on MWDB deployments that require a query parameter. Change only if your MWDB instance uses a different default scope.

### Circuit Breaker Configuration

Shared `CircuitBreaker` (`app/services/common.py`) is used by abusech, mwdb, and misp.
It opens after N consecutive failures and waits COOLDOWN_S before attempting again.

| Variable                        | Default | Description                               |
|---------------------------------|---------|-------------------------------------------|
| ABUSECH_CIRCUIT_FAIL_THRESHOLD  | 3       | Consecutive failures to open circuit      |
| ABUSECH_CIRCUIT_COOLDOWN_S      | 300     | Cooldown seconds after circuit opens      |
| MWDB_CIRCUIT_FAIL_THRESHOLD     | 3       | Same, for MWDB                            |
| MWDB_CIRCUIT_COOLDOWN_S         | 300     | Same, for MWDB                            |
| MISP_CIRCUIT_FAIL_THRESHOLD     | 3       | Same, for MISP                            |
| MISP_CIRCUIT_COOLDOWN_S         | 300     | Same, for MISP                            |

Circuit state is logged with keys `circuit_open` / `circuit_recovered` (field: `source`).
To force a reset, restart the worker.

---

## Core Configuration

### SECRET_KEY (REQUIRED)

**Type:** String  
**Minimum Length:** 32 characters  
**Purpose:** Flask session signing and security  
**Security:** CRITICAL - Must be unique and secret

```bash
# Generate secure key
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
```

**Error if not set:**
```
SECURITY ERROR: SECRET_KEY environment variable must be set.
Generate a secure key with: python -c 'import secrets; print(secrets.token_hex(32))'
```

### LOG_LEVEL

**Type:** String  
**Default:** `INFO`  
**Options:** `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

```bash
LOG_LEVEL=INFO
```

### LOG_RETENTION_DAYS

**Type:** Integer  
**Default:** `90`  
**Purpose:** Automatically purge `app_logs` table rows older than this many days. The daily cleanup job runs in the scheduler. Set to `0` to disable automatic cleanup.

> **Note**: `audit_log` rows are **not** purged automatically — the HMAC hash chain must remain intact. Retain audit records per your compliance requirement (ISO 27001 recommends minimum 1 year).

```bash
LOG_RETENTION_DAYS=90      # default
LOG_RETENTION_DAYS=365     # retain 1 year (compliance deployments)
LOG_RETENTION_DAYS=0       # disable automatic cleanup
```

### REQUESTS_PER_SECOND_MAX

**Type:** Integer  
**Default:** `1000000`  
**Purpose:** Global hard safety cap for incoming request rate (application-level guardrail)

```bash
REQUESTS_PER_SECOND_MAX=1000000
```

### RATE_LIMITS_ENABLED

**Type:** Boolean  
**Default:** `true`  
**Purpose:** Enable Flask-Limiter endpoint limits (`20/min`, `30/min`, etc.)

```bash
RATE_LIMITS_ENABLED=true
```

Use `false` only for controlled benchmark environments.

### QUERY_RESULT_LIMIT_MAX

**Type:** Integer  
**Default:** `10000`  
**Purpose:** Maximum `limit` accepted by `/indicators`

```bash
QUERY_RESULT_LIMIT_MAX=10000
```

### EXPORT_RESULT_LIMIT_MAX

**Type:** Integer  
**Default:** `200000`  
**Purpose:** Maximum `limit` accepted by `/indicators/<format>`

```bash
EXPORT_RESULT_LIMIT_MAX=200000
```

### CORRELATION_LIMIT_MAX

**Type:** Integer  
**Default:** `5000`  
**Purpose:** Maximum `limit` accepted by `/correlations`

```bash
CORRELATION_LIMIT_MAX=5000
```

### HEALTH_CACHE_TTL

**Type:** Integer (seconds)  
**Default:** `5`  
**Purpose:** Short-lived Redis cache for `/health` to reduce DB/Redis probe pressure under load

```bash
HEALTH_CACHE_TTL=5
```

### CORRELATION_CACHE_TTL

**Type:** Integer (seconds)  
**Default:** `30`  
**Purpose:** Redis cache TTL for `/correlations` responses

```bash
CORRELATION_CACHE_TTL=30
```

### CORRELATION_SNAPSHOT_ENABLED

**Type:** Boolean  
**Default:** `true`  
**Purpose:** Enable worker-driven preaggregation snapshots for `/correlations`

```bash
CORRELATION_SNAPSHOT_ENABLED=true
```

### CORRELATION_SNAPSHOT_INTERVAL

**Type:** Integer (seconds)  
**Default:** `60`  
**Purpose:** Snapshot refresh interval in background worker

```bash
CORRELATION_SNAPSHOT_INTERVAL=60
```

### CORRELATION_SNAPSHOT_MIN_SOURCES

**Type:** Integer  
**Default:** `2`  
**Purpose:** `min_sources` used for generated snapshots

```bash
CORRELATION_SNAPSHOT_MIN_SOURCES=2
```

### CORRELATION_SNAPSHOT_LIMIT

**Type:** Integer  
**Default:** `1000`  
**Purpose:** `limit` used for generated snapshots

```bash
CORRELATION_SNAPSHOT_LIMIT=1000
```

### CORRELATION_SNAPSHOT_TYPES

**Type:** Comma-separated string  
**Default:** `all,domain,ip,url,hash,email`  
**Purpose:** IOC types to precompute for correlation snapshots

```bash
CORRELATION_SNAPSHOT_TYPES=all,domain,ip,url,hash,email
```

---

## Database Configuration

### DATABASE_URL (REQUIRED)

**Type:** PostgreSQL connection string  
**Format:** `postgresql+psycopg2://user:pass@host:port/db`

```bash
DATABASE_URL=postgresql+psycopg2://threatfeed:PASSWORD@postgres:5432/threatfeed
```

**Connection Pool:**
- Pool size: controlled by `DB_POOL_SIZE` (default: 6)
- Max overflow: controlled by `DB_MAX_OVERFLOW` (default: 4)
- Pool pre-ping: Enabled (detects stale connections)
- Pool recycle: controlled by `DB_POOL_RECYCLE` (default: 1800s)

---

## Cache Configuration

### REDIS_URL (REQUIRED)

**Type:** Redis connection string  
**Format:** `redis://[:password]@host:port/db`

```bash
REDIS_URL=redis://:PASSWORD@redis:6379/0
```

### DB_POOL_SIZE

**Type:** Integer  
**Default:** `6`  
**Purpose:** Base SQLAlchemy connection pool size per process

```bash
DB_POOL_SIZE=6
```

### DB_MAX_OVERFLOW

**Type:** Integer  
**Default:** `4`  
**Purpose:** Additional burst connections above pool size

```bash
DB_MAX_OVERFLOW=4
```

### DB_POOL_TIMEOUT

**Type:** Integer (seconds)  
**Default:** `30`  
**Purpose:** Max wait time for a free DB connection from pool

```bash
DB_POOL_TIMEOUT=30
```

### DB_POOL_RECYCLE

**Type:** Integer (seconds)  
**Default:** `1800`  
**Purpose:** Lifetime of pooled DB connections before recycle

```bash
DB_POOL_RECYCLE=1800
```

### CACHE_TTL

**Type:** Integer (seconds)  
**Default:** `300` (5 minutes)  
**Purpose:** Response cache expiration time

```bash
CACHE_TTL=300
```

---

## Security Configuration

### ALLOWED_HOSTS

**Type:** Comma-separated hostnames  
**Default:** `*` (allow all)  
**Purpose:** Host header validation

```bash
# Production example
ALLOWED_HOSTS=localhost,threatfeed.example.com,10.0.0.5

# Development (allow all)
ALLOWED_HOSTS=*
```

### APP_ENV

**Type:** String (`development` | `production`)  
**Default:** `development`  
**Purpose:** Runtime mode switch for production safety checks.

```bash
APP_ENV=production
```

### TRUSTED_PROXY_COUNT

**Type:** Integer  
**Default:** `0` (don't trust X-Forwarded-For)  
**Purpose:** Number of trusted reverse proxies

```bash
# Behind nginx only
TRUSTED_PROXY_COUNT=1

# Behind nginx + cloudflare
TRUSTED_PROXY_COUNT=2

# Direct connection (no proxy)
TRUSTED_PROXY_COUNT=0
```

**How it works:**
- `0`: Use `request.remote_addr` (direct connection)
- `1`: Trust 1 proxy (take client IP from X-Forwarded-For)
- `2+`: Trust N proxies (take IP at position from right)

### Outbound Proxy/TLS Settings

Use these variables when connectors (MWDB, abuse.ch, MalwareBazaar, MISP, CrowdSec)
must route through a corporate proxy.

```bash
HTTP_PROXY=http://proxy.example.local:8080
HTTPS_PROXY=http://proxy.example.local:8080
NO_PROXY=localhost,127.0.0.1,postgres,redis,.internal
REQUESTS_CA_BUNDLE=/etc/ssl/certs/org-ca.pem
REQUESTS_SKIP_TLS_VERIFY=false
```

**Notes:**
- `REQUESTS_CA_BUNDLE`: preferred for TLS interception environments (secure).
- `REQUESTS_SKIP_TLS_VERIFY=true`: insecure fallback (equivalent to `curl -k`), use only temporarily.
- Admin UI (`/admin`) can persist proxy settings in DB (`proxy.http_url`, `proxy.https_url`, `proxy.no_proxy`, `proxy.ca_bundle_path`, `proxy.skip_tls_verify`); worker/app bootstrap these values at runtime.

Optional per-feed proxy override (advanced):

```bash
FEED_PROXY_URL_MWDB=http://proxy-for-mwdb.local:8080
FEED_PROXY_URL_ABUSECH=http://proxy-for-abusech.local:8080
FEED_HTTP_PROXY_MWDB=http://proxy-http.local:8080
FEED_HTTPS_PROXY_MWDB=http://proxy-https.local:8080
```

Name format: `FEED_PROXY_URL_<SOURCE>` (or `FEED_HTTP_PROXY_<SOURCE>`, `FEED_HTTPS_PROXY_<SOURCE>`) where source is uppercase with non-alphanumeric chars replaced by `_` (for example `abusech`, `mwdb`).

### CORS_ORIGINS

**Type:** Comma-separated origins  
**Default:** `*`  
**Purpose:** CORS allowed origins (future)

```bash
CORS_ORIGINS=https://dashboard.example.com,https://app.example.com
```

### SECURITY_ALLOW_PERMISSIVE_DEFAULTS

**Type:** Boolean  
**Default:** `false`  
**Purpose:** Emergency override for permissive `ALLOWED_HOSTS=*` / `CORS_ORIGINS=*` in production.

```bash
# only for temporary break-glass usage
SECURITY_ALLOW_PERMISSIVE_DEFAULTS=true
```

When `APP_ENV=production` and this flag is `false`, startup fails if `ALLOWED_HOSTS` or `CORS_ORIGINS` remains `*`.

---

## Integration Configuration

### MISP Integration

#### MISP_URL

**Type:** URL  
**Default:** Empty (disabled)  
**Purpose:** MISP instance base URL

```bash
MISP_URL=https://misp.example.com
```

#### MISP_API_KEY

**Type:** String (API key)  
**Default:** Empty (disabled)  
**Purpose:** MISP API authentication

```bash
MISP_API_KEY=your-misp-api-key-here
```

#### MISP_VERIFY_SSL

**Type:** Boolean  
**Default:** `true` (SECURE DEFAULT)  
**Purpose:** Verify MISP SSL certificates

```bash
# Production (default, recommended)
MISP_VERIFY_SSL=true

# Development with self-signed certs ONLY
MISP_VERIFY_SSL=false
```

**Security Note:** Changed from `false` to `true` in security audit. Always use `true` in production to prevent MITM attacks.

#### MISP_DAYS

**Type:** Integer  
**Default:** `7`  
**Purpose:** Number of days to fetch MISP events

```bash
MISP_DAYS=7
```

---

### CrowdSec Integration

#### CROWDSEC_API_KEY

**Type:** String (API key)  
**Default:** Empty (disabled)  
**Purpose:** CrowdSec API authentication

```bash
CROWDSEC_API_KEY=your-crowdsec-api-key
```

#### CROWDSEC_LISTS

**Type:** Comma-separated list IDs  
**Default:** Empty  
**Purpose:** CrowdSec blocklists to fetch

```bash
CROWDSEC_LISTS=list1,list2,list3
```

---

### MalwareBazaar Integration

#### MALWAREBAZAAR_API_URL

**Type:** URL  
**Default:** `https://mb-api.abuse.ch/api/v1/`  
**Purpose:** MalwareBazaar API endpoint (authentication uses `ABUSECH_AUTH_KEY`)

```bash
MALWAREBAZAAR_API_URL=https://mb-api.abuse.ch/api/v1/
```

#### MALWAREBAZAAR_SINCE_DATE

**Type:** ISO date (YYYY-MM-DD)  
**Default:** Empty  
**Purpose:** Fetch samples since this date

```bash
MALWAREBAZAAR_SINCE_DATE=2025-01-01
```

#### MALWAREBAZAAR_TAGS

**Type:** Comma-separated string  
**Default:** Empty  
**Purpose:** Worker tag list used for automatic MalwareBazaar ingestion

```bash
MALWAREBAZAAR_TAGS=TrickBot,Emotet
```

#### MALWAREBAZAAR_LIMIT

**Type:** Integer  
**Default:** `1000`  
**Purpose:** Max number of indicators fetched per MalwareBazaar worker run

```bash
MALWAREBAZAAR_LIMIT=1000
```

---

### MWDB Integration

#### MWDB_URL

**Type:** URL  
**Default:** Empty (disabled)  
**Purpose:** MWDB instance base URL

```bash
MWDB_URL=https://mwdb.cert.pl
```

#### MWDB_AUTH_KEY

**Type:** String (API key)  
**Default:** Empty (disabled)  
**Purpose:** MWDB API authentication

```bash
MWDB_AUTH_KEY=your-mwdb-api-key
```

#### MWDB_TAGS

**Type:** Comma-separated string  
**Default:** Empty  
**Purpose:** Worker tag list used for automatic MWDB ingestion

```bash
MWDB_TAGS=malware,apt
```

#### MWDB_LIMIT

**Type:** Integer  
**Default:** `1000`  
**Purpose:** Max number of indicators fetched per MWDB worker run

```bash
MWDB_LIMIT=1000
```

---

### abuse.ch Extended Integrations

#### ABUSECH_AUTH_KEY

**Type:** String (API key)  
**Default:** Empty  
**Purpose:** Shared auth key for abuse.ch APIs (ThreatFox/YARAify/Hunting). Source-specific keys can override.

```bash
ABUSECH_AUTH_KEY=your-auth-key
```

#### THREATFOX_* variables

```bash
THREATFOX_ENABLED=true
THREATFOX_API_URL=https://threatfox-api.abuse.ch/api/v1/
THREATFOX_AUTH_KEY=
THREATFOX_DAYS=3
THREATFOX_LIMIT=1000
```

#### URLHAUS_* variables

```bash
URLHAUS_ENABLED=true
URLHAUS_FEED_URL=https://urlhaus.abuse.ch/downloads/text_online/
URLHAUS_LIMIT=10000
```

#### FEODOTRACKER_* variables

```bash
FEODOTRACKER_ENABLED=true
FEODOTRACKER_FEED_URL=https://feodotracker.abuse.ch/downloads/ipblocklist.txt
FEODOTRACKER_LIMIT=10000
```

#### YARAIFY_* variables

```bash
YARAIFY_ENABLED=true
YARAIFY_API_URL=https://yaraify-api.abuse.ch/api/v1/
YARAIFY_AUTH_KEY=
YARAIFY_IDENTIFIER=
YARAIFY_LOOKUP_HASHES=
YARAIFY_TASK_STATUS=processed
YARAIFY_LIMIT=250
```

#### HUNTING_FPLIST_* variables

```bash
HUNTING_FPLIST_ENABLED=true
HUNTING_API_URL=https://hunting-api.abuse.ch/api/v1/
HUNTING_AUTH_KEY=
HUNTING_FPLIST_FORMAT=csv
HUNTING_FPLIST_LIMIT=10000
```

#### Database-backed abuse.ch component overrides

The Admin feed configuration stores abuse.ch component selections in `app_settings` and the `abusech` service reads those settings directly during worker execution. Persisted values take precedence over process environment defaults for:

- `feedcfg.abusech.threatfox_enabled`
- `feedcfg.abusech.urlhaus_enabled`
- `feedcfg.abusech.feodotracker_enabled`
- `feedcfg.abusech.yaraify_enabled`
- `feedcfg.abusech.hunting_fplist_enabled`
- `feedsecret.abusech.api_key`
- `feedsecret.abusech.yaraify_auth_key`
- `feedsecret.abusech.hunting_auth_key`
- `feedcfg.abusech.yaraify_identifier`
- `feedcfg.abusech.yaraify_lookup_hashes`
- `feedcfg.abusech.hunting_fplist_format`

This avoids the earlier operational gap where scheduled worker runs could still follow stale environment-only component toggles after an operator changed abuse.ch settings in the database.

#### ABUSECH hardening variables

```bash
ABUSECH_TIMEOUT_S=30
ABUSECH_RETRY_ATTEMPTS=4
ABUSECH_RETRY_BASE_DELAY_S=1
ABUSECH_CIRCUIT_FAIL_THRESHOLD=3
ABUSECH_CIRCUIT_COOLDOWN_S=300
```

#### Feed outbound rate limiting (all external feed integrations)

```bash
FEED_RATE_LIMIT_ENABLED=true
FEED_REQUESTS_PER_SECOND=10
FEED_REQUESTS_PER_MINUTE=55
```

- Applies to outbound requests for: `malwarebazaar`, `mwdb`, and abuse.ch feeds/APIs.
- Use `FEED_RATE_LIMIT_ENABLED=false` only in controlled benchmark/test scenarios.

---

## Worker Configuration

### DEP_HEALTH_INTERVAL_S

**Type:** Integer (seconds)
**Default:** `60`
**Purpose:** Interval for the dependency health refresh job that probes external services (MISP, …) and updates `/deps` independently of feed sync jobs.

```bash
DEP_HEALTH_INTERVAL_S=60
```

Set lower (e.g. `30`) for faster recovery detection; set higher to reduce probe frequency.

### ENABLE_BACKGROUND_JOBS

**Type:** Boolean  
**Default:** `true`  
**Purpose:** Enable background feed updates

```bash
# Enable worker (default)
ENABLE_BACKGROUND_JOBS=true

# Disable worker (API-only mode)
ENABLE_BACKGROUND_JOBS=false
```

### UPDATE_INTERVAL

**Type:** Integer (seconds)  
**Default:** `600` (10 minutes)  
**Purpose:** Feed update interval

```bash
# Update every 10 minutes (default)
UPDATE_INTERVAL=600

# Update every 5 minutes
UPDATE_INTERVAL=300

# Update every hour
UPDATE_INTERVAL=3600
```

### WORKER_HEALTH_HOST / WORKER_HEALTH_PORT

**Type:** String / integer
**Default:** `0.0.0.0` / `8091`
**Purpose:** Lightweight worker health server. It exposes `/healthz` and `/metrics` from the worker process and is used by the Docker healthcheck.

```bash
WORKER_HEALTH_HOST=0.0.0.0
WORKER_HEALTH_PORT=8091
WORKER_HEALTH_MAX_LOOP_AGE_S=120
```

Set `WORKER_HEALTH_PORT=0` to disable the worker health server.

### WORKER_SHUTDOWN_GRACE_S

**Type:** Integer (seconds)
**Default:** `30`
**Purpose:** Grace period for shutdown after SIGTERM/SIGINT. The worker stops accepting new jobs and waits for active jobs before closing the DB pool.

### SYNC_JOB_MAX_RETRIES / SYNC_JOB_RETRY_BASE_DELAY_S

**Type:** Integer
**Default:** `3` retries, `30` seconds base delay
**Purpose:** Automatic retry policy for transient sync-job failures. Delay uses exponential backoff and is capped by `SYNC_JOB_RETRY_MAX_DELAY_S`.

```bash
SYNC_JOB_MAX_RETRIES=3
SYNC_JOB_RETRY_BASE_DELAY_S=30
SYNC_JOB_RETRY_MAX_DELAY_S=900
```

---

## Docker Configuration

### APP_PORT

**Type:** Integer  
**Default:** `8080`  
**Purpose:** Application listening port

```bash
APP_PORT=8080
```

### WORKERS

**Type:** Integer  
**Default:** `3`  
**Purpose:** Number of Gunicorn workers

```bash
# Shared-host baseline (4 vCPU / 12 GB budget)
WORKERS=3
```

**Formula:** `(2 × CPU_CORES) + 1`

### GUNICORN_TIMEOUT

**Type:** Integer (seconds)  
**Default:** `120`  
**Purpose:** Gunicorn worker timeout

```bash
GUNICORN_TIMEOUT=120
```

---

## SSL/TLS Configuration

### SSL_CERT_PATH

**Type:** File path  
**Default:** `./ssl/cert.pem`  
**Purpose:** SSL certificate path (for nginx)

```bash
SSL_CERT_PATH=./ssl/cert.pem
```

### SSL_KEY_PATH

**Type:** File path  
**Default:** `./ssl/key.pem`  
**Purpose:** SSL private key path (for nginx)

```bash
SSL_KEY_PATH=./ssl/key.pem
```

### SSL_CHAIN_PATH

**Type:** File path  
**Default:** Empty (optional)  
**Purpose:** SSL certificate chain path

```bash
SSL_CHAIN_PATH=./ssl/chain.pem
```

---

## Network Configuration

### HTTP_PORT

**Type:** Integer  
**Default:** `80`  
**Purpose:** Nginx HTTP port (redirects to HTTPS)

```bash
HTTP_PORT=80
```

### HTTPS_PORT

**Type:** Integer  
**Default:** `7003`  
**Purpose:** Nginx HTTPS port

```bash
HTTPS_PORT=7003
```

---

## Example Configurations

### Minimal Production (.env)

```bash
# REQUIRED
SECRET_KEY=<generate-with-python-command>
DATABASE_URL=postgresql+psycopg2://user:pass@postgres:5432/threatfeed
REDIS_URL=redis://:password@redis:6379/0

# Security
ALLOWED_HOSTS=your-domain.com
TRUSTED_PROXY_COUNT=1
MISP_VERIFY_SSL=true

# At least one integration
MISP_URL=https://misp.example.com
MISP_API_KEY=your-key
```

### Full Production (.env)

```bash
# Core (REQUIRED)
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
LOG_LEVEL=INFO

# Database (REQUIRED)
POSTGRES_DB=threatfeed
POSTGRES_USER=threatfeed
POSTGRES_PASSWORD=<strong-password>
DATABASE_URL=postgresql+psycopg2://threatfeed:password@postgres:5432/threatfeed

# Cache (REQUIRED)
REDIS_PASSWORD=<strong-password>
REDIS_URL=redis://:password@redis:6379/0
CACHE_TTL=300

# Security
ALLOWED_HOSTS=threatfeed.example.com
TRUSTED_PROXY_COUNT=1
CORS_ORIGINS=https://dashboard.example.com

# MISP
MISP_URL=https://misp.example.com
MISP_API_KEY=your-misp-api-key
MISP_VERIFY_SSL=true
MISP_DAYS=7

# CrowdSec
CROWDSEC_API_KEY=your-crowdsec-api-key
CROWDSEC_LISTS=list1,list2,list3

# MalwareBazaar
MALWAREBAZAAR_API_URL=https://mb-api.abuse.ch/api/v1/
MALWAREBAZAAR_SINCE_DATE=2025-01-01
MALWAREBAZAAR_TAGS=TrickBot,Emotet
MALWAREBAZAAR_LIMIT=1000

# MWDB
MWDB_URL=https://mwdb.cert.pl
MWDB_AUTH_KEY=your-mwdb-key
MWDB_TAGS=malware,apt
MWDB_LIMIT=1000

# abuse.ch Extended
ABUSECH_AUTH_KEY=your-auth-key
THREATFOX_ENABLED=true
THREATFOX_DAYS=3
URLHAUS_ENABLED=true
FEODOTRACKER_ENABLED=true
YARAIFY_ENABLED=false
YARAIFY_IDENTIFIER=
HUNTING_FPLIST_ENABLED=true
HUNTING_FPLIST_FORMAT=csv

# Worker
ENABLE_BACKGROUND_JOBS=true
UPDATE_INTERVAL=600

# Network
HTTP_PORT=80
HTTPS_PORT=7003
APP_PORT=8080
WORKERS=4

# SSL
SSL_CERT_PATH=./ssl/cert.pem
SSL_KEY_PATH=./ssl/key.pem
SSL_CHAIN_PATH=./ssl/chain.pem
```

### Development (.env)

```bash
# Minimal dev setup
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
DATABASE_URL=postgresql+psycopg2://threatfeed:dev@localhost:5432/threatfeed
REDIS_URL=redis://localhost:6379/0
LOG_LEVEL=DEBUG
ALLOWED_HOSTS=*
TRUSTED_PROXY_COUNT=0
MISP_VERIFY_SSL=false  # Only for self-signed certs!
```

---

## Configuration Validation

### Startup Checks

The application validates configuration at startup:

1. **SECRET_KEY:** Must be set and >= 32 characters
2. **DATABASE_URL:** Must be valid PostgreSQL connection
3. **REDIS_URL:** Must be valid Redis connection

### Runtime Checks

Health endpoint (`/health`) checks:
- Database connectivity
- Redis availability
- MISP API reachability (if configured)
- CrowdSec API validity (if configured)

---

## Configuration Management

### Best Practices

1. **Never commit secrets** - Use `.env` file (gitignored)
2. **Use secrets management** - Vault, AWS Secrets Manager, etc.
3. **Rotate credentials** - Regularly rotate API keys and passwords
4. **Principle of least privilege** - Use read-only database user for queries
5. **Monitor configuration** - Log configuration changes

### Secrets Management

**Docker Secrets:**
```yaml
services:
  app:
    secrets:
      - secret_key
      - db_password
    environment:
      SECRET_KEY_FILE: /run/secrets/secret_key
      DATABASE_PASSWORD_FILE: /run/secrets/db_password
```

**Environment File:**
```bash
# Generate secrets
./scripts/generate-secrets.sh >> .env

# Secure permissions
chmod 600 .env
```

---

## Troubleshooting

### Common Issues

**SECRET_KEY error:**
```
RuntimeError: SECURITY ERROR: SECRET_KEY environment variable must be set.
```
**Fix:** Generate and set SECRET_KEY as shown above

**Database connection failed:**
```
sqlalchemy.exc.OperationalError: could not connect to server
```
**Fix:** Check DATABASE_URL, ensure PostgreSQL is running

**Redis connection failed:**
```
redis.exceptions.ConnectionError: Error connecting to Redis
```
**Fix:** Check REDIS_URL, ensure Redis is running

**MISP SSL verification failed:**
```
requests.exceptions.SSLError: certificate verify failed
```
**Fix:** Set `MISP_VERIFY_SSL=false` ONLY for development with self-signed certs

---

## See Also

- [SECURITY_AUDIT_REPORT.md](../SECURITY_AUDIT_REPORT.md) - Security configuration requirements
- [QUICKSTART.md](../QUICKSTART.md) - Quick setup guide
- [DEPLOYMENT.md](../DEPLOYMENT.md) - Production deployment guide
- [architecture.md](architecture.md) - System architecture
