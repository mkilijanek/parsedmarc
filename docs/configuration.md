# Configuration

## Environment Variables

All configuration is done via environment variables. No config files required.

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

### REQUESTS_PER_SECOND_MAX

**Type:** Integer  
**Default:** `1000000`  
**Purpose:** Global hard safety cap for incoming request rate (application-level guardrail)

```bash
REQUESTS_PER_SECOND_MAX=1000000
```

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

---

## Database Configuration

### DATABASE_URL (REQUIRED)

**Type:** PostgreSQL connection string  
**Format:** `postgresql+psycopg2://user:pass@host:port/db`

```bash
DATABASE_URL=postgresql+psycopg2://threatfeed:PASSWORD@postgres:5432/threatfeed
```

**Connection Pool:**
- Pool size: 10 connections
- Max overflow: 20 additional connections
- Pool pre-ping: Enabled (detects stale connections)
- Pool recycle: 1800 seconds (30 minutes)

---

## Cache Configuration

### REDIS_URL (REQUIRED)

**Type:** Redis connection string  
**Format:** `redis://[:password]@host:port/db`

```bash
REDIS_URL=redis://:PASSWORD@redis:6379/0
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

### CORS_ORIGINS

**Type:** Comma-separated origins  
**Default:** `*`  
**Purpose:** CORS allowed origins (future)

```bash
CORS_ORIGINS=https://dashboard.example.com,https://app.example.com
```

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
**Purpose:** MalwareBazaar API endpoint

```bash
MALWAREBAZAAR_API_URL=https://mb-api.abuse.ch/api/v1/
```

#### MALWAREBAZAAR_AUTH_KEY

**Type:** String (API key)  
**Default:** Empty (optional)  
**Purpose:** MalwareBazaar API authentication override. If empty, `ABUSECH_AUTH_KEY` is used.

```bash
MALWAREBAZAAR_AUTH_KEY=your-api-key
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

#### ABUSECH hardening variables

```bash
ABUSECH_TIMEOUT_S=30
ABUSECH_RETRY_ATTEMPTS=4
ABUSECH_RETRY_BASE_DELAY_S=1
ABUSECH_CIRCUIT_FAIL_THRESHOLD=3
ABUSECH_CIRCUIT_COOLDOWN_S=300
```

---

## Worker Configuration

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
**Default:** `4`  
**Purpose:** Number of Gunicorn workers

```bash
# Recommended: 2-4 × CPU cores
WORKERS=4
```

**Formula:** `(2 × CPU_CORES) + 1`

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
MALWAREBAZAAR_AUTH_KEY=your-key
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
