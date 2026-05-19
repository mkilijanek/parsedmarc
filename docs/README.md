# IOC Service — Documentation

**Version:** 1.9.x · **Updated:** 2026-05-19

IOC Service is a Threat Feed Aggregation platform that collects Indicators of Compromise from multiple sources (MISP, CrowdSec, MalwareBazaar, MWDB), normalises them into a unified schema, and exposes them through a REST API, a browser UI, and 17 export formats.

---

## Quick Start

```bash
# Generate a secret key
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Start the stack
docker compose up -d

# Verify
curl http://localhost:7005/healthz
```

See [Configuration](configuration.md) for all environment variables.

---

## Core Features

### Unified Search

Kibana-like query syntax with boolean operators:

```
type:ip AND confidence:>70 AND (tags:apt OR tags:malware)
```

Time-window filters (`since=7d`, `since=30m`, absolute `date_from`/`date_to`) and full-text search across value, source, tags, and metadata.

### Export (17 Formats)

| Category | Formats |
|----------|---------|
| Basic | TXT, CSV, JSON, XML |
| Firewalls | FortiGate, Check Point, Palo Alto, F5 |
| SIEMs | Sentinel, Defender, ArcSight, Splunk, Elasticsearch |
| Streaming | NDJSON (Elasticsearch, Cribl) |

```bash
curl http://localhost:7005/indicators/fortigate
curl http://localhost:7005/indicators/splunk
curl http://localhost:7005/indicators/elasticsearch
```

### Feed Management

- Per-feed on/off toggle, connection test, and manual sync trigger
- Background worker polls feeds every 10 minutes (configurable via `SYNC_INTERVAL_MINUTES`)
- Sync job queue with status tracking and dead-letter queue for permanent failures
- Feed health stats with per-run metrics

### Security

- Rate limiting on all endpoints
- CSP, HSTS, X-Frame-Options, X-Content-Type-Options headers
- HMAC-SHA256 audit log integrity chain
- Admin token auth with constant-time comparison
- DB circuit breaker with half-open probing
- Proxy-aware IP tracking (`TRUSTED_PROXY_COUNT`)

---

## System Architecture

```
┌─────────────┐
│    Nginx    │  ← TLS termination, rate limiting
└──────┬──────┘
       │
┌──────▼──────────────────────────────┐
│        Flask Application            │
│  ┌──────┐  ┌────────┐  ┌────────┐  │
│  │ API  │  │ Web UI │  │ Docs   │  │
│  └──────┘  └────────┘  └────────┘  │
│  ┌──────────────────────────────┐   │
│  │         Background Worker    │   │
│  └──────────────────────────────┘   │
└───────┬─────────────┬───────────────┘
        │             │
   ┌────▼────┐   ┌────▼────┐   ┌────────────┐
   │PostgreSQL│  │  Redis  │   │ Feed APIs  │
   │ (storage)│  │ (cache) │   │MISP/CrowdSec│
   └──────────┘  └─────────┘   └────────────┘
```

See [Architecture Overview](architecture.md) for the full design, and the [Architecture Diagrams](/docs/architecture) page for Mermaid views.

---

## API Quick Reference

```bash
# Health
curl http://localhost:7005/healthz

# List indicators
curl http://localhost:7005/api/v1/indicators

# Filter by type and time window
curl "http://localhost:7005/api/v1/indicators?type=ip&since=24h&min_conf=80"

# Export as FortiGate blocklist
curl http://localhost:7005/indicators/fortigate

# Trigger feed sync
curl -X POST http://localhost:7005/api/v1/sync \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source": "crowdsec"}'
```

See [API Reference](/docs/api) for the interactive Swagger UI.

---

## Common Configuration

```bash
# Required
SECRET_KEY=<32+ char random string>
DATABASE_URL=postgresql+psycopg2://user:pass@postgres:5432/ioc
REDIS_URL=redis://:password@redis:6379/0

# Feed integrations
MISP_URL=https://misp.example.com
MISP_API_KEY=your-key
CROWDSEC_API_KEY=your-key
CROWDSEC_LISTS=list1,list2

# Production hardening
ALLOWED_HOSTS=your-domain.com
TRUSTED_PROXY_COUNT=1
HSTS_ENABLED=true
```

See [Configuration](configuration.md) for the full variable reference.

---

## Troubleshooting

**SECRET_KEY not set:**
```
RuntimeError: SECURITY ERROR: SECRET_KEY environment variable must be set.
```
Fix: `export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')`

**Database connection failed:**
```
sqlalchemy.exc.OperationalError: could not connect to server
```
Fix: check `DATABASE_URL`, ensure PostgreSQL is running and the schema is migrated (`docker compose run migrate`).

**Redis connection failed:**
```
redis.exceptions.ConnectionError
```
Fix: check `REDIS_URL`, ensure Redis is running.

See [Troubleshooting](troubleshooting/502-bad-gateway.md) for more.
