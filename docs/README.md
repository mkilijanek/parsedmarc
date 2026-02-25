# Threat Feed Aggregator - Documentation

Comprehensive documentation for the IOC (Indicators of Compromise) Threat Feed Aggregation system.

---

## Quick Links

- 📖 **[API Documentation](api.md)** - REST endpoints, formats, and integration examples
- 🏗️ **[Architecture](architecture.md)** - System design and components
- ⚙️ **[Configuration](configuration.md)** - Environment variables and settings
- ⚡ **[Performance](performance.md)** - SLOs, benchmarking, degradation and runbook
- ✅ **[Contributing](../CONTRIBUTING.md)** - Quality gate and CI merge policy
- 🔌 **[Data Sources](data-sources.md)** - MISP, CrowdSec, MalwareBazaar, MWDB integration
- 💾 **[Database](database.md)** - Schema, indexes, and queries
- 💻 **[CLI Tool](cli.md)** - Manual ingestion commands
- 🌐 **[Web UI](web-ui.md)** - Browser interface guide
- 🔒 **[SSL/TLS](ssl.md)** - Certificate management

---

## Getting Started

### For Users

1. **[QUICKSTART.md](../QUICKSTART.md)** - Get running in 5 minutes
2. **[Configuration](configuration.md)** - Configure your deployment
3. **[API Documentation](api.md)** - Start querying IOCs

### For Developers

1. **[Architecture](architecture.md)** - Understand the system
2. **[Database](database.md)** - Schema and data model
3. **[Data Sources](data-sources.md)** - Add new integrations

### For Security Teams

1. **[SECURITY_AUDIT_REPORT.md](../SECURITY_AUDIT_REPORT.md)** - Security analysis
2. **[SECURITY.md](../SECURITY.md)** - Security policy
3. **[API Documentation](api.md#security-headers)** - Security features

---

## Documentation Structure

### Core Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| **[api.md](api.md)** | API endpoints, formats, examples | Users, Integrators |
| **[architecture.md](architecture.md)** | System design, data flow, scalability | Developers, Architects |
| **[configuration.md](configuration.md)** | Environment variables, examples | Ops, Admins |
| **[performance.md](performance.md)** | SLOs, benchmark harness, runbook | Ops, SRE, Developers |

### Integration Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| **[data-sources.md](data-sources.md)** | Source integrations, normalization | Developers, Threat Intel |
| **[database.md](database.md)** | Schema, indexes, queries | DBAs, Developers |
| **[cli.md](cli.md)** | Manual ingestion tool | Operators, Analysts |

### User Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| **[web-ui.md](web-ui.md)** | Web interface guide | End Users |
| **[ssl.md](ssl.md)** | TLS certificate management | Ops, Admins |

---

## Key Features

### 🔍 Unified Search

Kibana-like query syntax with boolean operators:

```
type:ip AND confidence:>70 AND (tags:apt OR tags:malware)
```

### 🔗 IOC Correlation

Cross-source correlation endpoint:

```bash
curl "https://localhost:7003/correlations?min_sources=2&type=domain"
```

### 📤 17 Export Formats

- **Basic:** TXT, CSV, JSON, XML
- **Firewalls:** FortiGate, Check Point, Palo Alto, F5
- **SIEMs:** Sentinel, Defender, ArcSight, Splunk, Elasticsearch

### 🔄 Auto-Update

Background worker fetches from MISP and CrowdSec every 10 minutes (configurable).

### 🔒 Security

- TLS 1.2+ with modern ciphers
- Rate limiting per endpoint
- Comprehensive security headers
- Audit logging
- IP tracking with proxy awareness

### ⚡ Performance

- PostgreSQL connection pooling
- Redis response caching (5 min TTL)
- Database-native exports
- GIN/B-tree indexes
- `limit`/`offset` pagination on view and export endpoints
- Optional NDJSON streaming for `elasticsearch` and `cribl` exports
- Global hard cap: `REQUESTS_PER_SECOND_MAX` (default 1,000,000 req/s)

---

## API Quick Reference

### Health & Monitoring

```bash
curl https://localhost:7003/health
curl https://localhost:7003/metrics
```

### Search & View

```bash
# HTML interface
curl https://localhost:7003/indicators

# With filters
curl "https://localhost:7003/indicators?type=ip&min_conf=80&tlp=AMBER"
```

### Export Formats

```bash
# Plain text
curl https://localhost:7003/indicators/txt

# FortiGate blocklist
curl https://localhost:7003/indicators/fortigate

# Elasticsearch bulk
curl https://localhost:7003/indicators/elasticsearch

# Splunk HEC
curl https://localhost:7003/indicators/splunk
```

See **[API Documentation](api.md)** for full details.

---

## Configuration Quick Reference

### Required Variables

```bash
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
DATABASE_URL=postgresql+psycopg2://user:pass@postgres:5432/threatfeed
REDIS_URL=redis://:password@redis:6379/0
```

### Security (Production)

```bash
ALLOWED_HOSTS=your-domain.com
TRUSTED_PROXY_COUNT=1
MISP_VERIFY_SSL=true
```

### Integrations

```bash
# MISP
MISP_URL=https://misp.example.com
MISP_API_KEY=your-key

# CrowdSec
CROWDSEC_API_KEY=your-key
CROWDSEC_LISTS=list1,list2,list3
```

See **[Configuration](configuration.md)** for all variables.

---

## Architecture Overview

```
┌─────────────┐
│   Nginx     │ ← TLS termination, rate limiting
│  (Reverse   │
│   Proxy)    │
└──────┬──────┘
       │
┌──────▼──────────────────────────────┐
│      Flask Application              │
│  ┌────────┐  ┌────────┐  ┌────────┐│
│  │  API   │  │ Web UI │  │ Worker ││
│  └────────┘  └────────┘  └────────┘│
└──────┬──────────┬──────────┬────────┘
       │          │          │
   ┌───▼───┐  ┌──▼───┐  ┌──▼────┐
   │ PostgreSQL│ Redis│ │External│
   │ (Storage) │(Cache││Sources │
   └───────────┘└──────┘└────────┘
```

See **[Architecture](architecture.md)** for details.

---

## Data Flow

### Ingestion (Background Worker)

```
External API → Fetch → Normalize → Upsert → Update Stats
     ↓
  (MISP, CrowdSec)
```

### Query (API Request)

```
Request → Cache Check → Database Query → Format → Response
   ↓            ↓              ↓
Security    Hit/Miss      Parameterized SQL
Headers
```

See **[Architecture](architecture.md#data-flow)** for details.

---

## Database Schema

### Core Tables

- **ti.indicators** - IOC storage with provenance
- **ti.feed_stats** - Feed health and statistics
- **ti.audit_log** - API access logging

### Key Indexes

- B-tree on (source, source_ref, is_active)
- GIN on tags array
- GIN on metadata JSONB
- pg_trgm for wildcard search

See **[Database](database.md)** for schema details.

---

## Security

### Critical Security Fixes

The system has undergone comprehensive security audit:

- ✅ **SECRET_KEY enforcement** - Required, minimum 32 characters
- ✅ **MISP SSL verification** - Enabled by default
- ✅ **IP tracking security** - Proxy-aware with TRUSTED_PROXY_COUNT
- ✅ **Security headers** - CSP, HSTS, X-Frame-Options, etc.
- ✅ **Secure cookies** - HttpOnly, Secure, SameSite
- ✅ **Rate limiting** - All endpoints protected

See **[SECURITY_AUDIT_REPORT.md](../SECURITY_AUDIT_REPORT.md)** for full audit.

### Best Practices

1. **Always use HTTPS** in production
2. **Set strong SECRET_KEY** (32+ characters)
3. **Enable MISP_VERIFY_SSL** (default: true)
4. **Configure ALLOWED_HOSTS** for production
5. **Set TRUSTED_PROXY_COUNT** if behind proxy
6. **Use VPN/private network** for /metrics endpoint

---

## CLI Tool

Manual IOC ingestion from MalwareBazaar and MWDB:

```bash
python -m app.cli fetch \
  --data-source bazaar \
  --tags TrickBot,Emotet \
  --since 2025-01-01 \
  --until 2025-01-31
```

See **[CLI Documentation](cli.md)** for full usage.

---

## Troubleshooting

### Common Issues

**SECRET_KEY not set:**
```
RuntimeError: SECURITY ERROR: SECRET_KEY environment variable must be set.
```
**Fix:** Generate with `python -c 'import secrets; print(secrets.token_hex(32))'`

**Database connection failed:**
```
sqlalchemy.exc.OperationalError: could not connect to server
```
**Fix:** Check DATABASE_URL, ensure PostgreSQL is running

**Redis connection failed:**
```
redis.exceptions.ConnectionError
```
**Fix:** Check REDIS_URL, ensure Redis is running

See individual docs for more troubleshooting.

---

## Support & Contributing

### Getting Help

- 📚 **Documentation:** Start here!
- 🐛 **Issues:** Check logs: `docker compose logs app`
- 🔍 **Debugging:** Set `LOG_LEVEL=DEBUG`

### Development

```bash
# Setup
git clone <repo>
cd ioc-service
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run app
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
python -m flask --app app.main run --debug
```

---

## Additional Resources

### In Repository

- **[README.md](../README.md)** - Project overview
- **[QUICKSTART.md](../QUICKSTART.md)** - Quick setup guide
- **[DEPLOYMENT.md](../DEPLOYMENT.md)** - Production deployment
- **[SECURITY.md](../SECURITY.md)** - Security policy
- **[SECURITY_AUDIT_REPORT.md](../SECURITY_AUDIT_REPORT.md)** - Security audit

### External

- **Flask:** https://flask.palletsprojects.com/
- **SQLAlchemy:** https://www.sqlalchemy.org/
- **PostgreSQL:** https://www.postgresql.org/docs/
- **Redis:** https://redis.io/docs/
- **MISP:** https://www.misp-project.org/

---

## Document Versions

| Document | Last Updated | Version |
|----------|--------------|---------|
| api.md | 2025-12-18 | 1.0 |
| architecture.md | 2025-12-18 | 1.0 |
| configuration.md | 2025-12-18 | 1.0 |
| data-sources.md | 2025-12-18 | 1.0 |
| database.md | 2025-12-18 | 1.0 |
| cli.md | 2025-12-18 | 1.0 |
| web-ui.md | 2025-12-18 | 1.0 |
| ssl.md | 2025-12-18 | 1.0 |

---

**Note:** This documentation reflects the state of the codebase after security audit and remediation (commit: `claude/security-audit-kili-2Ah1l`).
