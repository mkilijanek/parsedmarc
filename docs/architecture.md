# Architecture

Status: updated for `1.1.x` (2026-02-26).

## Overview

The Threat Feed Aggregator follows a **database-first** architecture where PostgreSQL serves as the central hub for data storage, transformation, and export operations. This design prioritizes performance, consistency, and reliability over application-level complexity.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Nginx (Reverse Proxy)                   │
│         TLS 1.2+, HTTP/2, Security Headers, Rate Limiting       │
└──────────────────┬──────────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────────┐
│                  Flask Application (Gunicorn)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐   │
│  │   Main API  │  │   Web UI    │  │  Background Worker   │   │
│  │  (REST/HTML)│  │  (Blueprint)│  │  (Scheduled Updates) │   │
│  └─────────────┘  └─────────────┘  └──────────────────────┘   │
│         │                │                     │                │
│         └────────────────┴─────────────────────┘                │
│                          │                                       │
└──────────────────────────┼───────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌──────────────┐  ┌──────────────┐
│  PostgreSQL   │  │    Redis     │  │   External   │
│   Database    │  │    Cache     │  │  TI Sources  │
│               │  │              │  │              │
│ - Indicators  │  │ - Response   │  │ - MISP       │
│ - Feed Stats  │  │   Cache      │  │ - CrowdSec   │
│ - Audit Log   │  │ - Rate Limit │  │ - Malware    │
│ - Functions   │  │   State      │  │   Bazaar     │
│ - Indexes     │  │              │  │ - MWDB       │
└───────────────┘  └──────────────┘  └──────────────┘
```

---

## Core Components

### 1. Web Application Layer

**Technology:** Flask 3.0 + Gunicorn

**Responsibilities:**
- HTTP request handling
- Query parsing and validation
- Response formatting and caching
- Security enforcement (headers, rate limiting)
- Audit logging

**Key Files:**
- `app/main.py` - Main Flask application, endpoints
- `app/webui.py` - Web UI Blueprint
- `app/security.py` - Security middleware and validation
- `app/formatters.py` - Export format implementations

**Characteristics:**
- Stateless design for horizontal scalability
- Minimal business logic (offloaded to database)
- Immutable configuration (dataclass)
- Structured logging with context

### 2. Database Layer (PostgreSQL 16+)

**Why Database-First:**
- **Performance:** SQL functions eliminate round-trips
- **Consistency:** Database handles transactions and constraints
- **Reliability:** ACID guarantees for concurrent writes
- **Scalability:** Query optimization at database level
- **Simplicity:** Less application code = fewer bugs

**Schema Design:**

```sql
ti.indicators (
    -- Identity
    id BIGSERIAL PRIMARY KEY,
    uuid UUID UNIQUE,

    -- IOC Data
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,

    -- Provenance (unique constraint)
    source TEXT NOT NULL,
    source_ref TEXT,

    -- Metadata
    confidence SMALLINT CHECK (0-100),
    tlp TEXT CHECK (WHITE|GREEN|AMBER|RED),
    is_active BOOLEAN DEFAULT TRUE,
    tags TEXT[],
    metadata JSONB,

    -- Timestamps
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,

    UNIQUE (ioc_value, ioc_type, source, source_ref)
)
```

**Database Functions:**
- `ti.export_indicators()` - Native format export
- `ti.search_unified()` - Unified search with filtering
- `ti.upsert_indicator()` - Atomic upsert operations
- Triggers for `updated_at` maintenance

**Indexes:**
- B-tree on `(source, source_id, is_active)`
- GIN on `tags` array
- GIN on `metadata` JSONB
- pg_trgm for wildcard searches
- Partial indexes for active indicators

**Performance Optimizations:**
- Prepared statements via SQLAlchemy
- Connection pooling (10 + 20 overflow)
- Pool pre-ping for stale connection detection
- Query result caching in Redis

### 3. Cache Layer (Redis 7)

**Purpose:**
- HTTP response caching (HTML, exports)
- Rate limit state storage
- Session management (future)

**Configuration:**
- **Persistence:** AOF (Append-Only File)
- **Memory:** 512MB max with LRU eviction
- **TTL:** 5 minutes default (CACHE_TTL)
- **Connection:** Single connection pool

**Cache Keys:**
```
indicators_html|q=value:*|type=ip|tlp=AMBER|...
export|fmt=csv|q=...|type=...
```

**Benefits:**
- Reduces database load
- Improves response latency
- Enables horizontal scaling
- Adds visibility via cache hit/miss metrics (`cache_access_total`)

### 4. Background Worker

**Technology:** Python schedule library + threading

**Responsibilities:**
- Periodic threat feed updates
- Feed health monitoring
- Stale indicator cleanup
- Statistics calculation

**Update Cycle:**
```python
# Default: 10 minutes (UPDATE_INTERVAL=600)
schedule.every(10).minutes.do(update_all_feeds)
```

**Feed Update Process:**
1. Fetch from external API (with retry/backoff)
2. Normalize IOC format
3. Upsert to database (ON CONFLICT handling)
4. Mark missing indicators as inactive
5. Update feed_stats table
6. Log metrics

**Error Handling:**
- Exponential backoff for transient errors
- Failed feed updates don't block others
- Errors logged with structured context
- `feed_stats.last_fetch_error` tracking

### 5. Sync Scheduler / Queue (1.1.x)

The application now uses a DB-backed sync queue:
- `sync_jobs` table for job lifecycle tracking
- idempotent enqueue per feed (prevents duplicate queued/running jobs)
- manual and scheduled sync paths both use the same queue runner
- logs include `run_id/job_id` for traceability

Startup is migration-first (Alembic), no runtime `create_all`.

---

## Data Flow

### Ingestion Flow (Background Worker)

```
External Source → API Fetch → Normalization → Database Upsert → Feed Stats
     (MISP)                                         ↓
     (CrowdSec)                              Audit Logging
     (MalwareBazaar)                              ↓
     (MWDB)                                  Cache Invalidation
```

**Steps:**
1. **Fetch:** HTTP GET with auth headers, retry logic
2. **Normalize:** Map source format to internal schema
3. **Transform:** Calculate confidence, extract TLP, parse tags
4. **Upsert:** `ON CONFLICT DO UPDATE` for idempotency
5. **Audit:** Log ingestion stats and errors
6. **Cache:** Clear relevant cache keys
7. **Quality/Enrichment:** Canonical normalization, dedup, and metadata enrichment

### Query Flow (API Request)

```
Client Request → Nginx → Flask → Cache Check → Database Query → Format → Response
                   ↓         ↓                        ↓
              Rate Limit   Security            Result Cache
              Check       Validation           (Redis)
```

**Steps:**
1. **Nginx:** TLS termination, rate limiting, security headers
2. **Global Guardrail:** In-process hard cap `REQUESTS_PER_SECOND_MAX` (default 1,000,000 req/s)
3. **Flask:** Parse query, validate syntax (max 500 chars)
4. **Cache:** Check Redis for cached response
5. **Database:** Execute parameterized SQL query with latency metrics (`db_query_duration_seconds`)
6. **Correlation (optional):** Aggregate active IOCs across distinct sources via `/correlations`
7. **Format:** Apply output formatter (txt/csv/json/...)
8. **Cache:** Store result in Redis (TTL: 5 minutes)
9. **Response:** Return with security headers

---

## Security Architecture

### Defense Layers

**Layer 1: Network (Nginx)**
- TLS 1.2+ only, modern cipher suites
- Rate limiting (nginx + redis)
- Request size limits
- DDoS mitigation

**Layer 2: Application (Flask)**
- Host header validation
- Query syntax validation (max length, blacklist)
- Input sanitization
- Secure session cookies
- CSRF protection (SameSite)

**Layer 3: Database**
- Parameterized queries only (SQLAlchemy ORM)
- Connection credentials via environment
- Read-only query user (optional)
- Row-level security (future)

**Security Headers:**
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; ...
Strict-Transport-Security: max-age=31536000
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Authentication & Authorization

**Current State:** No authentication required

**Recommended for Production:**
1. Deploy behind VPN/private network
2. Add nginx basic auth for /metrics
3. Implement API key middleware
4. Use IP whitelisting

**Future Enhancements:**
- JWT-based authentication
- Role-based access control (RBAC)
- TLP-based filtering per user
- API key rotation

---

## Scalability

### Horizontal Scaling

**Stateless Design:**
- No application state (all in Redis/PostgreSQL)
- Session storage in Redis
- Load balancer ready (nginx, HAProxy)

**Scaling Strategy:**
```
┌────────┐    ┌────────┐    ┌────────┐
│ App 1  │    │ App 2  │    │ App N  │
└───┬────┘    └───┬────┘    └───┬────┘
    │             │             │
    └─────────────┼─────────────┘
                  │
            ┌─────▼─────┐
            │   Redis   │
            └───────────┘
                  │
            ┌─────▼─────┐
            │PostgreSQL │
            └───────────┘
```

**Considerations:**
- Shared Redis for cache consistency
- Database connection pooling per instance
- Worker runs on single instance only (leader election needed for multi-worker)

### Vertical Scaling

**Database:**
- Increase `shared_buffers` (25% of RAM)
- Tune `work_mem` for complex queries
- Enable parallel query execution
- Add more indexes for specific workloads

**Application:**
- Increase Gunicorn workers (2-4 × CPU cores)
- Increase database connection pool size
- Tune Redis maxmemory

**Performance Targets:**
- < 100ms for cached responses
- < 500ms for database queries
- < 2s for large exports (100k IOCs)
- 1000+ req/s with caching

---

## Monitoring & Observability

### Metrics (Prometheus)

```
# Request metrics
http_requests_total{method, endpoint, status}
http_request_duration_seconds{endpoint}

# Application metrics
active_indicators
database_connection_pool_size
redis_cache_hit_ratio

# System metrics (via node_exporter)
node_cpu_usage
node_memory_usage
node_disk_io
```

### Logging

**Format:** JSON structured logging

**Levels:**
- DEBUG: Query details, cache operations
- INFO: Request logging, feed updates
- WARNING: Retry attempts, degraded performance
- ERROR: Failed requests, database errors

**Context:**
```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "level": "INFO",
  "message": "misp_updated",
  "extra": {
    "fetched": 1234,
    "events": 45,
    "duration_ms": 2345
  }
}
```

### Health Checks

**Endpoint:** `/health`

**Checks:**
- Database connectivity
- Redis availability
- MISP API reachability
- CrowdSec API key validity

**Docker Healthcheck:**
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -fsS http://localhost:8080/health || exit 1
```

---

## Technology Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Application | Python | 3.11 | Runtime |
| Web Framework | Flask | 3.1.3 | HTTP server |
| WSGI Server | Gunicorn | 22.0.0 | Production server |
| Database | PostgreSQL | 16+ | Data storage |
| Cache | Redis | 7+ | Response cache |
| Reverse Proxy | Nginx | 1.24+ | TLS, rate limiting |
| ORM | SQLAlchemy | 2.0.36 | Database abstraction |
| HTTP Client | requests | 2.32.4 | External API calls |
| Rate Limiting | Flask-Limiter | 3.7.0 | API rate limiting |
| Metrics | prometheus-client | 0.20.0 | Metrics export |
| MISP Client | pymisp | 2.4.179 | MISP integration |
| JSON | stdlib `json` | Python 3.11+ | JSON serialization |

---

## Design Principles

1. **Database-First:** Offload complexity to PostgreSQL
2. **Immutability:** Configuration is immutable (dataclass)
3. **Fail-Fast:** Validate early, fail with clear errors
4. **Defense-in-Depth:** Multiple security layers
5. **Observability:** Structured logging, metrics, health checks
6. **Simplicity:** Minimal abstractions, explicit over implicit
7. **Performance:** Caching, indexing, connection pooling
8. **Idempotency:** Upsert operations, safe retries

---

## Future Enhancements

### High Priority
- [ ] API authentication (API keys, JWT)
- [ ] Multi-tenancy support
- [ ] Real-time updates (WebSocket/SSE)
- [ ] Advanced query language (AST-based)

### Medium Priority
- [ ] GraphQL API
- [ ] Bulk import API
- [ ] Indicator enrichment pipeline
- [ ] Machine learning confidence scoring

### Low Priority
- [ ] Mobile app
- [ ] ChatOps integration (Slack, Teams)
- [ ] Threat intel sharing (TAXII 2.1)
- [ ] Blockchain provenance tracking

---

## Development

### Local Setup

```bash
# Clone and setup
git clone <repo>
cd ioc-service
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Database setup
docker compose up -d postgres redis
psql -h localhost -U threatfeed -d threatfeed -f database/init.sql

# Run app
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export DATABASE_URL="postgresql://..."
python -m flask --app app.main run --debug
```

### Testing

```bash
# Unit tests
pytest tests/ -v

# Integration tests
docker compose up -d
pytest tests/integration/ -v

# Load tests
python scripts/benchmark_m12.py --base-url http://127.0.0.1:8080 --duration 30 --concurrency 64
```

---

## See Also

- [API Documentation](api.md) - API endpoints and formats
- [Database Schema](database.md) - Database design
- [Configuration](configuration.md) - Environment variables
- [SECURITY_AUDIT_REPORT.md](../SECURITY_AUDIT_REPORT.md) - Security analysis
