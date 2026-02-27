# Database Documentation

Status: updated for `1.1.x` (2026-02-26).

## Overview

PostgreSQL 16+ with custom schema, functions, and indexes for high-performance IOC storage and retrieval.

---

## Schema: `ti` (Threat Intelligence)

All tables live in the `ti` schema for namespace isolation.

---

## Tables

### indicators

Core table storing all IOCs with provenance tracking.

```sql
CREATE TABLE ti.indicators (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID UNIQUE DEFAULT uuid_generate_v4(),
    
    -- IOC data
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL CHECK (ioc_type IN ('ip','domain','url','hash','email')),
    
    -- Provenance (unique per source+ref)
    source TEXT NOT NULL,
    source_ref TEXT,
    
    -- Metadata
    confidence SMALLINT DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    tlp TEXT DEFAULT 'GREEN' CHECK (tlp IN ('WHITE','GREEN','AMBER','RED')),
    is_active BOOLEAN DEFAULT TRUE,
    tags TEXT[] DEFAULT '{}',
    comments TEXT,
    metadata JSONB DEFAULT '{}',
    
    -- Timestamps
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    
    CONSTRAINT unique_indicator UNIQUE (ioc_value, ioc_type, source, source_ref)
);
```

**Unique Constraint Logic:**

Same IOC from different sources = different rows:
- `192.168.1.1` from MISP event 123
- `192.168.1.1` from CrowdSec list abc
= 2 separate rows

### feed_stats

Health and statistics per feed.

### sync_jobs

Queue table for feed synchronization orchestration.

Key fields:
- `job_id` (unique)
- `feed_source_id`
- `trigger_type` (`manual` / `scheduled`)
- `status` (`queued` / `running` / `success` / `failed`)
- `error`, `result_json`
- `created_at`, `started_at`, `finished_at`

Indexes:
- `idx_sync_jobs_feed_status`
- `idx_sync_jobs_created`
- `idx_sync_jobs_status_created`
- `idx_sync_jobs_trigger_status`

Schema is managed through Alembic migrations (`0001`, `0002`).

```sql
CREATE TABLE ti.feed_stats (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    source_ref TEXT,
    total_indicators INTEGER DEFAULT 0,
    active_indicators INTEGER DEFAULT 0,
    inactive_indicators INTEGER DEFAULT 0,
    last_update TIMESTAMPTZ DEFAULT now(),
    last_fetch_status TEXT,
    last_fetch_error TEXT,
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT unique_feed_stats UNIQUE (source, source_ref)
);
```

### audit_log

Tracks API queries and exports.

```sql
CREATE TABLE ti.audit_log (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    user_id TEXT,
    ip_address INET,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now()
);
```

---

## Indexes

### B-tree Indexes

```sql
-- Primary lookups
CREATE INDEX idx_indicators_source ON ti.indicators(source, source_ref, is_active);
CREATE INDEX idx_indicators_type ON ti.indicators(ioc_type, is_active);
CREATE INDEX idx_indicators_tlp ON ti.indicators(tlp, is_active);
CREATE INDEX idx_indicators_last_seen ON ti.indicators(last_seen DESC);

-- Partial index for active only
CREATE INDEX idx_indicators_active ON ti.indicators(ioc_value, ioc_type) 
  WHERE is_active = TRUE;
```

### GIN Indexes

```sql
-- Array search on tags
CREATE INDEX idx_indicators_tags ON ti.indicators USING GIN(tags);

-- JSONB search on metadata
CREATE INDEX idx_indicators_metadata ON ti.indicators USING GIN(metadata);

-- Full-text search (optional)
CREATE INDEX idx_indicators_value_trgm ON ti.indicators 
  USING GIN(ioc_value gin_trgm_ops);
```

---

## Functions

### ti.export_indicators()

Database-native export for performance.

```sql
SELECT ti.export_indicators(
    'csv',  -- format
    'type:ip AND confidence:>70',  -- query
    100000,  -- limit
    0,  -- offset
    ARRAY['ip'],  -- types filter
    ARRAY['misp'],  -- sources filter
    ARRAY['AMBER'],  -- tlps filter
    TRUE  -- active_only
);
```

### ti.search_unified()

Unified search with filters.

```sql
SELECT * FROM ti.search_unified(
    'value:192.168.*',  -- query
    1000,  -- limit
    0,  -- offset
    NULL,  -- types
    NULL,  -- sources
    NULL,  -- tlps
    TRUE  -- active_only
);
```

---

## Triggers

### updated_at Maintenance

```sql
CREATE TRIGGER trg_indicators_updated
BEFORE UPDATE ON ti.indicators
FOR EACH ROW
EXECUTE FUNCTION ti.update_timestamp();
```

---

## Queries

### Find High-Confidence IPs

```sql
SELECT ioc_value, confidence, source, tags
FROM ti.indicators
WHERE ioc_type = 'ip'
  AND confidence >= 80
  AND is_active = TRUE
ORDER BY last_seen DESC
LIMIT 100;
```

### Search by Tag

```sql
SELECT ioc_value, ioc_type, tags
FROM ti.indicators
WHERE 'apt' = ANY(tags)
  AND is_active = TRUE;
```

### Feed Statistics

```sql
SELECT source, 
       active_indicators, 
       last_update, 
       last_fetch_status
FROM ti.feed_stats
ORDER BY last_update DESC;
```

---

## Maintenance

### Vacuum

```sql
-- Regular vacuum
VACUUM ANALYZE ti.indicators;

-- Full vacuum (requires lock)
VACUUM FULL ti.indicators;
```

### Reindex

```sql
REINDEX TABLE ti.indicators;
```

### Statistics

```sql
-- Update planner statistics
ANALYZE ti.indicators;
```

---

## Performance Tuning

### Connection Pooling

```python
# app/db.py
engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=1800
)
```

### Query Optimization

1. **Use indexes** - Check with EXPLAIN ANALYZE
2. **Limit results** - Always use LIMIT
3. **Partial indexes** - For common filters (is_active=TRUE)
4. **Batch operations** - ON CONFLICT for upserts

### PostgreSQL Config

```ini
# postgresql.conf
shared_buffers = 2GB  # 25% of RAM
work_mem = 64MB
maintenance_work_mem = 512MB
effective_cache_size = 6GB  # 75% of RAM
```

---

## Backup & Recovery

### Backup

```bash
# Full dump
pg_dump -h localhost -U threatfeed -d threatfeed -F c -f backup.dump

# Schema only
pg_dump -h localhost -U threatfeed -d threatfeed --schema-only > schema.sql

# Data only
pg_dump -h localhost -U threatfeed -d threatfeed --data-only > data.sql
```

### Restore

```bash
# From custom format
pg_restore -h localhost -U threatfeed -d threatfeed backup.dump

# From SQL
psql -h localhost -U threatfeed -d threatfeed < backup.sql
```

---

## See Also

- [Architecture](architecture.md) - Database-first design
- [Data Sources](data-sources.md) - Schema normalization
- [Configuration](configuration.md) - DATABASE_URL setup
