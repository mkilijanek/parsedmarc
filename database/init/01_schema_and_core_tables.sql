-- Optional: keep everything in its own schema
CREATE SCHEMA IF NOT EXISTS ti;
SET search_path = ti, public;

-- Enumerations as CHECKs (more portable than ENUM for migrations)
-- Core IOC table: one row per (ioc_value, ioc_type, source, source_ref) to preserve provenance.
CREATE TABLE IF NOT EXISTS indicators (
    id              BIGSERIAL PRIMARY KEY,
    uuid            UUID NOT NULL DEFAULT uuid_generate_v4(),
    ioc_value       TEXT NOT NULL,
    ioc_type        TEXT NOT NULL,          -- ip, domain, url, hash, email, cert, ja3, imphash, etc.
    source          TEXT NOT NULL,          -- misp, crowdsec, malwarebazaar, mwdb, custom
    source_ref      TEXT,                   -- event_id, list_id, sample_id, blob_id, etc.
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    confidence      SMALLINT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    tlp             TEXT NOT NULL DEFAULT 'GREEN' CHECK (tlp IN ('WHITE','GREEN','AMBER','RED')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    tags            TEXT[] NOT NULL DEFAULT '{}'::text[],
    comments        TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb, -- source-specific context
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_indicator UNIQUE (ioc_value, ioc_type, source, source_ref)
);

-- Feed/source health stats (optional but useful)
CREATE TABLE IF NOT EXISTS feed_stats (
    id                BIGSERIAL PRIMARY KEY,
    source            TEXT NOT NULL,
    source_ref        TEXT,
    total_indicators  INTEGER NOT NULL DEFAULT 0,
    active_indicators INTEGER NOT NULL DEFAULT 0,
    inactive_indicators INTEGER NOT NULL DEFAULT 0,
    last_update       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_fetch_status TEXT,
    last_fetch_error  TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT uq_feed_stats UNIQUE (source, source_ref)
);
