-- Database initialization for threat-feed-aggregator
-- PostgreSQL 16+

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS indicators (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    value TEXT NOT NULL,
    type VARCHAR(50) NOT NULL,
    source VARCHAR(100) NOT NULL,
    source_id TEXT,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    confidence INTEGER DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
    tlp VARCHAR(20) DEFAULT 'WHITE' CHECK (tlp IN ('WHITE','GREEN','AMBER','RED')),
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT '{}'::text[],
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_indicator UNIQUE(value, source, source_id)
);

CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_indicators_value_trgm ON indicators USING gin(value gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_indicators_source ON indicators(source);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);
CREATE INDEX IF NOT EXISTS idx_indicators_last_seen ON indicators(last_seen);
CREATE INDEX IF NOT EXISTS idx_indicators_active ON indicators(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_indicators_metadata ON indicators USING GIN(metadata);
CREATE INDEX IF NOT EXISTS idx_indicators_tags ON indicators USING GIN(tags);

CREATE TABLE IF NOT EXISTS feed_stats (
    id SERIAL PRIMARY KEY,
    source VARCHAR(100) NOT NULL,
    source_id TEXT,
    total_indicators INTEGER DEFAULT 0,
    active_indicators INTEGER DEFAULT 0,
    inactive_indicators INTEGER DEFAULT 0,
    last_update TIMESTAMP DEFAULT NOW(),
    last_fetch_status VARCHAR(50),
    last_fetch_error TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    CONSTRAINT unique_feed_stats UNIQUE(source, source_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50),
    entity_id INTEGER,
    user_id VARCHAR(100),
    ip_address INET,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Auto-update updated_at timestamp:
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_indicators_updated_at ON indicators;
CREATE TRIGGER update_indicators_updated_at
    BEFORE UPDATE ON indicators
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Update feed_stats on indicator changes (insert/update/delete):
CREATE OR REPLACE FUNCTION refresh_feed_stats(p_source text, p_source_id text)
RETURNS void AS $$
BEGIN
    INSERT INTO feed_stats (source, source_id, total_indicators, active_indicators, inactive_indicators, last_update)
    SELECT
        p_source, p_source_id,
        COUNT(*),
        COUNT(*) FILTER (WHERE is_active = TRUE),
        COUNT(*) FILTER (WHERE is_active = FALSE),
        NOW()
    FROM indicators
    WHERE source = p_source AND ( (p_source_id IS NULL AND source_id IS NULL) OR source_id = p_source_id )
    ON CONFLICT (source, source_id) DO UPDATE SET
        total_indicators = EXCLUDED.total_indicators,
        active_indicators = EXCLUDED.active_indicators,
        inactive_indicators = EXCLUDED.inactive_indicators,
        last_update = NOW();
END;
$$ language 'plpgsql';

CREATE OR REPLACE FUNCTION update_feed_stats_trigger()
RETURNS TRIGGER AS $$
DECLARE
    s text;
    sid text;
BEGIN
    IF (TG_OP = 'DELETE') THEN
        s := OLD.source;
        sid := OLD.source_id;
    ELSE
        s := NEW.source;
        sid := NEW.source_id;
    END IF;

    PERFORM refresh_feed_stats(s, sid);
    RETURN COALESCE(NEW, OLD);
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS indicators_feed_stats_aiud ON indicators;
CREATE TRIGGER indicators_feed_stats_aiud
    AFTER INSERT OR UPDATE OR DELETE ON indicators
    FOR EACH ROW EXECUTE FUNCTION update_feed_stats_trigger();
