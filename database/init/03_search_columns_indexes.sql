SET search_path = ti, public;

-- Trigram search on IOC value + comments
CREATE INDEX IF NOT EXISTS idx_indicators_ioc_value_trgm
ON indicators USING gin (ioc_value gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_indicators_comments_trgm
ON indicators USING gin (comments gin_trgm_ops);

-- Tags array search
CREATE INDEX IF NOT EXISTS idx_indicators_tags_gin
ON indicators USING gin (tags);

-- Metadata JSONB search
CREATE INDEX IF NOT EXISTS idx_indicators_metadata_gin
ON indicators USING gin (metadata);

-- Common filters
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators (ioc_type);
CREATE INDEX IF NOT EXISTS idx_indicators_source ON indicators (source);
CREATE INDEX IF NOT EXISTS idx_indicators_tlp ON indicators (tlp);
CREATE INDEX IF NOT EXISTS idx_indicators_last_seen ON indicators (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_indicators_active_true ON indicators (is_active) WHERE is_active = TRUE;

-- Mobile indexes
CREATE INDEX IF NOT EXISTS idx_mobile_platform ON mobile_app_iocs (platform);
CREATE INDEX IF NOT EXISTS idx_mobile_package_trgm ON mobile_app_iocs USING gin (package_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_mobile_version_trgm ON mobile_app_iocs USING gin (app_version gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_mobile_permissions_gin ON mobile_app_iocs USING gin (permissions);

CREATE INDEX IF NOT EXISTS idx_mobile_permissions_perm_trgm ON mobile_permissions USING gin (permission gin_trgm_ops);

-- Full-text search vector across *all* relevant text content, including JSONB stringification
-- Use 'simple' to avoid language-specific stemming and reduce surprises in IOC tokens.
ALTER TABLE indicators
    ADD COLUMN IF NOT EXISTS fts tsvector
    GENERATED ALWAYS AS (
        to_tsvector('simple',
            coalesce(ioc_value,'') || ' ' ||
            coalesce(ioc_type,'') || ' ' ||
            coalesce(source,'') || ' ' ||
            coalesce(source_ref,'') || ' ' ||
            coalesce(comments,'') || ' ' ||
            coalesce(array_to_string(tags,' '),'') || ' ' ||
            coalesce(metadata::text,'')
        )
    ) STORED;

CREATE INDEX IF NOT EXISTS idx_indicators_fts_gin ON indicators USING gin (fts);

-- Optional: mobile FTS
ALTER TABLE mobile_app_iocs
    ADD COLUMN IF NOT EXISTS fts tsvector
    GENERATED ALWAYS AS (
        to_tsvector('simple',
            coalesce(platform,'') || ' ' ||
            coalesce(package_name,'') || ' ' ||
            coalesce(app_version,'') || ' ' ||
            coalesce(array_to_string(permissions,' '),'') || ' ' ||
            coalesce(cert_fingerprint,'') || ' ' ||
            coalesce(store_metadata::text,'')
        )
    ) STORED;

CREATE INDEX IF NOT EXISTS idx_mobile_fts_gin ON mobile_app_iocs USING gin (fts);
