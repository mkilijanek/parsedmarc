SET search_path = ti, public;

-- M9: query acceleration for canonicalized IOC lookups and active scans
CREATE INDEX IF NOT EXISTS idx_indicators_value_type_active
ON indicators (ioc_value, ioc_type, is_active);

CREATE INDEX IF NOT EXISTS idx_indicators_source_last_seen
ON indicators (source, last_seen DESC);

-- Fast case-insensitive domain/hash searches after canonicalization
CREATE INDEX IF NOT EXISTS idx_indicators_ioc_value_lower
ON indicators (lower(ioc_value));
