SET search_path = ti, public;

-- Upsert IOC with provenance; avoids dynamic SQL -> safer vs injection
-- Returns indicator_id.
CREATE OR REPLACE FUNCTION upsert_indicator(
    p_ioc_value TEXT,
    p_ioc_type TEXT,
    p_source TEXT,
    p_source_ref TEXT,
    p_confidence INT DEFAULT 50,
    p_tlp TEXT DEFAULT 'GREEN',
    p_tags TEXT[] DEFAULT NULL,
    p_comments TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb,
    p_is_active BOOLEAN DEFAULT TRUE,
    p_first_seen TIMESTAMPTZ DEFAULT NULL,
    p_last_seen TIMESTAMPTZ DEFAULT NULL
) RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
  v_id BIGINT;
BEGIN
  INSERT INTO indicators (
      ioc_value, ioc_type, source, source_ref,
      confidence, tlp, tags, comments, metadata, is_active,
      first_seen, last_seen
  )
  VALUES (
      p_ioc_value, p_ioc_type, p_source, p_source_ref,
      GREATEST(0, LEAST(100, COALESCE(p_confidence, 50))),
      COALESCE(p_tlp, 'GREEN'),
      COALESCE(p_tags, '{}'::text[]),
      p_comments,
      COALESCE(p_metadata, '{}'::jsonb),
      COALESCE(p_is_active, TRUE),
      COALESCE(p_first_seen, now()),
      COALESCE(p_last_seen, now())
  )
  ON CONFLICT (ioc_value, ioc_type, source, source_ref)
  DO UPDATE SET
      confidence = GREATEST(0, LEAST(100, COALESCE(EXCLUDED.confidence, indicators.confidence))),
      tlp = COALESCE(EXCLUDED.tlp, indicators.tlp),
      tags = (
        SELECT ARRAY(SELECT DISTINCT t FROM unnest(indicators.tags || EXCLUDED.tags) AS t ORDER BY 1)
      ),
      comments = COALESCE(EXCLUDED.comments, indicators.comments),
      metadata = indicators.metadata || EXCLUDED.metadata,
      is_active = COALESCE(EXCLUDED.is_active, indicators.is_active),
      first_seen = LEAST(indicators.first_seen, EXCLUDED.first_seen),
      last_seen  = GREATEST(indicators.last_seen, EXCLUDED.last_seen),
      updated_at = now()
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$;

-- Attach / upsert mobile context for an indicator
CREATE OR REPLACE FUNCTION upsert_mobile_context(
    p_indicator_id BIGINT,
    p_platform TEXT,
    p_package_name TEXT DEFAULT NULL,
    p_app_version TEXT DEFAULT NULL,
    p_permissions TEXT[] DEFAULT NULL,
    p_cert_fingerprint TEXT DEFAULT NULL,
    p_store_metadata JSONB DEFAULT '{}'::jsonb
) RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO mobile_app_iocs (
      indicator_id, platform, package_name, app_version, permissions, cert_fingerprint, store_metadata
  )
  VALUES (
      p_indicator_id,
      p_platform,
      p_package_name,
      p_app_version,
      COALESCE(p_permissions, '{}'::text[]),
      p_cert_fingerprint,
      COALESCE(p_store_metadata, '{}'::jsonb)
  )
  ON CONFLICT (indicator_id)
  DO UPDATE SET
      platform = EXCLUDED.platform,
      package_name = COALESCE(EXCLUDED.package_name, mobile_app_iocs.package_name),
      app_version = COALESCE(EXCLUDED.app_version, mobile_app_iocs.app_version),
      permissions = (
        SELECT ARRAY(SELECT DISTINCT p FROM unnest(mobile_app_iocs.permissions || EXCLUDED.permissions) AS p ORDER BY 1)
      ),
      cert_fingerprint = COALESCE(EXCLUDED.cert_fingerprint, mobile_app_iocs.cert_fingerprint),
      store_metadata = mobile_app_iocs.store_metadata || EXCLUDED.store_metadata;
END;
$$;

-- Full-text search returning unified rows (IOC + optional mobile columns)
-- Uses plainto_tsquery to avoid query syntax injection.
CREATE OR REPLACE FUNCTION search_unified(
    p_query TEXT,
    p_limit INT DEFAULT 200,
    p_offset INT DEFAULT 0,
    p_types TEXT[] DEFAULT NULL,
    p_sources TEXT[] DEFAULT NULL,
    p_tlps TEXT[] DEFAULT NULL,
    p_active_only BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    id BIGINT,
    uuid UUID,
    ioc_value TEXT,
    ioc_type TEXT,
    source TEXT,
    source_ref TEXT,
    confidence SMALLINT,
    tlp TEXT,
    is_active BOOLEAN,
    tags TEXT[],
    comments TEXT,
    metadata JSONB,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    platform TEXT,
    package_name TEXT,
    app_version TEXT,
    permissions TEXT[],
    cert_fingerprint TEXT,
    store_metadata JSONB
)
LANGUAGE sql
STABLE
AS $$
SELECT
    i.id, i.uuid, i.ioc_value, i.ioc_type, i.source, i.source_ref,
    i.confidence, i.tlp, i.is_active, i.tags, i.comments, i.metadata,
    i.first_seen, i.last_seen,
    m.platform, m.package_name, m.app_version, m.permissions, m.cert_fingerprint, m.store_metadata
FROM indicators i
LEFT JOIN mobile_app_iocs m ON m.indicator_id = i.id
WHERE
    (p_active_only IS FALSE OR i.is_active)
    AND (p_types IS NULL OR i.ioc_type = ANY(p_types))
    AND (p_sources IS NULL OR i.source = ANY(p_sources))
    AND (p_tlps IS NULL OR i.tlp = ANY(p_tlps))
    AND (
      p_query IS NULL OR length(btrim(p_query)) = 0
      OR i.fts @@ plainto_tsquery('simple', p_query)
      OR i.ioc_value ILIKE '%' || p_query || '%'
      OR (m.indicator_id IS NOT NULL AND (m.fts @@ plainto_tsquery('simple', p_query)))
    )
ORDER BY i.last_seen DESC
LIMIT GREATEST(1, LEAST(p_limit, 5000))
OFFSET GREATEST(0, p_offset);
$$;

-- Aggregations for dashboards/feeds
CREATE OR REPLACE FUNCTION agg_iocs_by_source_type_tlp(
    p_days INT DEFAULT 30
)
RETURNS TABLE (
    source TEXT,
    ioc_type TEXT,
    tlp TEXT,
    total BIGINT,
    active BIGINT,
    last_seen_max TIMESTAMPTZ
)
LANGUAGE sql
STABLE
AS $$
SELECT
    source,
    ioc_type,
    tlp,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE is_active) AS active,
    MAX(last_seen) AS last_seen_max
FROM indicators
WHERE last_seen >= now() - (make_interval(days => GREATEST(0, p_days)))
GROUP BY source, ioc_type, tlp
ORDER BY total DESC;
$$;
