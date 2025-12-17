SET search_path = ti, public;

-- Generate full export formats from the database layer.
-- This is intentionally implemented in SQL/PLpgSQL to make exports deterministic and easy to consume
-- without relying on application-side formatting logic.

CREATE OR REPLACE FUNCTION export_indicators(
    p_fmt TEXT,
    p_query TEXT DEFAULT NULL,
    p_limit INT DEFAULT 100000,
    p_offset INT DEFAULT 0,
    p_types TEXT[] DEFAULT NULL,
    p_sources TEXT[] DEFAULT NULL,
    p_tlps TEXT[] DEFAULT NULL,
    p_active_only BOOLEAN DEFAULT TRUE
) RETURNS TEXT
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    fmt TEXT := lower(coalesce(p_fmt, 'json'));
    out TEXT;
BEGIN
    WITH base AS (
        SELECT *
        FROM search_unified(
            p_query,
            p_limit,
            p_offset,
            p_types,
            p_sources,
            p_tlps,
            p_active_only
        )
    )
    SELECT
        CASE fmt
            WHEN 'txt' THEN coalesce(string_agg(ioc_value, E'\n'), '') || CASE WHEN count(*)>0 THEN E'\n' ELSE '' END
            WHEN 'csv' THEN (
                'uuid,ioc_value,ioc_type,source,source_ref,confidence,tlp,is_active,tags,comments,first_seen,last_seen' || E'\n' ||
                coalesce(string_agg(
                    -- naive CSV escaping: quotes around fields + double quotes inside
                    '"' || replace(coalesce(uuid::text,''),'"','""') || '",' ||
                    '"' || replace(coalesce(ioc_value,''),'"','""') || '",' ||
                    '"' || replace(coalesce(ioc_type,''),'"','""') || '",' ||
                    '"' || replace(coalesce(source,''),'"','""') || '",' ||
                    '"' || replace(coalesce(source_ref,''),'"','""') || '",' ||
                    coalesce(confidence::text,'') || ',' ||
                    '"' || replace(coalesce(tlp,''),'"','""') || '",' ||
                    CASE WHEN is_active THEN 'true' ELSE 'false' END || ',' ||
                    '"' || replace(coalesce(array_to_string(tags,';'),''),'"','""') || '",' ||
                    '"' || replace(coalesce(comments,''),'"','""') || '",' ||
                    '"' || replace(coalesce(first_seen::text,''),'"','""') || '",' ||
                    '"' || replace(coalesce(last_seen::text,''),'"','""') || '"'
                , E'\n'), '')
                || CASE WHEN count(*)>0 THEN E'\n' ELSE '' END
            )
            WHEN 'tsv' THEN (
                'uuid\tioc_value\tioc_type\tsource\tsource_ref\tconfidence\ttlp\tis_active\ttags\tcomments\tfirst_seen\tlast_seen' || E'\n' ||
                coalesce(string_agg(
                    coalesce(uuid::text,'') || E'\t' ||
                    replace(coalesce(ioc_value,''), E'\t', ' ') || E'\t' ||
                    coalesce(ioc_type,'') || E'\t' ||
                    coalesce(source,'') || E'\t' ||
                    coalesce(source_ref,'') || E'\t' ||
                    coalesce(confidence::text,'') || E'\t' ||
                    coalesce(tlp,'') || E'\t' ||
                    CASE WHEN is_active THEN 'true' ELSE 'false' END || E'\t' ||
                    coalesce(array_to_string(tags,';'),'') || E'\t' ||
                    replace(coalesce(comments,''), E'\t', ' ') || E'\t' ||
                    coalesce(first_seen::text,'') || E'\t' ||
                    coalesce(last_seen::text,'')
                , E'\n'), '')
                || CASE WHEN count(*)>0 THEN E'\n' ELSE '' END
            )
            WHEN 'json' THEN (
                SELECT coalesce(jsonb_pretty(jsonb_agg(to_jsonb(base) - 'store_metadata')), '[]'::text)
                FROM base
            )
            -- Tool-specific formats (best-effort, aligned with README/spec)
            WHEN 'fortigate' THEN coalesce((SELECT string_agg(ioc_value, E'\n') FROM base WHERE ioc_type='ip'), '') || E'\n'
            WHEN 'paloalto' THEN coalesce((SELECT string_agg(ioc_value, E'\n') FROM base WHERE ioc_type='ip'), '') || E'\n'
            WHEN 'checkpoint' THEN (
                'name,ip-address,confidence,severity,comments,color' || E'\n' ||
                coalesce((
                    SELECT string_agg(
                        'ThreatFeed-' || replace(ioc_value,'.','-') || ',' ||
                        ioc_value || ',' ||
                        CASE
                            WHEN confidence >= 85 THEN 'high'
                            WHEN confidence >= 60 THEN 'medium'
                            ELSE 'low'
                        END || ',high,' ||
                        'Threat intelligence indicator,orange'
                    , E'\n')
                    FROM base WHERE ioc_type='ip'
                ), '') || E'\n'
            )
            WHEN 'arcsight' THEN coalesce((
                SELECT string_agg(
                    'CEF:0|ThreatFeedAggregator|IOC Feed|1.0|TI-' || upper(ioc_type) ||
                    '|Threat Intelligence: ' || replace(ioc_value,'|',' ') ||
                    '|7|src=' || replace(ioc_value,'|',' ') ||
                    ' cs1Label=TLP cs1=' || coalesce(tlp,'') ||
                    ' cs2Label=Confidence cs2=' || coalesce(confidence::text,'')
                , E'\n')
                FROM base
            ), '') || E'\n'
            WHEN 'elasticsearch' THEN coalesce((
                SELECT string_agg(
                    '{"index":{"_index":"threat-intel-indicators","_id":"' || source || '-' || replace(ioc_value,'"','\\"') || '"}}' || E'\n' ||
                    '{"@timestamp":"' || to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS"Z"') ||
                    '","indicator":{"value":"' || replace(ioc_value,'"','\\"') || '","type":"' || ioc_type ||
                    '","confidence":' || coalesce(confidence::text,'0') || '}}'
                , E'\n')
                FROM base
            ), '') || E'\n'
            WHEN 'splunk' THEN (
                SELECT coalesce(jsonb_pretty(jsonb_agg(
                    jsonb_build_object(
                        'time', extract(epoch from now() at time zone 'utc')::bigint,
                        'host', 'threat-feed-aggregator',
                        'source', 'threat_intelligence_feed',
                        'sourcetype', 'threatintel:indicator',
                        'event', jsonb_build_object(
                            'indicator', ioc_value,
                            'indicator_type', ioc_type,
                            'confidence', confidence,
                            'tlp', tlp,
                            'tags', tags,
                            'source', source
                        )
                    )
                )), '[]'::text)
                FROM base
            )
            WHEN 'cribl' THEN coalesce((
                SELECT string_agg(
                    jsonb_build_object(
                        '_time', extract(epoch from now() at time zone 'utc')::bigint,
                        'source', 'threat-feed-aggregator',
                        'sourcetype', 'threat_intelligence',
                        'indicator_value', ioc_value,
                        'indicator_type', ioc_type,
                        'confidence_score', confidence,
                        'tlp', tlp,
                        'tags', tags
                    )::text
                , E'\n')
                FROM base
            ), '') || E'\n'
            WHEN 'fidelis' THEN (
                SELECT jsonb_build_object(
                    'type','bundle',
                    'id','bundle--threat-feed-' || extract(epoch from now() at time zone 'utc')::bigint,
                    'objects',
                    coalesce(jsonb_agg(
                        jsonb_build_object(
                            'type','indicator',
                            'spec_version','2.1',
                            'id','indicator--' || uuid::text,
                            'created', to_char(first_seen at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                            'modified', to_char(last_seen at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                            'pattern', CASE
                                WHEN ioc_type='ip' THEN '[ipv4-addr:value = ''' || ioc_value || ''']'
                                WHEN ioc_type='domain' THEN '[domain-name:value = ''' || ioc_value || ''']'
                                WHEN ioc_type='url' THEN '[url:value = ''' || ioc_value || ''']'
                                ELSE '[file:hashes.''SHA-256'' = ''' || ioc_value || ''']'
                            END,
                            'pattern_type','stix',
                            'valid_from', to_char(first_seen at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS"Z"')
                        )
                    ), '[]'::jsonb)
                )::text
                FROM base
            )
            ELSE (
                -- default to json
                SELECT coalesce(jsonb_pretty(jsonb_agg(to_jsonb(base) - 'store_metadata')), '[]'::text) FROM base
            )
        END
    INTO out
    FROM base;

    RETURN coalesce(out,'');
END;
$$;
