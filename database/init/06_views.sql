SET search_path = ti, public;

-- Unified view for consumption by app layer (presentation).
CREATE OR REPLACE VIEW v_iocs_unified AS
SELECT
    i.id,
    i.uuid,
    i.ioc_value,
    i.ioc_type,
    i.source,
    i.source_ref,
    i.confidence,
    i.tlp,
    i.is_active,
    i.tags,
    i.comments,
    i.metadata,
    i.first_seen,
    i.last_seen,
    m.platform,
    m.package_name,
    m.app_version,
    m.permissions,
    m.cert_fingerprint,
    m.store_metadata
FROM indicators i
LEFT JOIN mobile_app_iocs m ON m.indicator_id = i.id;

-- Dedicated mobile consumption view (APK/iOS)
CREATE OR REPLACE VIEW v_mobile_iocs AS
SELECT
    i.uuid,
    i.ioc_value      AS app_artifact,
    i.ioc_type       AS artifact_type,
    m.platform,
    m.package_name,
    m.app_version,
    m.permissions,
    m.cert_fingerprint,
    i.source,
    i.source_ref,
    i.confidence,
    i.tlp,
    i.tags,
    i.comments,
    i.metadata,
    i.first_seen,
    i.last_seen,
    i.is_active,
    i.created_at,
    i.updated_at,
    m.store_metadata
FROM indicators i
JOIN mobile_app_iocs m ON m.indicator_id = i.id;

-- Convenience view: indicators likely to be file-artifacts (hashes etc.)
CREATE OR REPLACE VIEW v_file_artifacts AS
SELECT
    i.uuid,
    i.ioc_value,
    i.ioc_type,
    i.source,
    i.source_ref,
    i.confidence,
    i.tlp,
    i.tags,
    i.comments,
    i.metadata,
    i.first_seen,
    i.last_seen,
    i.is_active
FROM indicators i
WHERE i.ioc_type IN ('hash','sha256','sha1','md5','imphash','ssdeep','tlsh','apk_hash','ios_hash');
