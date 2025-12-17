SET search_path = ti, public;

-- Mobile app-specific context for IOC that represent an app artifact (APK / iOS IPA / app bundle)
-- Keep IOC in indicators (hash/value), store mobile fields here (1:1 with indicators row).
CREATE TABLE IF NOT EXISTS mobile_app_iocs (
    indicator_id      BIGINT PRIMARY KEY REFERENCES indicators(id) ON DELETE CASCADE,
    platform          TEXT NOT NULL CHECK (platform IN ('android','ios')),
    package_name      TEXT,                 -- Android: packageName; iOS: bundleIdentifier (if known)
    app_version       TEXT,                 -- versionName/versionCode or CFBundleShortVersionString/CFBundleVersion
    permissions       TEXT[] NOT NULL DEFAULT '{}'::text[], -- Android perms; iOS entitlements (if extracted)
    cert_fingerprint  TEXT,                 -- signer cert SHA256 (Android) / signing identity (iOS) if available
    store_metadata    JSONB NOT NULL DEFAULT '{}'::jsonb     -- app store refs, SDK info, trackers, etc.
);

-- Optional: normalize permissions to support fast "who requests X?"
CREATE TABLE IF NOT EXISTS mobile_permissions (
    indicator_id BIGINT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    platform     TEXT NOT NULL CHECK (platform IN ('android','ios')),
    permission   TEXT NOT NULL,
    PRIMARY KEY (indicator_id, permission)
);
