from __future__ import annotations

import os
from dataclasses import dataclass, field

def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1","true","yes","y","on"}


def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))

def _get_secret_key() -> str:
    """Get SECRET_KEY from environment with validation.

    SECURITY: Enforces that SECRET_KEY is set and strong enough.
    """
    key = os.getenv("SECRET_KEY", "")
    if not key:
        raise RuntimeError(
            "SECURITY ERROR: SECRET_KEY environment variable must be set. "
            "Generate a secure key with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    if len(key) < 32:
        raise RuntimeError(
            f"SECURITY ERROR: SECRET_KEY must be at least 32 characters long (current: {len(key)}). "
            "Generate a secure key with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    return key

@dataclass(frozen=True)
class Config:
    # Core
    SECRET_KEY: str = field(default_factory=_get_secret_key)
    LOG_LEVEL: str = field(default_factory=lambda: _env_str("LOG_LEVEL", "INFO").upper())
    REQUESTS_PER_SECOND_MAX: int = field(default_factory=lambda: _env_int("REQUESTS_PER_SECOND_MAX", 1000000))
    RATE_LIMITS_ENABLED: bool = field(default_factory=lambda: _env_bool("RATE_LIMITS_ENABLED", True))
    QUERY_RESULT_LIMIT_MAX: int = field(default_factory=lambda: _env_int("QUERY_RESULT_LIMIT_MAX", 10000))
    EXPORT_RESULT_LIMIT_MAX: int = field(default_factory=lambda: _env_int("EXPORT_RESULT_LIMIT_MAX", 200000))
    CORRELATION_LIMIT_MAX: int = field(default_factory=lambda: _env_int("CORRELATION_LIMIT_MAX", 5000))
    HEALTH_CACHE_TTL: int = field(default_factory=lambda: _env_int("HEALTH_CACHE_TTL", 5))
    CORRELATION_CACHE_TTL: int = field(default_factory=lambda: _env_int("CORRELATION_CACHE_TTL", 30))
    CORRELATION_SNAPSHOT_ENABLED: bool = field(default_factory=lambda: _env_bool("CORRELATION_SNAPSHOT_ENABLED", True))
    CORRELATION_SNAPSHOT_INTERVAL: int = field(default_factory=lambda: _env_int("CORRELATION_SNAPSHOT_INTERVAL", 60))
    CORRELATION_SNAPSHOT_LIMIT: int = field(default_factory=lambda: _env_int("CORRELATION_SNAPSHOT_LIMIT", 1000))
    CORRELATION_SNAPSHOT_MIN_SOURCES: int = field(default_factory=lambda: _env_int("CORRELATION_SNAPSHOT_MIN_SOURCES", 2))
    CORRELATION_SNAPSHOT_TYPES: str = field(default_factory=lambda: _env_str("CORRELATION_SNAPSHOT_TYPES", "all,domain,ip,url,hash,email"))

    # DB / Redis
    DATABASE_URL: str = field(default_factory=lambda: _env_str("DATABASE_URL", "postgresql+psycopg2://threatfeed:threatfeed@localhost:5432/threatfeed"))
    DATABASE_READ_URL: str = field(default_factory=lambda: _env_str("DATABASE_READ_URL", ""))
    REDIS_URL: str = field(default_factory=lambda: _env_str("REDIS_URL", "redis://:changeme@localhost:6379/0"))
    CACHE_TTL: int = field(default_factory=lambda: _env_int("CACHE_TTL", 300))
    FEED_HTTP_TIMEOUT_S: int = field(default_factory=lambda: _env_int("FEED_HTTP_TIMEOUT_S", 30))
    FEED_RETRY_ATTEMPTS: int = field(default_factory=lambda: _env_int("FEED_RETRY_ATTEMPTS", 4))
    FEED_RETRY_BASE_DELAY_S: int = field(default_factory=lambda: _env_int("FEED_RETRY_BASE_DELAY_S", 1))
    EXPORT_JOB_DIR: str = field(default_factory=lambda: _env_str("EXPORT_JOB_DIR", "/tmp/ioc-export-jobs"))
    EXPORT_ASYNC_THRESHOLD: int = field(default_factory=lambda: _env_int("EXPORT_ASYNC_THRESHOLD", 5000))

    # Integrations
    CROWDSEC_API_KEY: str = field(default_factory=lambda: _env_str("CROWDSEC_API_KEY", ""))
    CROWDSEC_LISTS: str = field(default_factory=lambda: _env_str("CROWDSEC_LISTS", ""))

    MISP_URL: str = field(default_factory=lambda: _env_str("MISP_URL", ""))
    MISP_API_KEY: str = field(default_factory=lambda: _env_str("MISP_API_KEY", ""))
    # SECURITY: SSL verification enabled by default to prevent MITM attacks
    MISP_VERIFY_SSL: bool = field(default_factory=lambda: _env_bool("MISP_VERIFY_SSL", True))
    MISP_DAYS: int = field(default_factory=lambda: _env_int("MISP_DAYS", 7))
    MISP_SYNC_TIMEOUT_S: int = field(default_factory=lambda: _env_int("MISP_SYNC_TIMEOUT_S", 30))
    MISP_CIRCUIT_FAIL_THRESHOLD: int = field(default_factory=lambda: _env_int("MISP_CIRCUIT_FAIL_THRESHOLD", 3))
    MISP_CIRCUIT_COOLDOWN_S: int = field(default_factory=lambda: _env_int("MISP_CIRCUIT_COOLDOWN_S", 300))

    MALWAREBAZAAR_SINCE_DATE: str = field(default_factory=lambda: _env_str("MALWAREBAZAAR_SINCE_DATE", ""))
    MALWAREBAZAAR_API_URL: str = field(default_factory=lambda: _env_str("MALWAREBAZAAR_API_URL", "https://mb-api.abuse.ch/api/v1/"))
    MALWAREBAZAAR_AUTH_KEY: str = field(default_factory=lambda: _env_str("MALWAREBAZAAR_AUTH_KEY", _env_str("ABUSECH_AUTH_KEY", "")))
    MALWAREBAZAAR_TAGS: str = field(default_factory=lambda: _env_str("MALWAREBAZAAR_TAGS", ""))
    MALWAREBAZAAR_LIMIT: int = field(default_factory=lambda: _env_int("MALWAREBAZAAR_LIMIT", 1000))
    MWDB_URL: str = field(default_factory=lambda: _env_str("MWDB_URL", ""))
    MWDB_AUTH_KEY: str = field(default_factory=lambda: _env_str("MWDB_AUTH_KEY", ""))
    MWDB_CUSTOM_FILTER: str = field(default_factory=lambda: _env_str("MWDB_CUSTOM_FILTER", ""))
    MWDB_TAGS: str = field(default_factory=lambda: _env_str("MWDB_TAGS", ""))
    MWDB_DAYS: int = field(default_factory=lambda: _env_int("MWDB_DAYS", 30))
    MWDB_NO_TIME_LIMIT: bool = field(default_factory=lambda: _env_bool("MWDB_NO_TIME_LIMIT", False))
    MWDB_ORGANIZATIONS: str = field(default_factory=lambda: _env_str("MWDB_ORGANIZATIONS", ""))
    MWDB_LIMIT: int = field(default_factory=lambda: _env_int("MWDB_LIMIT", 1000))
    MWDB_CIRCUIT_FAIL_THRESHOLD: int = field(default_factory=lambda: _env_int("MWDB_CIRCUIT_FAIL_THRESHOLD", 3))
    MWDB_CIRCUIT_COOLDOWN_S: int = field(default_factory=lambda: _env_int("MWDB_CIRCUIT_COOLDOWN_S", 300))
    MWDB_MY_GROUP: str = field(default_factory=lambda: _env_str("MWDB_MY_GROUP", ""))

    ABUSECH_AUTH_KEY: str = field(default_factory=lambda: _env_str("ABUSECH_AUTH_KEY", ""))
    THREATFOX_ENABLED: bool = field(default_factory=lambda: _env_bool("THREATFOX_ENABLED", False))
    THREATFOX_API_URL: str = field(default_factory=lambda: _env_str("THREATFOX_API_URL", "https://threatfox-api.abuse.ch/api/v1/"))
    THREATFOX_AUTH_KEY: str = field(default_factory=lambda: _env_str("THREATFOX_AUTH_KEY", ""))
    THREATFOX_DAYS: int = field(default_factory=lambda: _env_int("THREATFOX_DAYS", 3))
    THREATFOX_LIMIT: int = field(default_factory=lambda: _env_int("THREATFOX_LIMIT", 1000))

    URLHAUS_ENABLED: bool = field(default_factory=lambda: _env_bool("URLHAUS_ENABLED", False))
    URLHAUS_FEED_URL: str = field(default_factory=lambda: _env_str("URLHAUS_FEED_URL", "https://urlhaus.abuse.ch/downloads/text_online/"))
    URLHAUS_LIMIT: int = field(default_factory=lambda: _env_int("URLHAUS_LIMIT", 10000))

    FEODOTRACKER_ENABLED: bool = field(default_factory=lambda: _env_bool("FEODOTRACKER_ENABLED", False))
    FEODOTRACKER_FEED_URL: str = field(default_factory=lambda: _env_str("FEODOTRACKER_FEED_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"))
    FEODOTRACKER_LIMIT: int = field(default_factory=lambda: _env_int("FEODOTRACKER_LIMIT", 10000))

    YARAIFY_ENABLED: bool = field(default_factory=lambda: _env_bool("YARAIFY_ENABLED", False))
    YARAIFY_API_URL: str = field(default_factory=lambda: _env_str("YARAIFY_API_URL", "https://yaraify-api.abuse.ch/api/v1/"))
    YARAIFY_AUTH_KEY: str = field(default_factory=lambda: _env_str("YARAIFY_AUTH_KEY", ""))
    YARAIFY_IDENTIFIER: str = field(default_factory=lambda: _env_str("YARAIFY_IDENTIFIER", ""))
    YARAIFY_LOOKUP_HASHES: str = field(default_factory=lambda: _env_str("YARAIFY_LOOKUP_HASHES", ""))
    YARAIFY_TASK_STATUS: str = field(default_factory=lambda: _env_str("YARAIFY_TASK_STATUS", "processed"))
    YARAIFY_LIMIT: int = field(default_factory=lambda: _env_int("YARAIFY_LIMIT", 250))

    HUNTING_FPLIST_ENABLED: bool = field(default_factory=lambda: _env_bool("HUNTING_FPLIST_ENABLED", False))
    HUNTING_API_URL: str = field(default_factory=lambda: _env_str("HUNTING_API_URL", "https://hunting-api.abuse.ch/api/v1/"))
    HUNTING_AUTH_KEY: str = field(default_factory=lambda: _env_str("HUNTING_AUTH_KEY", ""))
    HUNTING_FPLIST_FORMAT: str = field(default_factory=lambda: _env_str("HUNTING_FPLIST_FORMAT", "csv"))
    HUNTING_FPLIST_LIMIT: int = field(default_factory=lambda: _env_int("HUNTING_FPLIST_LIMIT", 10000))
    ABUSECH_TIMEOUT_S: int = field(default_factory=lambda: _env_int("ABUSECH_TIMEOUT_S", 30))
    ABUSECH_RETRY_ATTEMPTS: int = field(default_factory=lambda: _env_int("ABUSECH_RETRY_ATTEMPTS", 4))
    ABUSECH_RETRY_BASE_DELAY_S: int = field(default_factory=lambda: _env_int("ABUSECH_RETRY_BASE_DELAY_S", 1))
    ABUSECH_CIRCUIT_FAIL_THRESHOLD: int = field(default_factory=lambda: _env_int("ABUSECH_CIRCUIT_FAIL_THRESHOLD", 3))
    ABUSECH_CIRCUIT_COOLDOWN_S: int = field(default_factory=lambda: _env_int("ABUSECH_CIRCUIT_COOLDOWN_S", 300))


    # Worker
    ENABLE_BACKGROUND_JOBS: bool = field(default_factory=lambda: _env_bool("ENABLE_BACKGROUND_JOBS", True))
    UPDATE_INTERVAL: int = field(default_factory=lambda: _env_int("UPDATE_INTERVAL", 600))

    # Security
    ALLOWED_HOSTS: str = field(default_factory=lambda: _env_str("ALLOWED_HOSTS", "*"))
    CORS_ORIGINS: str = field(default_factory=lambda: _env_str("CORS_ORIGINS", "*"))
    METRICS_AUTH_TOKEN: str = field(default_factory=lambda: _env_str("METRICS_AUTH_TOKEN", ""))
