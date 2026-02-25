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

    # DB / Redis
    DATABASE_URL: str = field(default_factory=lambda: _env_str("DATABASE_URL", "postgresql+psycopg2://threatfeed:threatfeed@localhost:5432/threatfeed"))
    REDIS_URL: str = field(default_factory=lambda: _env_str("REDIS_URL", "redis://:changeme@localhost:6379/0"))
    CACHE_TTL: int = field(default_factory=lambda: _env_int("CACHE_TTL", 300))

    # Integrations
    CROWDSEC_API_KEY: str = field(default_factory=lambda: _env_str("CROWDSEC_API_KEY", ""))
    CROWDSEC_LISTS: str = field(default_factory=lambda: _env_str("CROWDSEC_LISTS", ""))

    MISP_URL: str = field(default_factory=lambda: _env_str("MISP_URL", ""))
    MISP_API_KEY: str = field(default_factory=lambda: _env_str("MISP_API_KEY", ""))
    # SECURITY: SSL verification enabled by default to prevent MITM attacks
    MISP_VERIFY_SSL: bool = field(default_factory=lambda: _env_bool("MISP_VERIFY_SSL", True))
    MISP_DAYS: int = field(default_factory=lambda: _env_int("MISP_DAYS", 7))

    MALWAREBAZAAR_SINCE_DATE: str = field(default_factory=lambda: _env_str("MALWAREBAZAAR_SINCE_DATE", ""))
    MALWAREBAZAAR_API_URL: str = field(default_factory=lambda: _env_str("MALWAREBAZAAR_API_URL", "https://mb-api.abuse.ch/api/v1/"))
    MALWAREBAZAAR_AUTH_KEY: str = field(default_factory=lambda: _env_str("MALWAREBAZAAR_AUTH_KEY", ""))
    MWDB_URL: str = field(default_factory=lambda: _env_str("MWDB_URL", ""))
    MWDB_AUTH_KEY: str = field(default_factory=lambda: _env_str("MWDB_AUTH_KEY", ""))


    # Worker
    ENABLE_BACKGROUND_JOBS: bool = field(default_factory=lambda: _env_bool("ENABLE_BACKGROUND_JOBS", True))
    UPDATE_INTERVAL: int = field(default_factory=lambda: _env_int("UPDATE_INTERVAL", 600))

    # Security
    ALLOWED_HOSTS: str = field(default_factory=lambda: _env_str("ALLOWED_HOSTS", "*"))
    CORS_ORIGINS: str = field(default_factory=lambda: _env_str("CORS_ORIGINS", "*"))
