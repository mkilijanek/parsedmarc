from __future__ import annotations

import os
from dataclasses import dataclass

def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1","true","yes","y","on"}

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
    SECRET_KEY: str = _get_secret_key()
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

    # DB / Redis
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg2://threatfeed:threatfeed@localhost:5432/threatfeed")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://:changeme@localhost:6379/0")
    CACHE_TTL: int = int(os.getenv("CACHE_TTL", "300"))

    # Integrations
    CROWDSEC_API_KEY: str = os.getenv("CROWDSEC_API_KEY", "")
    CROWDSEC_LISTS: str = os.getenv("CROWDSEC_LISTS", "")

    MISP_URL: str = os.getenv("MISP_URL", "")
    MISP_API_KEY: str = os.getenv("MISP_API_KEY", "")
    # SECURITY: SSL verification enabled by default to prevent MITM attacks
    MISP_VERIFY_SSL: bool = _env_bool("MISP_VERIFY_SSL", True)
    MISP_DAYS: int = int(os.getenv("MISP_DAYS", "7"))

    MALWAREBAZAAR_SINCE_DATE: str = os.getenv("MALWAREBAZAAR_SINCE_DATE", "")
    MALWAREBAZAAR_API_URL: str = os.getenv("MALWAREBAZAAR_API_URL", "https://mb-api.abuse.ch/api/v1/")
    MALWAREBAZAAR_AUTH_KEY: str = os.getenv("MALWAREBAZAAR_AUTH_KEY", "")
    MWDB_URL: str = os.getenv("MWDB_URL", "")
    MWDB_AUTH_KEY: str = os.getenv("MWDB_AUTH_KEY", "")


    # Worker
    ENABLE_BACKGROUND_JOBS: bool = _env_bool("ENABLE_BACKGROUND_JOBS", True)
    UPDATE_INTERVAL: int = int(os.getenv("UPDATE_INTERVAL", "600"))

    # Security
    ALLOWED_HOSTS: str = os.getenv("ALLOWED_HOSTS", "*")
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")
