from __future__ import annotations

from app.config import Config, DatabaseConfig


def test_config_exposes_grouped_sections_and_legacy_access(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    monkeypatch.setenv("DATABASE_URL", "sqlite:////tmp/test-grouped-config.db")
    monkeypatch.setenv("ADMIN_API_TOKEN", "token-123")

    cfg = Config()

    assert cfg.database.DATABASE_URL == "sqlite:////tmp/test-grouped-config.db"
    assert cfg.security.ADMIN_API_TOKEN == "token-123"
    assert cfg.DATABASE_URL == cfg.database.DATABASE_URL
    assert cfg.ADMIN_API_TOKEN == cfg.security.ADMIN_API_TOKEN
    assert cfg.as_dict()["DATABASE_URL"] == "sqlite:////tmp/test-grouped-config.db"


def test_database_config_reads_env_from_config_layer(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:////tmp/test-db-layer.db")
    monkeypatch.setenv("DATABASE_READ_URL", "sqlite:////tmp/test-db-layer-read.db")
    monkeypatch.setenv("DB_POOL_SIZE", "9")
    monkeypatch.setenv("DB_MAX_OVERFLOW", "5")
    monkeypatch.setenv("DB_POOL_TIMEOUT", "42")
    monkeypatch.setenv("DB_POOL_RECYCLE", "3600")

    db_cfg = DatabaseConfig.from_env()

    assert db_cfg.DATABASE_URL.endswith("test-db-layer.db")
    assert db_cfg.DATABASE_READ_URL.endswith("test-db-layer-read.db")
    assert db_cfg.DB_POOL_SIZE == 9
    assert db_cfg.DB_MAX_OVERFLOW == 5
    assert db_cfg.DB_POOL_TIMEOUT == 42
    assert db_cfg.DB_POOL_RECYCLE == 3600
