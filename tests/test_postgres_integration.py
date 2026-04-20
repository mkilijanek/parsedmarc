from __future__ import annotations

import os

import pytest
from sqlalchemy import delete, inspect, select


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="PostgreSQL integration tests require RUN_POSTGRES_TESTS=1",
)


def _require_postgres() -> None:
    from app.db import engine

    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL integration tests require a PostgreSQL DATABASE_URL")


def test_postgres_jsonb_array_and_tag_lookup_roundtrip():
    _require_postgres()

    from app.db import SessionLocal
    from app.models import Indicator, tags_contains

    db = SessionLocal()
    try:
        db.execute(delete(Indicator).where(Indicator.source == "pg_integration"))
        indicator = Indicator(
            value="pg-integration.example",
            type="domain",
            source="pg_integration",
            source_id="case-1",
            confidence=88,
            tlp="AMBER",
            tags=["apt", "postgres"],
            metadata_={"nested": {"score": 88}, "source": "pytest"},
        )
        db.add(indicator)
        db.commit()

        row = db.scalars(
            select(Indicator).where(
                Indicator.source == "pg_integration",
                tags_contains(Indicator.tags, "postgres"),
            )
        ).one()

        assert row.metadata_["nested"]["score"] == 88
        assert "postgres" in row.tags
        assert row.tlp == "AMBER"
    finally:
        db.execute(delete(Indicator).where(Indicator.source == "pg_integration"))
        db.commit()
        db.close()


def test_postgres_migration_schema_contains_integrity_columns():
    _require_postgres()

    from app.db import engine

    inspector = inspect(engine)
    audit_columns = {column["name"] for column in inspector.get_columns("audit_log")}
    sync_job_columns = {column["name"] for column in inspector.get_columns("sync_jobs")}

    assert {"previous_hash", "log_hash"}.issubset(audit_columns)
    assert {
        "job_id",
        "feed_source_id",
        "status",
        "retry_count",
        "max_retries",
        "failure_class",
        "next_attempt_at",
        "created_at",
    }.issubset(sync_job_columns)
