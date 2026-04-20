#!/usr/bin/env python
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, inspect


ROOT = Path(__file__).resolve().parents[1]


def _metadata_tables() -> dict[str, set[str]]:
    from app import models  # noqa: F401
    from app.db import Base

    return {
        table.name: {column.name for column in table.columns}
        for table in Base.metadata.sorted_tables
    }


def _migrated_tables(db_url: str) -> dict[str, set[str]]:
    alembic_cfg = AlembicConfig(str(ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(ROOT / "alembic"))
    previous_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = db_url
    try:
        command.upgrade(alembic_cfg, "head")
    finally:
        if previous_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_url

    engine = create_engine(db_url, future=True)
    try:
        inspector = inspect(engine)
        return {
            table: {column["name"] for column in inspector.get_columns(table)}
            for table in inspector.get_table_names()
            if table != "alembic_version"
        }
    finally:
        engine.dispose()


def _legacy_sql_tables() -> set[str]:
    init_dir = ROOT / "database" / "init"
    text = "\n".join(path.read_text(encoding="utf-8") for path in sorted(init_dir.glob("*.sql")))
    return set(re.findall(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+(?:\w+\.)?(\w+)\s*\(", text, flags=re.I))


def _diff_tables(expected: dict[str, set[str]], actual: dict[str, set[str]]) -> list[str]:
    errors: list[str] = []
    missing_tables = sorted(set(expected) - set(actual))
    extra_tables = sorted(set(actual) - set(expected))
    if missing_tables:
        errors.append(f"missing migrated tables: {', '.join(missing_tables)}")
    if extra_tables:
        errors.append(f"unexpected migrated tables: {', '.join(extra_tables)}")
    for table in sorted(set(expected) & set(actual)):
        missing_columns = sorted(expected[table] - actual[table])
        extra_columns = sorted(actual[table] - expected[table])
        if missing_columns:
            errors.append(f"{table}: missing columns: {', '.join(missing_columns)}")
        if extra_columns:
            errors.append(f"{table}: unexpected columns: {', '.join(extra_columns)}")
    return errors


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ioc-schema-") as tmpdir:
        db_url = f"sqlite:///{Path(tmpdir) / 'schema.db'}"
        expected = _metadata_tables()
        actual = _migrated_tables(db_url)
        errors = _diff_tables(expected, actual)

    legacy_tables = _legacy_sql_tables()
    legacy_overlap = sorted(set(expected) & legacy_tables)

    print(f"ORM tables: {len(expected)}")
    print(f"Alembic migrated tables: {len(actual)}")
    print(f"Legacy SQL tables inventoried: {len(legacy_tables)}")
    print(f"Legacy SQL overlap with ORM: {', '.join(legacy_overlap) if legacy_overlap else 'none'}")

    if errors:
        print("Schema drift detected:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Schema drift check OK: ORM metadata and Alembic head match.")
    if legacy_tables:
        print("Legacy SQL inventory is reported for convergence tracking and is not a failing gate yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
