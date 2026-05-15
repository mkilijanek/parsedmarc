from __future__ import annotations

from logging.config import fileConfig
import os

from sqlalchemy import engine_from_config, pool, text
from alembic import context

from app.db import Base
from app import models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    return os.getenv("DATABASE_URL", config.get_main_option("sqlalchemy.url"))


def run_migrations_offline() -> None:
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # Alembic's default version_num column is VARCHAR(32); widen it so
        # migration IDs longer than 32 chars (e.g. 0007_dead_letter_job_requeue_state)
        # can be written without StringDataRightTruncation.
        connection.execute(text(
            "ALTER TABLE IF EXISTS alembic_version "
            "ALTER COLUMN version_num TYPE VARCHAR(128)"
        ))
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
