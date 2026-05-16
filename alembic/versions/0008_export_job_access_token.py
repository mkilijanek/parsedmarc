"""export job access token and expiry

Revision ID: 0008_export_job_token
Revises: 0007_dlq_requeue_state
Create Date: 2026-05-16 20:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0008_export_job_token"
down_revision = "0007_dlq_requeue_state"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = inspector.get_columns(table_name)
    return any(col["name"] == column_name for col in columns)


def _has_index(table_name: str, index_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(idx["name"] == index_name for idx in inspector.get_indexes(table_name))


def upgrade() -> None:
    if not _has_column("export_jobs", "access_token"):
        op.add_column(
            "export_jobs",
            sa.Column("access_token", sa.String(length=64), nullable=True),
        )
        op.create_unique_constraint("uq_export_jobs_access_token", "export_jobs", ["access_token"])
    if not _has_column("export_jobs", "expires_at"):
        op.add_column(
            "export_jobs",
            sa.Column("expires_at", sa.DateTime(), nullable=True),
        )
    if not _has_index("export_jobs", "idx_export_jobs_expires_at"):
        op.create_index("idx_export_jobs_expires_at", "export_jobs", ["expires_at"])


def downgrade() -> None:
    op.drop_index("idx_export_jobs_expires_at", table_name="export_jobs", if_exists=True)
    op.drop_constraint("uq_export_jobs_access_token", "export_jobs", type_="unique", if_exists=True)
    if _has_column("export_jobs", "expires_at"):
        op.drop_column("export_jobs", "expires_at")
    if _has_column("export_jobs", "access_token"):
        op.drop_column("export_jobs", "access_token")
