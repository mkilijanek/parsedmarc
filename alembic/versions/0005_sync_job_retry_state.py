"""sync job retry state

Revision ID: 0005_sync_job_retry_state
Revises: 0004_audit_log_integrity
Create Date: 2026-04-20 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0005_sync_job_retry_state"
down_revision = "0004_audit_log_integrity"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    if not _has_column("sync_jobs", "retry_count"):
        op.add_column("sync_jobs", sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"))
    if not _has_column("sync_jobs", "max_retries"):
        op.add_column("sync_jobs", sa.Column("max_retries", sa.Integer(), nullable=False, server_default="3"))
    if not _has_column("sync_jobs", "failure_class"):
        op.add_column("sync_jobs", sa.Column("failure_class", sa.String(length=32), nullable=True))
    if not _has_column("sync_jobs", "next_attempt_at"):
        op.add_column("sync_jobs", sa.Column("next_attempt_at", sa.DateTime(), nullable=True))
    op.create_index(
        "idx_sync_jobs_status_next_attempt",
        "sync_jobs",
        ["status", "next_attempt_at"],
        unique=False,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("idx_sync_jobs_status_next_attempt", table_name="sync_jobs", if_exists=True)
    for column_name in ("next_attempt_at", "failure_class", "max_retries", "retry_count"):
        if _has_column("sync_jobs", column_name):
            op.drop_column("sync_jobs", column_name)
