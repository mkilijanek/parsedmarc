"""dead letter job requeue state

Revision ID: 0007_dlq_requeue_state
Revises: 0006_dead_letter_jobs
Create Date: 2026-04-30 12:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0007_dlq_requeue_state"
down_revision = "0006_dead_letter_jobs"
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
    if not _has_column("dead_letter_jobs", "status"):
        op.add_column(
            "dead_letter_jobs",
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        )
    if not _has_column("dead_letter_jobs", "requeue_sync_job_id"):
        op.add_column(
            "dead_letter_jobs",
            sa.Column("requeue_sync_job_id", sa.String(length=64), nullable=True),
        )
    op.execute(
        sa.text(
            "UPDATE dead_letter_jobs "
            "SET status = CASE WHEN COALESCE(requeue_count, 0) > 0 THEN 'requeued' ELSE 'pending' END "
            "WHERE status IS NULL OR status = ''"
        )
    )
    if not _has_index("dead_letter_jobs", "idx_dlq_status_created"):
        op.create_index("idx_dlq_status_created", "dead_letter_jobs", ["status", "created_at"])


def downgrade() -> None:
    op.drop_index("idx_dlq_status_created", table_name="dead_letter_jobs", if_exists=True)
    if _has_column("dead_letter_jobs", "requeue_sync_job_id"):
        op.drop_column("dead_letter_jobs", "requeue_sync_job_id")
    if _has_column("dead_letter_jobs", "status"):
        op.drop_column("dead_letter_jobs", "status")
