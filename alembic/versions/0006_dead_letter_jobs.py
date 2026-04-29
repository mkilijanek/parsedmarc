"""dead letter jobs table

Revision ID: 0006_dead_letter_jobs
Revises: 0005_sync_job_retry_state
Create Date: 2026-04-29 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0006_dead_letter_jobs"
down_revision = "0005_sync_job_retry_state"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def upgrade() -> None:
    if not _has_table("dead_letter_jobs"):
        op.create_table(
            "dead_letter_jobs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("original_job_id", sa.String(64), nullable=False),
            sa.Column("feed_source_id", sa.String(120), nullable=False),
            sa.Column("failure_class", sa.String(32), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("payload", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("requeue_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_requeued_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        )
        op.create_index(
            "idx_dlq_original_job_id", "dead_letter_jobs", ["original_job_id"]
        )
        op.create_index(
            "idx_dlq_feed_created", "dead_letter_jobs", ["feed_source_id", "created_at"]
        )


def downgrade() -> None:
    op.drop_index("idx_dlq_feed_created", table_name="dead_letter_jobs", if_exists=True)
    op.drop_index("idx_dlq_original_job_id", table_name="dead_letter_jobs", if_exists=True)
    if _has_table("dead_letter_jobs"):
        op.drop_table("dead_letter_jobs")
