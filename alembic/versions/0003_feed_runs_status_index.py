"""feed_runs status index

Revision ID: 0003_feed_runs_status_index
Revises: 0002_sync_jobs_extra_indexes
Create Date: 2026-02-27 00:00:00
"""
from __future__ import annotations

from alembic import op


revision = "0003_feed_runs_status_index"
down_revision = "0002_sync_jobs_extra_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE INDEX IF NOT EXISTS idx_feed_runs_status_started ON feed_runs (status, started_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_feed_runs_status_started")
