"""sync jobs extra indexes

Revision ID: 0002_sync_jobs_extra_indexes
Revises: 0001_baseline_schema
Create Date: 2026-02-26 00:30:00
"""
from __future__ import annotations

from alembic import op


revision = "0002_sync_jobs_extra_indexes"
down_revision = "0001_baseline_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE INDEX IF NOT EXISTS idx_sync_jobs_status_created ON sync_jobs (status, created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_sync_jobs_trigger_status ON sync_jobs (trigger_type, status)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_sync_jobs_trigger_status")
    op.execute("DROP INDEX IF EXISTS idx_sync_jobs_status_created")
