"""audit log integrity fields

Revision ID: 0004_audit_log_integrity
Revises: 0003_feed_runs_status_index
Create Date: 2026-04-20 00:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0004_audit_log_integrity"
down_revision = "0003_feed_runs_status_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("audit_log")}
    with op.batch_alter_table("audit_log") as batch_op:
        if "previous_hash" not in existing:
            batch_op.add_column(sa.Column("previous_hash", sa.String(length=64), nullable=True))
        if "log_hash" not in existing:
            batch_op.add_column(sa.Column("log_hash", sa.String(length=64), nullable=True))


def downgrade() -> None:
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("audit_log")}
    with op.batch_alter_table("audit_log") as batch_op:
        if "log_hash" in existing:
            batch_op.drop_column("log_hash")
        if "previous_hash" in existing:
            batch_op.drop_column("previous_hash")
