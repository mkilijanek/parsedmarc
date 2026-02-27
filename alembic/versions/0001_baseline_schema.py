"""baseline schema

Revision ID: 0001_baseline_schema
Revises:
Create Date: 2026-02-26 00:00:00
"""
from __future__ import annotations

from alembic import op

from app.db import Base
from app import models  # noqa: F401


# revision identifiers, used by Alembic.
revision = "0001_baseline_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
