from __future__ import annotations

from sqlalchemy import String, Integer, Boolean, Text, DateTime, func, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY, INET
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base
import uuid

class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    value: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # ip, domain, url, hash, email
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    source_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    confidence: Mapped[int] = mapped_column(Integer, server_default="50", nullable=False)
    tlp: Mapped[str] = mapped_column(String(20), server_default="WHITE", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)

    metadata: Mapped[dict] = mapped_column(JSONB, server_default="{}")
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")

    created_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("value", "source", "source_id", name="unique_indicator"),
    )

class FeedStats(Base):
    __tablename__ = "feed_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    source_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    total_indicators: Mapped[int] = mapped_column(Integer, server_default="0")
    active_indicators: Mapped[int] = mapped_column(Integer, server_default="0")
    inactive_indicators: Mapped[int] = mapped_column(Integer, server_default="0")
    last_update: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    last_fetch_status: Mapped[str | None] = mapped_column(String(50))
    last_fetch_error: Mapped[str | None] = mapped_column(Text)
    metadata: Mapped[dict] = mapped_column(JSONB, server_default="{}")

    __table_args__ = (
        UniqueConstraint("source", "source_id", name="unique_feed_stats"),
    )

class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(50))
    entity_id: Mapped[int | None] = mapped_column(Integer)
    user_id: Mapped[str | None] = mapped_column(String(100))
    ip_address: Mapped[str | None] = mapped_column(INET)
    metadata: Mapped[dict] = mapped_column(JSONB, server_default="{}")
    created_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
