from __future__ import annotations

import uuid

from sqlalchemy import String, Integer, Boolean, Text, DateTime, func, UniqueConstraint
from sqlalchemy import types
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY, INET
from sqlalchemy.sql.functions import FunctionElement
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base


class UUIDCompat(types.TypeDecorator):
    impl = types.CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(UUID(as_uuid=True))
        return dialect.type_descriptor(types.CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
        return str(value if isinstance(value, uuid.UUID) else uuid.UUID(str(value)))

    def process_result_value(self, value, dialect):
        if value is None or isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class JSONCompat(types.TypeDecorator):
    impl = types.JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB)
        return dialect.type_descriptor(types.JSON)


class StringArrayCompat(types.TypeDecorator):
    impl = types.JSON
    cache_ok = True

    class Comparator(types.TypeDecorator.Comparator):
        def any(self, other):
            return tags_contains(self.expr, other)

    comparator_factory = Comparator

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(Text))
        return dialect.type_descriptor(types.JSON)

    def process_bind_param(self, value, dialect):
        if value is None:
            return []
        return list(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        return list(value)


class InetCompat(types.TypeDecorator):
    impl = types.String
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(INET)
        return dialect.type_descriptor(types.String(45))


class TagsContains(FunctionElement):
    type = types.Boolean()
    inherit_cache = True


@compiles(TagsContains, "sqlite")
def _compile_tags_contains_sqlite(element, compiler, **kw):
    tags_expr, value_expr = list(element.clauses)
    tags_sql = compiler.process(tags_expr, **kw)
    value_sql = compiler.process(value_expr, **kw)
    return (
        f"EXISTS (SELECT 1 FROM json_each({tags_sql}) "
        f"WHERE json_each.value = {value_sql})"
    )


@compiles(TagsContains, "postgresql")
def _compile_tags_contains_postgresql(element, compiler, **kw):
    tags_expr, value_expr = list(element.clauses)
    tags_sql = compiler.process(tags_expr, **kw)
    value_sql = compiler.process(value_expr, **kw)
    return f"{tags_sql} @> ARRAY[{value_sql}]::text[]"


def tags_contains(tags_column, value):
    return TagsContains(tags_column, value)

class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[uuid.UUID] = mapped_column(UUIDCompat(), default=uuid.uuid4, unique=True, nullable=False)

    value: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # ip, domain, url, hash, email
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    source_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    confidence: Mapped[int] = mapped_column(Integer, server_default="50", nullable=False)
    tlp: Mapped[str] = mapped_column(String(20), server_default="WHITE", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)

    metadata_: Mapped[dict] = mapped_column("metadata", JSONCompat(), default=dict, nullable=False)
    tags: Mapped[list[str]] = mapped_column(StringArrayCompat(), default=list, nullable=False)

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
    metadata_: Mapped[dict] = mapped_column("metadata", JSONCompat(), default=dict, nullable=False)

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
    ip_address: Mapped[str | None] = mapped_column(InetCompat())
    metadata_: Mapped[dict] = mapped_column("metadata", JSONCompat(), default=dict, nullable=False)
    created_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
