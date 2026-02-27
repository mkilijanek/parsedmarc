from __future__ import annotations

import uuid

from sqlalchemy import String, Integer, Boolean, Text, DateTime, func, UniqueConstraint, Index
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

    confidence: Mapped[int] = mapped_column(Integer, default=50, server_default="50", nullable=False)
    tlp: Mapped[str] = mapped_column(String(20), default="WHITE", server_default="WHITE", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)

    metadata_: Mapped[dict] = mapped_column("metadata", JSONCompat(), default=dict, nullable=False)
    tags: Mapped[list[str]] = mapped_column(StringArrayCompat(), default=list, nullable=False)

    created_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("idx_indicators_active_last_seen", "is_active", "last_seen"),
        Index("idx_indicators_active_type_last_seen", "is_active", "type", "last_seen"),
        Index("idx_indicators_active_source_last_seen", "is_active", "source", "last_seen"),
        Index("idx_indicators_active_tlp_conf_last_seen", "is_active", "tlp", "confidence", "last_seen"),
        Index("idx_indicators_value_type_active", "value", "type", "is_active"),
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


class AppSetting(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    is_secret: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    updated_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class ExportJob(Base):
    __tablename__ = "export_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    fmt: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", server_default="queued")
    result_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    query_json: Mapped[dict] = mapped_column(JSONCompat(), default=dict, nullable=False)
    created_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class Feed(Base):
    __tablename__ = "feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    source_type: Mapped[str] = mapped_column(String(80), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    schedule_cron: Mapped[str] = mapped_column(String(64), nullable=False, default="*/15 * * * *", server_default="*/15 * * * *")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    created_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class FeedRun(Base):
    __tablename__ = "feed_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feed_source_id: Mapped[str] = mapped_column(String(120), nullable=False)
    run_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False, default="manual", server_default="manual")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running", server_default="running")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    started_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    finished_at: Mapped["DateTime | None"] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        Index("idx_feed_runs_feed_started", "feed_source_id", "started_at"),
        Index("idx_feed_runs_status_started", "status", "started_at"),
    )


class AppLog(Base):
    __tablename__ = "app_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="INFO", server_default="INFO")
    component: Mapped[str] = mapped_column(String(64), nullable=False, default="app", server_default="app")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    feed_source_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONCompat(), default=dict, nullable=False)
    created_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("idx_app_logs_created", "created_at"),
        Index("idx_app_logs_feed_created", "feed_source_id", "created_at"),
    )


class SyncJob(Base):
    __tablename__ = "sync_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    feed_source_id: Mapped[str] = mapped_column(String(120), nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False, default="manual", server_default="manual")
    idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", server_default="queued")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[dict] = mapped_column(JSONCompat(), default=dict, nullable=False)
    created_at: Mapped["DateTime"] = mapped_column(DateTime, server_default=func.now())
    started_at: Mapped["DateTime | None"] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped["DateTime | None"] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        Index("idx_sync_jobs_feed_status", "feed_source_id", "status"),
        Index("idx_sync_jobs_created", "created_at"),
        Index("idx_sync_jobs_status_created", "status", "created_at"),
        Index("idx_sync_jobs_trigger_status", "trigger_type", "status"),
    )
