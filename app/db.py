from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker
from sqlalchemy.pool import QueuePool

from .config import DatabaseConfig


class Base(DeclarativeBase):
    pass


_db_success_observers: list[Callable[[], None]] = []
_db_failure_observers: list[Callable[[], None]] = []


def _notify_success(*_args, **_kwargs) -> None:
    for callback in tuple(_db_success_observers):
        try:
            callback()
        except Exception:
            continue


def _notify_failure(*_args, **_kwargs) -> None:
    for callback in tuple(_db_failure_observers):
        try:
            callback()
        except Exception:
            continue


def register_db_circuit_observers(
    *,
    on_success: Callable[[], None] | None = None,
    on_failure: Callable[[], None] | None = None,
) -> None:
    if on_success is not None and on_success not in _db_success_observers:
        _db_success_observers.append(on_success)
    if on_failure is not None and on_failure not in _db_failure_observers:
        _db_failure_observers.append(on_failure)


def _build_engine(url: str, cfg: DatabaseConfig):
    return create_engine(
        url,
        poolclass=QueuePool,
        pool_size=max(1, cfg.DB_POOL_SIZE),
        max_overflow=max(0, cfg.DB_MAX_OVERFLOW),
        pool_timeout=max(1, cfg.DB_POOL_TIMEOUT),
        pool_pre_ping=True,
        pool_recycle=max(30, cfg.DB_POOL_RECYCLE),
        pool_use_lifo=True,
        future=True,
    )


_db_cfg = DatabaseConfig.from_env()

# Resource-aware defaults for shared hosts (ELK/parsedmarc co-located).
engine = _build_engine(_db_cfg.DATABASE_URL, _db_cfg)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))

if _db_cfg.DATABASE_READ_URL:
    read_engine = _build_engine(_db_cfg.DATABASE_READ_URL, _db_cfg)
    SessionReadLocal = scoped_session(sessionmaker(bind=read_engine, autoflush=False, autocommit=False, future=True))
else:
    SessionReadLocal = SessionLocal

for _sql_engine in ({engine, read_engine} if _db_cfg.DATABASE_READ_URL else {engine}):
    if _sql_engine is None:
        continue
    event.listen(_sql_engine, "after_cursor_execute", _notify_success)
    event.listen(_sql_engine, "handle_error", _notify_failure)


def get_session(*, read_only: bool = False):
    if read_only:
        return SessionReadLocal()
    return SessionLocal()


def get_db():
    db = get_session(read_only=False)
    try:
        yield db
    finally:
        db.close()
