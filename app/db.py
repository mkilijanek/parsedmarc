from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker
from sqlalchemy.pool import QueuePool

from .config import DatabaseConfig


class Base(DeclarativeBase):
    pass


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
