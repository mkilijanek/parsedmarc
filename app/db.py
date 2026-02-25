from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, DeclarativeBase
from sqlalchemy.pool import QueuePool
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://threatfeed:threatfeed@localhost:5432/threatfeed")
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "6"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "4"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "1800"))
DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))

class Base(DeclarativeBase):
    pass

# Resource-aware defaults for shared hosts (ELK/parsedmarc co-located).
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=max(1, DB_POOL_SIZE),
    max_overflow=max(0, DB_MAX_OVERFLOW),
    pool_timeout=max(1, DB_POOL_TIMEOUT),
    pool_pre_ping=True,
    pool_recycle=max(30, DB_POOL_RECYCLE),
    pool_use_lifo=True,
    future=True,
)

SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
