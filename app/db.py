from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, DeclarativeBase
from sqlalchemy.pool import QueuePool
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://threatfeed:threatfeed@localhost:5432/threatfeed")

class Base(DeclarativeBase):
    pass

# Pooling: 10 connections + 20 overflow (as requested)
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=1800,
    future=True,
)

SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
