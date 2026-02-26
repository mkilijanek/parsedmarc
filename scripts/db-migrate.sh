#!/usr/bin/env sh
set -eu

if [ -z "${DATABASE_URL:-}" ]; then
  export DATABASE_URL="postgresql+psycopg2://threatfeed:threatfeed@postgres:5432/threatfeed"
fi

python - <<'PY'
import os
from sqlalchemy import create_engine, text
from alembic.config import Config
from alembic import command

url = os.environ["DATABASE_URL"]
engine = create_engine(url, future=True)
lock_id = 993452
acquired = False

with engine.begin() as conn:
    if engine.dialect.name == "postgresql":
        acquired = bool(conn.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}).scalar())
        if not acquired:
            print("Migration lock not acquired; another instance is migrating. Exiting.")
            raise SystemExit(0)

try:
    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
finally:
    if acquired:
        with engine.begin() as conn:
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id})
PY
