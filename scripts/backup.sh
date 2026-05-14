#!/usr/bin/env bash
# PostgreSQL + Redis backup script for ioc-service.
# Implements ISO 27001 A.12.3.1 (Information Backup).
#
# Usage:
#   backup.sh [--retention-days N] [--backup-dir PATH] [--remote-dest RCLONE_DEST]
#
# Environment variables (override defaults):
#   DATABASE_URL        PostgreSQL connection string
#   REDIS_URL           Redis URL (redis://:password@host:port/db)
#   BACKUP_DIR          Local directory for backup files (default: /var/backups/ioc-service)
#   BACKUP_RETENTION_DAYS  Delete local backups older than N days (default: 30)
#   BACKUP_REMOTE_DEST  rclone destination (e.g. "s3:my-bucket/ioc-backups") — optional
#   BACKUP_ENCRYPT      Set to "true" to encrypt with gpg (requires BACKUP_GPG_RECIPIENT)
#   BACKUP_GPG_RECIPIENT  GPG key fingerprint or email for encryption

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
BACKUP_DIR="${BACKUP_DIR:-/var/backups/ioc-service}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
BACKUP_REMOTE_DEST="${BACKUP_REMOTE_DEST:-}"
BACKUP_ENCRYPT="${BACKUP_ENCRYPT:-false}"
BACKUP_GPG_RECIPIENT="${BACKUP_GPG_RECIPIENT:-}"
DATABASE_URL="${DATABASE_URL:-}"
REDIS_URL="${REDIS_URL:-}"

# parse CLI overrides
while [[ $# -gt 0 ]]; do
  case "$1" in
    --retention-days) BACKUP_RETENTION_DAYS="$2"; shift 2 ;;
    --backup-dir)     BACKUP_DIR="$2"; shift 2 ;;
    --remote-dest)    BACKUP_REMOTE_DEST="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

TS="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${BACKUP_DIR}"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# ── PostgreSQL ───────────────────────────────────────────────────────────────
if [[ -n "${DATABASE_URL}" ]]; then
  log "Starting PostgreSQL backup..."
  PG_FILE="${BACKUP_DIR}/ioc-pg-${TS}.sql.gz"
  eval "$(
    python3 - <<'PY'
from urllib.parse import parse_qs, unquote, urlparse
import os

url = os.environ["DATABASE_URL"].replace("postgresql+psycopg2://", "postgresql://", 1)
parsed = urlparse(url)
query = parse_qs(parsed.query)
sslmode = query.get("sslmode", [""])[0]

def emit(name: str, value: str) -> None:
    safe = value.replace("\\", "\\\\").replace('"', '\\"')
    print(f'{name}="{safe}"')

emit("PGHOST", parsed.hostname or "localhost")
emit("PGPORT", str(parsed.port or 5432))
emit("PGUSER", unquote(parsed.username or ""))
emit("PGPASSWORD_VALUE", unquote(parsed.password or ""))
emit("PGDATABASE", (parsed.path or "/").lstrip("/"))
emit("PGSSLMODE_VALUE", sslmode)
PY
  )"
  PGPASSFILE="$(mktemp)"
  cleanup_pgpass() {
    rm -f "${PGPASSFILE}"
  }
  trap cleanup_pgpass EXIT
  umask 077
  printf '%s:%s:%s:%s:%s\n' "${PGHOST}" "${PGPORT}" "${PGDATABASE}" "${PGUSER}" "${PGPASSWORD_VALUE}" > "${PGPASSFILE}"
  export PGPASSFILE
  if [[ -n "${PGSSLMODE_VALUE}" ]]; then
    export PGSSLMODE="${PGSSLMODE_VALUE}"
  fi
  pg_dump -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" "${PGDATABASE}" | gzip -9 > "${PG_FILE}"
  PG_SIZE=$(du -sh "${PG_FILE}" | cut -f1)
  log "PostgreSQL backup written: ${PG_FILE} (${PG_SIZE})"

  if [[ "${BACKUP_ENCRYPT}" == "true" ]] && [[ -n "${BACKUP_GPG_RECIPIENT}" ]]; then
    gpg --batch --yes --recipient "${BACKUP_GPG_RECIPIENT}" --encrypt "${PG_FILE}"
    rm -f "${PG_FILE}"
    PG_FILE="${PG_FILE}.gpg"
    log "PostgreSQL backup encrypted: ${PG_FILE}"
  fi
else
  log "DATABASE_URL not set — skipping PostgreSQL backup"
fi

# ── Redis ────────────────────────────────────────────────────────────────────
if [[ -n "${REDIS_URL}" ]]; then
  log "Requesting Redis BGSAVE..."
  # Extract host:port and password from Redis URL
  # Format: redis://:password@host:port/db
  REDIS_HOST=$(echo "${REDIS_URL}" | sed -E 's|redis://[^@]*@([^:/]+).*|\1|' || echo "localhost")
  REDIS_PORT=$(echo "${REDIS_URL}" | sed -E 's|.*:([0-9]+)/.*|\1|' || echo "6379")
  REDIS_PASS=$(echo "${REDIS_URL}" | sed -E 's|redis://:([^@]*)@.*|\1|' || echo "")

  REDIS_CLI_ARGS=(-h "${REDIS_HOST}" -p "${REDIS_PORT}")
  # Use REDISCLI_AUTH env var instead of -a flag to keep the password out of
  # the process argument list (visible via ps aux).
  if [[ -n "${REDIS_PASS}" ]]; then
    REDISCLI_AUTH="${REDIS_PASS}" redis-cli "${REDIS_CLI_ARGS[@]}" BGSAVE >/dev/null 2>&1 || log "redis-cli not available — skipping Redis backup"
  else
    redis-cli "${REDIS_CLI_ARGS[@]}" BGSAVE >/dev/null 2>&1 || log "redis-cli not available — skipping Redis backup"
  fi
  log "Redis BGSAVE triggered (RDB will be saved by Redis to its configured dir)"
else
  log "REDIS_URL not set — skipping Redis backup"
fi

# ── Retention enforcement ─────────────────────────────────────────────────────
log "Enforcing retention: removing backups older than ${BACKUP_RETENTION_DAYS} days..."
DELETED=$(find "${BACKUP_DIR}" -maxdepth 1 -name "ioc-pg-*.sql.gz*" -mtime "+${BACKUP_RETENTION_DAYS}" -print -delete | wc -l)
log "Deleted ${DELETED} expired backup file(s)"

# ── Remote upload (optional) ──────────────────────────────────────────────────
if [[ -n "${BACKUP_REMOTE_DEST}" ]]; then
  if command -v rclone >/dev/null 2>&1; then
    log "Uploading to remote: ${BACKUP_REMOTE_DEST}"
    rclone copy "${BACKUP_DIR}" "${BACKUP_REMOTE_DEST}" --include "ioc-pg-${TS}*"
    log "Remote upload complete"
  else
    log "WARNING: BACKUP_REMOTE_DEST is set but rclone is not installed — skipping remote upload"
  fi
fi

log "Backup finished."
