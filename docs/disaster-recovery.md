# Disaster Recovery Plan

Status: introduced for `compliance-1.0`.
Framework: ISO 27001 A.12.3 (Backup), A.17 (Information Security Continuity), NIST CSF RC.RP.

---

## 1. Recovery Objectives

| Tier | Component | RPO (max data loss) | RTO (restore service) |
|---|---|---|---|
| Critical | PostgreSQL, Core API | 24 hours | 4 hours |
| Important | Redis cache, Admin panel | 24 hours | 4 hours |
| Standard | Worker, Logs | 24 hours | 8 hours |

---

## 2. Backup Strategy

| Asset | Method | Frequency | Retention | Encryption |
|---|---|---|---|---|
| PostgreSQL | `pg_dump` → gzip via `PGPASSFILE` | Daily (cron) | 30 days local | GPG optional (see `scripts/backup.sh`) |
| PostgreSQL | Weekly full | Weekly | 90 days | GPG optional |
| Redis | `BGSAVE` (RDB) | Daily | 7 days (host volume) | Host-volume encryption |
| Configuration | git history | On every commit | Indefinite | N/A |
| Export files | N/A — ephemeral | N/A | 30 days max | Host-volume encryption |

**Backup script**: `scripts/backup.sh`

Note:
- `1.8.1` hardens PostgreSQL backup execution so credentials are passed through a temporary `PGPASSFILE` rather than embedded in `pg_dump` arguments.

```bash
# Daily PostgreSQL backup
DATABASE_URL="$DATABASE_URL" \
BACKUP_DIR="/var/backups/ioc-service" \
BACKUP_RETENTION_DAYS=30 \
scripts/backup.sh

# Optional: encrypt and upload to S3
DATABASE_URL="$DATABASE_URL" \
BACKUP_DIR="/var/backups/ioc-service" \
BACKUP_ENCRYPT=true \
BACKUP_GPG_RECIPIENT="ops-key@example.com" \
BACKUP_REMOTE_DEST="s3:my-bucket/ioc-backups" \
scripts/backup.sh
```

Add to cron (`crontab -e`):
```
0 2 * * * /home/kili/Repo/ioc-service/scripts/backup.sh >> /var/log/ioc-backup.log 2>&1
```

---

## 3. Disaster Scenarios and Recovery Procedures

### 3.1 Application container crash / restart loop

1. Check logs: `docker compose logs app --tail=100`
2. Check health: `curl http://localhost:7005/health`
3. Restart: `docker compose up -d --force-recreate app`
4. If startup fails: check `DATABASE_URL`, `SECRET_KEY`, `REDIS_URL` environment variables are set.

### 3.2 PostgreSQL volume loss

1. Provision a new PostgreSQL instance.
2. Restore from the most recent backup:
   ```bash
   gunzip -c ioc-pg-<TS>.sql.gz | psql "${DATABASE_URL}"
   ```
3. Run Alembic migrations to bring schema to HEAD:
   ```bash
   docker compose run --rm migrate
   ```
4. Restart the app: `docker compose up -d --force-recreate app worker`
5. Verify audit chain integrity: `GET /admin/audit/verify`

### 3.3 Redis cache loss

Redis stores only ephemeral rate-limit counters and session data — no persistent IOC data.

1. Restart Redis: `docker compose up -d --force-recreate redis`
2. Active admin sessions will be invalidated; users must log in again.
3. Rate-limit counters reset to zero — this is safe.

### 3.4 Host server failure (full rebuild)

1. Provision a new host.
2. Install Docker and Docker Compose.
3. Clone the repository: `git clone https://github.com/mkilijanek/ioc-service.git`
4. Restore `.env` from secrets vault (or re-provision with `scripts/generate-secrets.sh`).
5. Pull images: `docker pull ghcr.io/mkilijanek/ioc-service:latest`
6. Start infrastructure: `docker compose -f docker-compose-release.yml up -d postgres redis`
7. Restore PostgreSQL (see 3.2 above).
8. Start services: `scripts/deploy_ghcr_variant.sh ioc-service latest`

Estimated RTO: 2–4 hours depending on backup restore time.

### 3.5 Compromised deployment (security incident)

See `docs/incident-response.md` for the full procedure. In summary:
1. Isolate the host from external traffic (firewall rule or load-balancer drain).
2. Preserve forensic evidence (logs, DB snapshot, audit trail export).
3. Provision a clean host (see 3.4 above) using a known-good image tag.
4. Rotate all secrets: `SECRET_KEY`, `ADMIN_API_TOKEN`, `DATABASE_URL` password, feed credentials.
5. Restore from a pre-incident backup.

---

## 4. Backup Verification

Backups must be verified to be recoverable. Perform a test restore at least quarterly:

```bash
# Spin up a temporary PostgreSQL instance
docker run -d --name pg-restore-test \
  -e POSTGRES_PASSWORD=test -e POSTGRES_DB=restore_test \
  -p 5433:5432 postgres:16

# Restore
gunzip -c /var/backups/ioc-service/ioc-pg-<LATEST>.sql.gz | \
  psql "postgresql://postgres:test@localhost:5433/restore_test"

# Spot-check row counts
psql "postgresql://postgres:test@localhost:5433/restore_test" \
  -c "SELECT COUNT(*) FROM indicators; SELECT COUNT(*) FROM audit_log;"

# Tear down
docker rm -f pg-restore-test
```

Record the verification result in `change.log`.

---

## 5. Risk Register Reference

| Risk ID | Description | Treatment |
|---|---|---|
| R006 | Unencrypted backup leak | `scripts/backup.sh` with GPG encryption option; host-volume encryption required |

See `docs/risk-register.md` for full risk register.
