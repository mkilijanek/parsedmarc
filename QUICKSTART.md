# IOC Service — Quick Start

Updated: `1.8.0` + `compliance-1.0` (2026-04-30)

## Prerequisites

- Docker 24.0+
- Python 3.11+
- 4 GB RAM minimum
- Git

## Quick Setup (Docker)

```bash
# 1. Clone and enter
git clone <repo-url> ioc-service
cd ioc-service

# 2. Create environment file
cp .env.example .env

# 3. Generate and append secrets
bash scripts/generate-secrets.sh >> .env

# 4. Configure environment
# Edit .env with your editor — at minimum review SECRET_KEY, ADMIN_API_TOKEN, DATABASE_URL, REDIS_URL

# 5. Start services
docker compose up -d postgres redis
docker compose up -d app worker

# 6. Verify
curl http://localhost:7005/healthz
curl http://localhost:7005/health | jq
```

## Key Endpoints

### Health & Monitoring
- `GET /healthz` — Liveness (no external calls)
- `GET /readyz` — Readiness (DB + Redis)
- `GET /health` — Full health including DBCircuitBreaker state
- `GET /metrics` — Prometheus metrics
- `GET /api/events` — SSE stream (heartbeat, indicator count, sync status, feed health)

### Versioned API (`/api/v1/`)
- `GET /api/v1/indicators` — Query IOCs
- `GET /api/v1/feeds` — Feed inventory
- `GET /api/v1/feeds/metrics` — Feed telemetry
- `GET /api/v1/runs/current` — Scheduler/job state
- `GET /api/v1/logs` — Structured logs
- `POST /api/v1/sync` — Trigger sync

### Admin (`/admin/*` — requires login)
- Web UI at `/admin`
- DLQ inventory and requeue at `/admin/api/dead-letter-jobs`
- DBCircuitBreaker state at `/admin/api/db-circuit`

### Audit verification (`/admin/audit/*` — current known access-control gap)
- Integrity verification at `/admin/audit/verify`
- Treat as internal-only until the access-control backlog item is closed

### Export Formats
```bash
curl http://localhost:7005/indicators/txt          # Plain text
curl http://localhost:7005/indicators/csv          # CSV
curl http://localhost:7005/indicators/json         # JSON
curl http://localhost:7005/indicators/fortigate    # FortiGate
curl http://localhost:7005/indicators/splunk       # Splunk
curl http://localhost:7005/indicators/elasticsearch # Elasticsearch NDJSON
```

### OpenAPI
- `/api/v1/openapi.yaml` — OpenAPI spec for the versioned API
- `/api/swagger` — Swagger UI

## Local Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Set required env vars
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export DATABASE_URL=postgresql+psycopg2://user:pass@localhost:5432/threatfeed
export REDIS_URL=redis://localhost:6379/0
export ADMIN_API_TOKEN=dev-token

# Run tests
pytest tests/ -v

# Run app
python -m flask --app app.factory run --debug --port 8080
```

## Production Checklist

- [ ] `SECRET_KEY` explicitly provisioned (>= 32 characters)
- [ ] `ADMIN_API_TOKEN` set and not default
- [ ] SSL certificate from trusted CA (or use TLS variant)
- [ ] `ALLOWED_HOSTS` configured
- [ ] `TRUSTED_PROXY_COUNT` set if behind reverse proxy
- [ ] `.env` secured (`chmod 600`)
- [ ] Backup procedure tested (`bash scripts/backup.sh`)
- [ ] Grafana dashboard imported (`grafana/dashboard.json`)
- [ ] Monitoring and alerting configured
- [ ] Audit integrity verification scheduled

## Troubleshooting

### Containers won't start
```bash
docker compose logs --tail=100
docker compose ps
sudo netstat -tulpn | grep -E '7005|5432|6379'
```

### Database connection failed
```bash
docker compose exec postgres pg_isready -U threatfeed
grep DATABASE_URL .env
```

### DBCircuitBreaker is open
```bash
curl http://localhost:7005/health | jq '.db_circuit_state'
# Check PostgreSQL, wait for cooldown, circuit auto-recovers
```

### Audit chain verification
```bash
# Current implementation exposes this route without admin auth.
# Treat it as internal-only and protect it at the edge.
curl http://localhost:7005/admin/audit/verify | jq .
```

## Documentation Index

| Document | Purpose |
|---|---|
| [README.md](README.md) | Project overview and endpoint catalog |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production deployment guide |
| [SECURITY.md](SECURITY.md) | Security policy and supported versions |
| [docs/architecture.md](docs/architecture.md) | System design and data flow |
| [docs/configuration.md](docs/configuration.md) | Environment variables reference |
| [docs/api.md](docs/api.md) | Full API documentation |
| [docs/runbook.md](docs/runbook.md) | Operational procedures |
| [docs/compliance.md](docs/compliance.md) | ISO 27001 / NIST CSF controls matrix |
| [docs/incident-response.md](docs/incident-response.md) | Incident playbooks |
| [docs/disaster-recovery.md](docs/disaster-recovery.md) | DR plan and restore procedures |
| [ROADMAP.md](ROADMAP.md) | Feature roadmap |
| [MILESTONES.md](MILESTONES.md) | Milestone tracking |
