# Deployment Guide

Updated for release line `1.6.1` (2026-04-28).

## Quick Start

```bash
# 1. Generate secrets
./scripts/generate-secrets.sh

# 2. Configure .env
vim .env  # Add MISP and CrowdSec credentials

# 3. Start services
docker compose up -d postgres redis
docker compose up -d app worker

# 4. Verify
curl http://localhost:7005/health
```

## Production Deployment

### Prerequisites
- Docker 24.0+
- 4GB RAM minimum
- Valid SSL certificate for the TLS variant
- External IP/domain name when exposing the TLS variant

### Deployment Variants

#### `ioc-service` (no edge TLS)
- App/workers only.
- Intended for F5/VS deployments where TLS is terminated upstream or traffic is intentionally plain HTTP on a trusted network.
- Required env:
  - `EDGE_HTTPS_ENABLED=false`
  - `HSTS_ENABLED=false`
  - `SESSION_COOKIE_SECURE_ENABLED=false`

#### `ioc-service-tls` (bundled edge TLS)
- App/workers plus nginx edge image.
- Intended when this stack terminates HTTPS itself.
- Requires mounted certs under `./ssl`.

### Steps
1. Clone repository
2. Configure environment variables
3. Choose deployment variant
4. Setup SSL with Let's Encrypt when using the TLS variant
5. Start services
6. Configure firewall (`7005/tcp` for app-only, `7003/tcp` for TLS edge)
7. Setup monitoring

### GitHub Actions publish and deploy

1. Publish both images from the selected commit:
   - run workflow `Release Package`
   - use `workflow_dispatch`
   - resulting manual tags are published as `sha-<commit>`

2. Deploy one variant on a self-hosted runner host:
   - run workflow `Deploy Images`
   - `variant=ioc-service` for plain HTTP/app-only
   - `variant=ioc-service-tls` for nginx edge TLS
   - `image_tag=sha-<commit>` or a release tag

The deploy workflow executes `scripts/deploy_ghcr_variant.sh`, which pulls GHCR images and rolls the compose stack forward.
On self-hosted runners, the workflow expects runtime secrets in `/home/kili/Repo/ioc-service/.env` unless `DEPLOY_ENV_FILE` is explicitly overridden in the job environment.

### Monitoring
- App-only health: http://your-host:7005/healthz
- App-only readiness: http://your-host:7005/readyz
- TLS edge health: https://your-domain:7003/healthz
- TLS edge readiness: https://your-domain:7003/readyz
- Logs: docker compose logs -f
- Stats: https://your-domain:7003/api/stats
- Metrics: https://your-domain:7003/metrics (deploy behind VPN/internal network)

**Key Prometheus metrics for alerting:**

| Metric                | Alert condition                          |
|-----------------------|------------------------------------------|
| `sync_jobs_queued`    | > 10 for > 5 min → worker may be stuck  |
| `sync_jobs_running`   | > 5 simultaneously → concurrency issue  |
| `export_jobs_pending` | > 20 for > 10 min → export backlog      |
| `active_indicators`   | Sudden drop → feed sync failure          |

See `docs/api.md` for the full list of exposed metrics.

### Backup
```bash
# Backup database
docker compose exec postgres pg_dump -U threatfeed threatfeed > backup.sql

# Backup .env
cp .env .env.backup
```

### Updates
```bash
git pull
docker compose build
docker compose up -d
```

`app` and `worker` execute database upgrade automatically on start (`AUTO_MIGRATE_ON_START=true` by default), so restarting with a newer image applies schema updates without manual migration commands.


---

## Troubleshooting

### 502 Bad Gateway

If Nginx returns 502, see the step-by-step guide:
[docs/troubleshooting/502-bad-gateway.md](docs/troubleshooting/502-bad-gateway.md)

Common causes: app not listening, wrong upstream port, SELinux policy, F5 monitor misconfiguration.
