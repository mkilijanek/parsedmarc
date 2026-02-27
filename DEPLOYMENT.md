# Deployment Guide

Updated for release line `1.1.x` (2026-02-26).

## Quick Start

```bash
# 1. Generate secrets
./scripts/generate-secrets.sh

# 2. Setup SSL
./scripts/setup-ssl.sh

# 3. Configure .env
vim .env  # Add MISP and CrowdSec credentials

# 4. Start services
docker compose up -d postgres redis
docker compose up -d app worker

# 5. Verify
curl -k https://localhost:7003/health
```

## Production Deployment

### Prerequisites
- Docker 24.0+
- 4GB RAM minimum
- Valid SSL certificate
- External IP/domain name

### Steps
1. Clone repository
2. Configure environment variables
3. Setup SSL with Let's Encrypt
4. Start services
5. Configure firewall (allow 7003/tcp)
6. Setup monitoring

### Monitoring
- Health: https://your-domain:7003/health
- Logs: docker compose logs -f
- Stats: https://your-domain:7003/api/stats

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
