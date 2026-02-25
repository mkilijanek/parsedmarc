# Threat Intelligence Feed Aggregator

Production-ready threat feed aggregation and export service:
- Ingests **CrowdSec** blocklists and **MISP** (IDS-flagged only, warninglist enforced)
- Stores IOCs in **PostgreSQL 16** (JSONB + pg_trgm) with audit trail and feed stats
- Caches exports/views in **Redis 7** (AOF, 512MB, LRU)
- Serves HTTPS via **Nginx** (TLS 1.2+, HTTP/2, security headers, rate limiting)
- Web UI: `/indicators` (Kibana-like search) with WCAG/ARIA attributes
- Source shortcuts: `/sources/<src>` (e.g. `/sources/bazaar`, `/sources/mwdb`)
- 17 export formats via `/indicators/<format>`

## Quickstart (Docker Compose)

1) Copy env template and generate secrets:
```bash
cp .env.example .env
./scripts/generate-secrets.sh >> .env
```

2) Create dev TLS cert (self-signed):
```bash
./scripts/setup-ssl.sh
```

3) Configure integrations (optional):
- CrowdSec: set `CROWDSEC_API_KEY` and `CROWDSEC_LISTS` (comma-separated list IDs)
- MISP: set `MISP_URL`, `MISP_API_KEY`, and `MISP_VERIFY_SSL`

4) Start:
```bash
docker compose up -d --build
```

5) Validate:
```bash
curl -k https://localhost:7003/health
curl -k https://localhost:7003/indicators
curl -k https://localhost:7003/indicators/arcsight | head
```

## Endpoints

- `GET /health` – health + integration checks
- `GET /` – status overview
- `GET /indicators` – unified view (HTML)
- `GET /indicators/<fmt>` – export (TXT/CSV/JSON/XML + vendor formats)
- `GET /metrics` – Prometheus metrics (deploy behind internal network/VPN if needed)

### Export formats (17)

Basic:
- `txt`, `csv`, `json`, `xml`

Firewall / blocklists:
- `fortigate` (external block list)
- `fortigate_ips`
- `checkpoint`
- `paloalto`

SIEM / platforms:
- `sentinel` (STIX wrapper JSON)
- `defender` (CSV)
- `f5` (iRule data group)
- `imperva` (JSON)
- `arcsight` (CEF)
- `elasticsearch` (bulk NDJSON)
- `cribl` (NDJSON)
- `splunk` (HEC JSON)
- `fidelis` (STIX 2.1 bundle)

## Search syntax

Kibana-like:
- Operators: `AND`, `OR`, `NOT`
- Predicates:
  - `value:192.168.*`
  - `confidence:>70` (also `<`, `>=`, `<=`, `:`)
  - `type:ip`, `tlp:AMBER`, `source:misp`
  - `tags:apt`

## Notes / Security

- No hardcoded secrets; all secrets via environment variables.
- DB queries compiled via SQLAlchemy expressions (parameterized).
- Rate limiting: Nginx + Flask-Limiter (Redis backend).
- Defense-in-depth validation of query strings (`max 500` chars, rejects obvious injection markers).
- CrowdSec indicators are **always** enforced as `TLP:AMBER`.

## Development

Run tests locally:
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Contribution and quality gate:
- See `CONTRIBUTING.md` for merge policy and smoke-test checklist.
- CI (`.github/workflows/ci.yml`) enforces tests on Python 3.11/3.12 for pushes and PRs.


## Configuration

- `MALWAREBAZAAR_SINCE_DATE` (optional): ISO date `YYYY-MM-DD`. When set, MALWAREBAZAAR_SINCE_DATE: ISO date `YYYY-MM-DD` (UTC). MalwareBazaar ingestion pulls entries from this date (inclusive) onward.
- `MALWAREBAZAAR_TAGS` (optional): comma-separated tags for worker auto-ingestion.
- `MALWAREBAZAAR_LIMIT` (optional): max rows per run (default: `1000`).
- `MWDB_TAGS` (optional): comma-separated tags for worker auto-ingestion.
- `MWDB_LIMIT` (optional): max rows per run (default: `1000`).
- abuse.ch extended integrations (optional): `THREATFOX_*`, `URLHAUS_*`, `YARAIFY_*`, `FEODOTRACKER_*`, `HUNTING_FPLIST_*`, with shared `ABUSECH_AUTH_KEY`.


## CLI (IOC ingestion)

Run locally:

```bash
export DATABASE_URL='postgresql://iocuser:pass@localhost:5432/iocdb'
python -m app.cli fetch --data-source bazaar --tags TrickBot --since 2025-01-01 --until 2025-01-31
python -m app.cli fetch --data-source mwdb --tags EvilTag --since 2025-01-01 --config-file ./config/cli.env
```

### Config file
`--config-file` supports JSON (`.json`) or `.env` style `KEY=VALUE`.
Supported keys:
- `DATABASE_URL`
- `TAGS` (comma-separated)
- `SINCE` (YYYY-MM-DD or ISO datetime)
- `UNTIL` (YYYY-MM-DD or ISO datetime)
- `MALWAREBAZAAR_API_URL`
- `MWDB_URL`
- `MWDB_AUTH_KEY`
- `ABUSECH_AUTH_KEY` (preferred shared key for abuse.ch services)
- `MALWAREBAZAAR_AUTH_KEY` (optional override)

Precedence:
- CLI flags override values from `--config-file`.
- For `DATABASE_URL`, current precedence is: environment variable first, then `--config-file`.
