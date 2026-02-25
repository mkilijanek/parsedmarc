# CLI Documentation

## Overview

The CLI tool (`app.cli`) provides manual ingestion of IOCs from MalwareBazaar and MWDB repositories. It offers fine-grained control over what data gets imported.

---

## Installation

```bash
# In project directory
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Basic Usage

```bash
python -m app.cli fetch \
  --data-source {bazaar|mwdb} \
  --tags TAG1,TAG2 \
  --since YYYY-MM-DD \
  --until YYYY-MM-DD \
  [--config-file path/to/config] \
  [--limit 1000] \
  [--dry-run]
```

---

## Commands

### fetch

Fetch indicators from a data source and insert into database.

**Arguments:**

| Argument | Required | Description | Example |
|----------|----------|-------------|---------|
| `--data-source` | Yes | Data source | `bazaar`, `mwdb` |
| `--tags` | Yes | Tags to query (repeatable) | `--tags TrickBot --tags Emotet` |
| `--since` | No | Start date/time | `2025-01-01` or ISO datetime |
| `--until` | No | End date/time | `2025-01-31` or ISO datetime |
| `--limit` | No | Max items per tag | Default: 1000 |
| `--dry-run` | No | Don't write to DB, print stats | Flag |
| `--config-file` | No | Config file path | `./config/cli.env` |

---

## Examples

### MalwareBazaar by Tags

```bash
# Fetch TrickBot and Emotet samples from January 2025
python -m app.cli fetch \
  --data-source bazaar \
  --tags TrickBot,Emotet \
  --since 2025-01-01 \
  --until 2025-01-31
```

### MWDB with Config File

```bash
# Use config file for auth and parameters
python -m app.cli fetch \
  --data-source mwdb \
  --tags malware,apt \
  --config-file ./config/cli.env
```

### Dry Run

```bash
# Check what would be fetched without inserting
python -m app.cli fetch \
  --data-source bazaar \
  --tags Qakbot \
  --since 2025-01-01 \
  --dry-run
```

Output:
```json
{
  "data_source": "bazaar",
  "tags": ["Qakbot"],
  "count": 523
}
```

---

## Configuration File

### Format

Supports JSON (`.json`) or KEY=VALUE (`.env`) format:

```bash
# config/cli.env
DATABASE_URL=postgresql://user:pass@localhost:5432/iocdb
TAGS=TrickBot,Emotet
SINCE=2025-01-01
UNTIL=2025-01-31
MALWAREBAZAAR_API_URL=https://mb-api.abuse.ch/api/v1/
MALWAREBAZAAR_AUTH_KEY=your-key
MWDB_URL=https://mwdb.cert.pl
MWDB_AUTH_KEY=your-key
```

### Supported Keys

- `DATABASE_URL` - PostgreSQL connection string
- `TAGS` - Comma-separated tags
- `SINCE` - Start date (YYYY-MM-DD or ISO)
- `UNTIL` - End date (YYYY-MM-DD or ISO)
- `MALWAREBAZAAR_API_URL` - MalwareBazaar API endpoint
- `MALWAREBAZAAR_AUTH_KEY` - MalwareBazaar API key (optional)
- `MWDB_URL` - MWDB instance URL
- `MWDB_AUTH_KEY` - MWDB API key

### Precedence

1. **CLI flags** - Highest priority
2. **Config file** - Via `--config-file`
3. **Environment variables** - Lowest priority (DATABASE_URL only)

---

## Output

### Success

```json
{
  "data_source": "bazaar",
  "tags": ["TrickBot", "Emotet"],
  "ingested": 150,
  "updated": 23,
  "total_rows": 173
}
```

### Error

```
SystemExit: No tags provided. Use --tags or TAGS in --config-file.
```

---

## Database Requirements

### Schema

The CLI requires the `ti` schema with `indicators` table:

```sql
-- Must exist before running CLI
CREATE SCHEMA ti;
CREATE TABLE ti.indicators (...);
```

See [database.md](database.md) for full schema.

### Connection

```bash
# Via environment variable
export DATABASE_URL='postgresql://user:pass@host:5432/db'

# Via config file
DATABASE_URL=postgresql://user:pass@host:5432/db

# Both work, environment has priority
```

---

## Integration

### Scheduled Ingestion

```bash
#!/bin/bash
# /etc/cron.d/ioc-ingest
# Run daily at 2 AM

0 2 * * * user cd /app && \
  python -m app.cli fetch \
    --data-source bazaar \
    --tags TrickBot,Emotet \
    --since $(date -d '7 days ago' +\%Y-\%m-\%d) \
    --config-file /app/config/cli.env
```

### CI/CD Pipeline

```yaml
# .gitlab-ci.yml
ingest_iocs:
  stage: deploy
  script:
    - python -m app.cli fetch
        --data-source mwdb
        --tags ${IOC_TAGS}
        --since ${START_DATE}
        --config-file ./config/prod.env
  only:
    - schedules
```

---

## Error Handling

### Connection Errors

```python
# API unreachable
requests.exceptions.ConnectionError

# Database unreachable
psycopg2.OperationalError
```

### Authentication Errors

```python
# Invalid API key
requests.exceptions.HTTPError: 401 Unauthorized

# Database auth failed
psycopg2.OperationalError: password authentication failed
```

### Data Errors

```python
# Invalid date format
ValueError: time data '2025/01/01' does not match format

# Empty result
# Returns success with count: 0
```

---

## Limitations

- **Worker auto-update exists** - CLI is still useful for ad-hoc/manual ingestion and one-off backfills
- **Tag-based only** - Cannot query by hash or other fields
- **Rate limits** - Subject to API provider limits
- **No streaming** - Loads all results in memory
- **Single-threaded** - One source at a time

---

## See Also

- [Data Sources](data-sources.md) - Source details and API formats
- [Configuration](configuration.md) - Environment variables
- [Database](database.md) - Schema and tables
