# Data Sources

## Overview

The Threat Feed Aggregator integrates multiple threat intelligence sources to provide comprehensive IOC coverage. All sources are normalized to a unified schema and stored in PostgreSQL.

---

## Supported Sources

### 1. MISP (Malware Information Sharing Platform)

**Type:** Threat Intelligence Platform  
**Integration:** PyMISP library  
**Update Frequency:** Configurable (default: 10 minutes)

**Configuration:**
```bash
MISP_URL=https://misp.example.com
MISP_API_KEY=your-api-key
MISP_VERIFY_SSL=true  # Always true in production
MISP_DAYS=7  # Fetch events from last N days
```

**Fetched Data:**
- Events with `to_ids=True` flag only
- `enforce_warninglist=True` for quality filtering
- Includes event tags and attribute tags
- Supports all MISP attribute types

**Supported IOC Types:**
- IP addresses (ip-src, ip-dst, ip-src|port, ip-dst|port)
- Domains (domain, hostname)
- URLs
- Hashes (MD5, SHA1, SHA256, SHA512, SSDEEP)
- Emails (email, email-src, email-dst, email-subject)

**TLP Extraction:**
- Extracts TLP from attribute tags (priority)
- Falls back to event tags
- Supports TLP 2.0 (clear → WHITE)
- Default: GREEN if not specified

**Confidence Calculation:**
```
Base confidence from distribution:
- 0 (Your organization only): 90
- 1 (This community only): 80
- 2 (Connected communities): 70
- 3 (All communities): 60
- 4 (Sharing group): 50

Bonus for high-confidence tags:
+10 for: apt, malware, ransomware, banker, apt28, apt29
```

**Update Process:**
1. Fetch attributes via PyMISP search
2. Filter by timestamp (last N days)
3. Normalize attribute types to internal schema
4. Calculate confidence and extract TLP
5. Upsert to database (per event)
6. Mark missing indicators as inactive

---

### 2. CrowdSec

**Type:** Community-driven IP blocklists  
**Integration:** REST API  
**Update Frequency:** Configurable (default: 10 minutes)

**Configuration:**
```bash
CROWDSEC_API_KEY=your-api-key
CROWDSEC_LISTS=list1,list2,list3
```

**Fetched Data:**
- IP addresses and CIDR ranges
- Plain text format (one per line)
- Comments starting with `#` are ignored

**IOC Types:**
- IP addresses only (IPv4 and IPv6)

**Metadata:**
- **TLP:** Always AMBER (hardcoded requirement)
- **Confidence:** 75 (fixed)
- **Source:** "crowdsec"
- **Source ID:** List ID

**Update Process:**
1. Fetch each list via HTTP GET
2. Parse plain text (skip comments)
3. Preserve CIDR notation if present
4. Upsert with list_id as source_ref
5. Mark indicators not in current list as inactive

**API Endpoint:**
```
GET https://api.crowdsec.net/v2/blocklists/{list_id}
Headers:
  X-Api-Key: <your-key>
```

---

### 3. MalwareBazaar (abuse.ch)

**Type:** Malware sample repository  
**Integration:** REST API (CLI tool)  
**Update Method:** Manual via CLI

**Configuration:**
```bash
MALWAREBAZAAR_API_URL=https://mb-api.abuse.ch/api/v1/
MALWAREBAZAAR_AUTH_KEY=your-key  # Optional
MALWAREBAZAAR_SINCE_DATE=2025-01-01  # Optional
```

**CLI Usage:**
```bash
python -m app.cli fetch \
  --data-source bazaar \
  --tags TrickBot,Emotet \
  --since 2025-01-01 \
  --until 2025-01-31
```

**Fetched Data:**
- File hashes (SHA256, MD5, SHA1)
- Associated tags
- Sample metadata (file type, signature, etc.)

**IOC Types:**
- Hashes (MD5, SHA1, SHA256)

**Metadata:**
- Tags from MalwareBazaar
- File type and signature
- First/last seen timestamps
- Reporter information

---

### 4. MWDB (CERT.pl Malware Database)

**Type:** Malware repository  
**Integration:** REST API (CLI tool)  
**Update Method:** Manual via CLI

**Configuration:**
```bash
MWDB_URL=https://mwdb.cert.pl
MWDB_AUTH_KEY=your-api-key
```

**CLI Usage:**
```bash
python -m app.cli fetch \
  --data-source mwdb \
  --tags malware,apt \
  --since 2025-01-01 \
  --config-file ./config/cli.env
```

**Fetched Data:**
- File hashes
- Config extracts
- Associated tags
- Sample metadata

**IOC Types:**
- Hashes (SHA256, MD5, SHA1)
- Extracted IPs and domains
- URLs from configs

---

## Source Comparison

| Source | Auto Update | IOC Types | TLP Support | Confidence | API Auth |
|--------|-------------|-----------|-------------|------------|----------|
| MISP | ✅ Yes | All | ✅ Yes | Dynamic | API Key |
| CrowdSec | ✅ Yes | IP only | ❌ AMBER only | Fixed (75) | API Key |
| MalwareBazaar | ❌ CLI only | Hashes | ❌ No | Default (50) | Optional |
| MWDB | ❌ CLI only | Hashes, IP, Domain, URL | ❌ No | Default (50) | API Key |

---

## Data Normalization

### Unified Schema

All sources are normalized to:

```python
{
  "ioc_value": "192.168.1.1",
  "ioc_type": "ip",
  "source": "misp",
  "source_ref": "event_id_123",
  "confidence": 80,
  "tlp": "AMBER",
  "is_active": True,
  "tags": ["apt", "malware"],
  "metadata": {
    "misp": {
      "attribute_id": "456",
      "category": "Network activity",
      "distribution": 1
    }
  },
  "first_seen": "2025-01-15T10:00:00Z",
  "last_seen": "2025-01-15T12:30:00Z"
}
```

### Type Mapping

| Source Type | Normalized Type |
|-------------|-----------------|
| ip-src, ip-dst, ip-src\|port | ip |
| domain, hostname | domain |
| url | url |
| md5, sha1, sha256, sha512, ssdeep | hash |
| email, email-src, email-dst | email |

---

## Update Strategy

### Automatic Updates (MISP, CrowdSec)

**Schedule:**
```python
# Default: every 10 minutes
UPDATE_INTERVAL=600
```

**Process:**
1. Background worker wakes up
2. Fetches from each configured source
3. Normalizes and upserts data
4. Marks missing indicators as inactive
5. Updates feed statistics
6. Logs metrics

**Error Handling:**
- Exponential backoff for transient errors
- Failed source doesn't block others
- Errors logged to `feed_stats.last_fetch_error`
- Health endpoint reflects source status

### Manual Updates (MalwareBazaar, MWDB)

**Workflow:**
1. Run CLI tool with desired parameters
2. Fetches data from API
3. Normalizes and upserts to database
4. Returns ingestion statistics

**Benefits:**
- Control over what gets ingested
- Filter by tags before import
- Time range selection
- Dry-run mode for testing

---

## Feed Statistics

Tracked per source in `feed_stats` table:

```sql
SELECT * FROM ti.feed_stats;
```

**Columns:**
- `source` - Source name (misp, crowdsec, etc.)
- `source_ref` - Optional source-specific ID
- `total_indicators` - Total ever seen
- `active_indicators` - Currently active
- `inactive_indicators` - Deactivated
- `last_update` - Last successful update
- `last_fetch_status` - success/error
- `last_fetch_error` - Error message if failed
- `metadata` - Additional stats (e.g., fetched count)

**View Stats:**
```bash
curl https://localhost:7003/
# Shows feed statistics table
```

---

## Adding New Sources

### Integration Checklist

1. **Create service module:** `app/services/new_source.py`
2. **Implement fetch function:**
   ```python
   def fetch_new_source() -> List[Dict]:
       # Fetch from API
       # Normalize to internal schema
       # Return list of indicators
       pass
   ```
3. **Add to worker:** Register in `app/worker.py`
4. **Add configuration:** Environment variables in `app/config.py`
5. **Update documentation:** This file and configuration.md
6. **Add tests:** Unit and integration tests

### Example Implementation

```python
# app/services/example.py
def fetch_example_feed(api_key: str) -> List[Dict]:
    resp = requests.get(
        "https://api.example.com/indicators",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30
    )
    resp.raise_for_status()
    
    indicators = []
    for item in resp.json()["items"]:
        indicators.append({
            "ioc_value": item["value"],
            "ioc_type": map_type(item["type"]),
            "source": "example",
            "source_ref": str(item["id"]),
            "confidence": 70,
            "tlp": "GREEN",
            "is_active": True,
            "tags": item.get("tags", []),
            "metadata": {"raw": item},
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
        })
    
    return indicators
```

---

## Best Practices

### Source Selection

1. **Quality over quantity** - Prefer high-fidelity sources
2. **TLP compliance** - Respect data sharing restrictions
3. **Update frequency** - Balance freshness vs. API limits
4. **Attribution** - Track provenance with source_ref

### Performance

1. **Batch upserts** - Use PostgreSQL's ON CONFLICT
2. **Incremental updates** - Fetch only new/changed data
3. **Connection pooling** - Reuse HTTP connections
4. **Caching** - Cache API responses when appropriate

### Error Handling

1. **Retry with backoff** - Handle transient errors
2. **Circuit breaker** - Stop after repeated failures
3. **Alerting** - Monitor `feed_stats.last_fetch_status`
4. **Graceful degradation** - Continue with other sources

---

## See Also

- [CLI Documentation](cli.md) - Manual ingestion tools
- [Configuration](configuration.md) - Source configuration
- [Architecture](architecture.md) - Data flow and processing
- [Database](database.md) - Schema and indexes
