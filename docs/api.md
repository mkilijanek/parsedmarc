# API Documentation

## Overview

The Threat Feed Aggregator provides a RESTful API for querying and exporting Indicators of Compromise (IOCs). All endpoints support various formats and filtering options.

---

## Base URL

- **HTTP:** `http://localhost:8080` (development)
- **HTTPS:** `https://localhost:7003` (production, via nginx)

---

## Authentication

The current implementation does not require authentication for API access. **For production deployments**, consider:
- Deploying behind VPN/internal network
- Adding API key authentication
- Implementing IP whitelisting at nginx level

---

## Endpoints

### Health Check

#### `GET /health`

Returns service health status and integration checks.

**Rate Limit:** 60 requests/minute

**Response:**
```json
{
  "status": "healthy",
  "checks": {
    "database": true,
    "redis": true,
    "misp": true,
    "crowdsec": true
  }
}
```

**Status Values:**
- `healthy` - All checks passed
- `degraded` - Some checks failed

---

### Metrics

#### `GET /metrics`

Returns Prometheus-compatible metrics for monitoring.

**Rate Limit:** 30 requests/minute

**Response Format:** Prometheus text format

**Metrics Exposed:**
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request duration histogram
- `active_indicators` - Number of active indicators in database

**Security Note:** Deploy this endpoint behind internal network/VPN in production.

---

### Index / Dashboard

#### `GET /`

Returns HTML dashboard with system overview and feed statistics.

**Rate Limit:** 60 requests/minute

**Response:** HTML page with:
- Total and active indicator counts
- Feed statistics table
- Quick links to exports

---

### Indicator Search & View

#### `GET /indicators`

Unified indicator search and viewing endpoint with HTML interface.

**Rate Limit:** 20 requests/minute

**Query Parameters:**

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `q` | string | Kibana-like search query | `value:192.168.* AND confidence:>70` |
| `type` | string | Filter by IOC type | `ip`, `domain`, `url`, `hash`, `email` |
| `tlp` | string | Filter by TLP level | `WHITE`, `GREEN`, `AMBER`, `RED` |
| `source` | string | Filter by data source | `misp`, `crowdsec`, `malwarebazaar`, `mwdb` |
| `min_conf` | integer | Minimum confidence (0-100) | `70` |
| `max_conf` | integer | Maximum confidence (0-100) | `90` |

**Search Query Syntax (Kibana-like):**

```
# Field searches
value:192.168.*
type:ip
source:misp
tlp:AMBER
tags:apt

# Comparisons (for confidence field)
confidence:>70
confidence:>=80
confidence:<50
confidence:<=60

# Boolean operators
type:ip AND confidence:>70
value:*.example.com OR value:*.evil.com
NOT type:hash

# Wildcards
value:192.168.*    # * matches any characters
value:192.168.1.?  # ? matches single character

# Parentheses for grouping
(type:ip OR type:domain) AND confidence:>80
```

**Supported Fields:**
- `value` - IOC value (supports wildcards)
- `type` - IOC type
- `confidence` - Confidence score (supports comparison operators)
- `tlp` - TLP marking
- `tags` - Tags (exact match)
- `source` - Data source

**Response:** HTML page with indicator table

**Caching:** Responses are cached in Redis for 5 minutes (configurable via `CACHE_TTL`)

**Example:**
```bash
curl "https://localhost:7003/indicators?type=ip&min_conf=70&tlp=AMBER"
```

---

### Indicator Export

#### `GET /indicators/<format>`

Export indicators in various formats for SIEM/firewall integration.

**Rate Limit:** 30 requests/minute

**Query Parameters:** Same as `/indicators` endpoint

**Supported Formats:**

##### Basic Formats

| Format | MIME Type | Description |
|--------|-----------|-------------|
| `txt` | `text/plain` | Plain text, one IOC per line |
| `csv` | `text/csv` | CSV with headers |
| `json` | `application/json` | JSON array |
| `xml` | `application/xml` | XML format |

##### Firewall / Blocklist Formats

| Format | MIME Type | Description | Vendor |
|--------|-----------|-------------|--------|
| `fortigate` | `text/plain` | External Block List (IP only) | FortiGate |
| `fortigate_ips` | `text/plain` | IPS signature format | FortiGate |
| `checkpoint` | `text/csv` | CSV import format | Check Point |
| `paloalto` | `text/plain` | External Dynamic List (EDL) | Palo Alto Networks |
| `f5` | `text/plain` | iRule Data Group format | F5 BIG-IP |

##### SIEM / Platform Formats

| Format | MIME Type | Description | Platform |
|--------|-----------|-------------|----------|
| `sentinel` | `application/json` | STIX 2.1 wrapper | Microsoft Sentinel |
| `defender` | `text/csv` | IOC CSV import | Microsoft Defender |
| `imperva` | `application/json` | Blocklist JSON | Imperva SecureSphere |
| `arcsight` | `text/plain` | CEF format | ArcSight |
| `elasticsearch` | `application/x-ndjson` | Bulk API NDJSON | Elasticsearch |
| `cribl` | `application/x-ndjson` | ECS-compatible NDJSON | Cribl |
| `splunk` | `application/json` | HEC batch format | Splunk |
| `fidelis` | `application/json` | STIX 2.1 bundle | Fidelis Cybersecurity |

**Examples:**

```bash
# Export all high-confidence IPs as text
curl "https://localhost:7003/indicators/txt?type=ip&min_conf=80"

# Export AMBER TLP indicators for FortiGate
curl "https://localhost:7003/indicators/fortigate?tlp=AMBER"

# Export to Elasticsearch bulk format
curl "https://localhost:7003/indicators/elasticsearch" | \
  curl -X POST http://elasticsearch:9200/_bulk \
  -H "Content-Type: application/x-ndjson" --data-binary @-

# Export to Splunk HEC
curl "https://localhost:7003/indicators/splunk" | \
  curl -X POST http://splunk:8088/services/collector/event \
  -H "Authorization: Splunk YOUR-HEC-TOKEN" \
  -H "Content-Type: application/json" --data-binary @-
```

**Caching:** Export responses are cached in Redis for 5 minutes

**Performance Notes:**
- Exports are limited to 100,000 indicators
- Large exports may take several seconds
- Database-native exports (txt, csv, json) use PostgreSQL functions for better performance

---

### Source Shortcuts

#### `GET /sources/<source>`

Convenience redirect to indicators filtered by source.

**Rate Limit:** 30 requests/minute

**Example:**
```bash
curl "https://localhost:7003/sources/misp"
# Redirects to: /indicators?source=misp

curl "https://localhost:7003/sources/crowdsec"
# Redirects to: /indicators?source=crowdsec
```

---

### MISP-Specific Endpoints

#### `GET /misp/event/<event_id>`

Redirect to MISP web UI for the specified event.

**Rate Limit:** 30 requests/minute

**Example:**
```bash
curl -L "https://localhost:7003/misp/event/12345"
# Redirects to: https://misp.example.com/events/view/12345
```

#### `GET /misp/event/<event_id>/<ioc_type>/<format>`

Export indicators from a specific MISP event.

**Rate Limit:** 30 requests/minute

**Parameters:**
- `event_id` - MISP event ID
- `ioc_type` - IOC type: `ip`, `domain`, `url`, `hash`, `email`, or `all`
- `format` - Export format (see supported formats above)

**Example:**
```bash
# Export all IPs from MISP event 12345 as CSV
curl "https://localhost:7003/misp/event/12345/ip/csv"

# Export all IOCs from event in JSON format
curl "https://localhost:7003/misp/event/12345/all/json"
```

---

### CrowdSec-Specific Endpoints

#### `GET /crowdsec/list/<list_id>/<format>`

Export indicators from a specific CrowdSec blocklist.

**Rate Limit:** 30 requests/minute

**Parameters:**
- `list_id` - CrowdSec list identifier
- `format` - Export format (see supported formats above)

**Example:**
```bash
curl "https://localhost:7003/crowdsec/list/my-blocklist/txt"
```

---

## Response Formats

### Success Response (Export)

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=300

[response body in requested format]
```

### Error Response

```json
{
  "error": "Invalid query"
}
```

**HTTP Status Codes:**
- `200 OK` - Successful request
- `400 Bad Request` - Invalid parameters or query syntax
- `404 Not Found` - Unknown format or endpoint
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

---

## Rate Limiting

Rate limits are enforced per client IP address:

| Endpoint | Limit |
|----------|-------|
| `/indicators` | 20/minute |
| `/indicators/<format>` | 30/minute |
| `/health` | 60/minute |
| `/metrics` | 30/minute |
| `/misp/*` | 30/minute |
| `/crowdsec/*` | 30/minute |
| `/sources/*` | 30/minute |
| Default | 60/minute |

**Rate Limit Headers:**
```
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 19
X-RateLimit-Reset: 1640000000
```

When rate limited:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

---

## Security Headers

All responses include security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; ...
Strict-Transport-Security: max-age=31536000; includeSubDomains
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## Caching

- **HTML responses:** Cached for 5 minutes (CACHE_TTL)
- **Export responses:** Cached for 5 minutes (CACHE_TTL)
- **Cache backend:** Redis
- **Cache key format:** `prefix|param1=value1|param2=value2`

To bypass cache (not recommended in production):
- Wait for TTL expiration
- Clear Redis cache manually

---

## Integration Examples

### Python

```python
import requests

# Search for high-confidence IPs
response = requests.get(
    "https://localhost:7003/indicators/json",
    params={
        "type": "ip",
        "min_conf": 80,
        "tlp": "AMBER"
    },
    verify=False  # Only for self-signed certs
)

indicators = response.json()
for ioc in indicators:
    print(f"{ioc['value']} - Confidence: {ioc['confidence']}")
```

### curl

```bash
# Download FortiGate blocklist
curl -k "https://localhost:7003/indicators/fortigate?tlp=AMBER" \
  -o blocklist.txt

# Search with complex query
curl -k "https://localhost:7003/indicators/json" \
  --data-urlencode "q=type:ip AND confidence:>70 AND (tags:apt OR tags:malware)"
```

### Scheduled Import (cron)

```bash
#!/bin/bash
# /etc/cron.d/ioc-import
# Run every 5 minutes

*/5 * * * * root curl -k "https://localhost:7003/indicators/fortigate" \
  -o /tmp/blocklist.txt && \
  fortiguard-cli import blocklist /tmp/blocklist.txt
```

---

## Best Practices

1. **Use HTTPS:** Always use HTTPS in production with valid certificates
2. **Filter appropriately:** Use TLP levels and confidence scores to avoid false positives
3. **Cache wisely:** Don't query more frequently than the cache TTL
4. **Monitor rate limits:** Implement exponential backoff for 429 responses
5. **Validate inputs:** Always validate and sanitize IOCs before using them
6. **Handle errors:** Implement proper error handling for 4xx/5xx responses
7. **Use specific formats:** Choose the format that matches your platform for best compatibility

---

## API Limitations

- Maximum query length: 500 characters
- Maximum export limit: 100,000 indicators per request
- Results are ordered by last_seen DESC
- Pagination is not currently implemented (use limit/offset via query)
- No streaming support for large exports

---

## Support

For issues or questions:
- Check logs: `docker compose logs app`
- Review SECURITY_AUDIT_REPORT.md for security considerations
- See QUICKSTART.md for deployment guidance
