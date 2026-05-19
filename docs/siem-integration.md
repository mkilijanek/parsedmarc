# SIEM Integration

Status: updated for `1.9.x` (2026-05-19).
Framework: NIST CSF DE.CM (Security Continuous Monitoring), ISO 27001 A.12.4.

---

## 1. Integration Methods

ioc-service exposes two log endpoints suitable for SIEM ingestion:

| Endpoint | Format | Use case |
|---|---|---|
| `GET /api/logs` | JSON (default) | Pull-based JSON ingestion (Logstash, Fluentd, custom) |
| `GET /api/logs?format=cef` | CEF (text/plain) | ArcSight, Splunk, QRadar direct CEF ingest |
| `GET /api/logs/export` | JSON + integrity checksum | Point-in-time evidence package with `X-Export-Checksum` header |
| `GET /admin/audit/report` | JSON | Compliance audit trail with hash-chain verification |

Authentication: requires an active admin session cookie (`GET /auth/login` → POST credentials → session).

---

## 2. CEF Format

The `?format=cef` option returns ArcSight Common Event Format lines:

```
CEF:0|ioc-service|app|1.0|<SignatureID>|<Name>|<Severity>|Extension
```

**Severity mapping**:

| Log level | CEF severity |
|---|---|
| INFO / DEBUG | 0 |
| WARNING / WARN | 5 |
| ERROR | 8 |
| CRITICAL | 10 |

**Extension fields**:

| Field | CEF label | Content |
|---|---|---|
| `created_at` | `rt` | ISO timestamp |
| `component` | `cs1` | app component (scheduler, fetcher, parser…) |
| `feed_source_id` | `cs2` | feed name (misp, mwdb, crowdsec…) |
| `run_id` | `cs3` | sync job UUID |
| `message` | `msg` | human-readable message |

**Example**:
```
CEF:0|ioc-service|app|1.0|ERROR|ERROR|8|rt=2026-04-29T08:00:00 cs1Label=component cs1=fetcher cs2Label=feed cs2=misp cs3Label=run_id cs3=run-abc123 msg=Connection timeout after 30s
```

---

## 3. Query Parameters

| Parameter | Description | Example |
|---|---|---|
| `since` | ISO 8601 start time | `since=2026-04-01T00:00:00Z` |
| `until` | ISO 8601 end time | `until=2026-04-29T23:59:59Z` |
| `level` | Single or pipe-separated levels | `level=WARNING\|ERROR` |
| `feed` | Feed source ID | `feed=misp` |
| `component` | Component name | `component=scheduler` |
| `job_id` | Sync job run UUID | `job_id=run-abc123` |
| `limit` | Max rows (default 200, max 500 for `/api/logs`; max 5000 for `/api/logs/export`) | `limit=500` |
| `format` | `json` (default) or `cef` | `format=cef` |

---

## 4. Splunk Integration

**Option A — HTTP Event Collector (HEC) via script**:

```bash
#!/bin/bash
# Poll ioc-service logs and forward to Splunk HEC
SINCE=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
curl -s "https://ioc-service/api/logs?format=cef&level=WARNING|ERROR&since=${SINCE}" \
  -H "Cookie: session=<session>" | \
  curl -s -X POST "https://splunk:8088/services/collector/raw" \
  -H "Authorization: Splunk <HEC-token>" \
  -H "Content-Type: text/plain" \
  --data-binary @-
```

**Option B — Splunk UF (Universal Forwarder)** on the ioc-service host, reading Docker logs:
```
docker compose logs --follow app 2>&1 | /opt/splunkforwarder/bin/splunk add monitor stdin
```

---

## 5. ELK / OpenSearch Integration (Logstash)

```ruby
# logstash.conf
input {
  http_poller {
    urls => {
      ioc_logs => {
        method => get
        url => "https://ioc-service/api/logs?level=WARNING|ERROR&limit=500"
        headers => { "Cookie" => "session=<session>" }
      }
    }
    schedule => { every => "5m" }
    codec => "json"
  }
}

filter {
  split { field => "items" }
  mutate { rename => { "[items][message]" => "message" } }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    index => "ioc-service-logs-%{+YYYY.MM.dd}"
  }
}
```

---

## 6. Microsoft Sentinel Integration

ioc-service supports two complementary Sentinel integrations:

### Option A — Push IOC indicators via Graph API (native)

Configure `AZURE_SENTINEL_*` environment variables to push threat indicators directly to Sentinel via the Microsoft Graph API (`/beta/security/tiIndicators/submitTiIndicators`). The worker sends indicators automatically during feed sync.

Required env vars (see [Configuration](configuration.md) for full reference):

```bash
AZURE_SENTINEL_TENANT_ID=<tenant-id>
AZURE_SENTINEL_CLIENT_ID=<app-registration-client-id>
AZURE_SENTINEL_AUTH_MODE=client_secret          # or: certificate
AZURE_SENTINEL_CLIENT_SECRET=<client-secret>    # for client_secret mode
```

Optional:
```bash
AZURE_SENTINEL_CHUNK_SIZE=100    # indicators per API request (default 100)
AZURE_SENTINEL_SCOPE=https://graph.microsoft.com/.default
```

Required Azure AD permission: `ThreatIndicators.ReadWrite.OwnedBy` on Microsoft Graph.

### Option B — Forward logs via HTTP Data Collector API

Pull log events from ioc-service and push them to a Sentinel Log Analytics workspace:

```python
import requests, json, hashlib, hmac, base64, datetime

workspace_id = "<WORKSPACE_ID>"
workspace_key = "<WORKSPACE_KEY>"
log_type = "IocServiceLogs"

def build_signature(workspace_id, key, date, content_length):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"

logs = requests.get(
    "https://ioc-service/api/logs?level=WARNING|ERROR&limit=500",
    cookies={"session": "<session>"}
).json()["items"]

body = json.dumps(logs)
rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
signature = build_signature(workspace_id, workspace_key, rfc1123date, len(body))

requests.post(
    f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
    headers={"Authorization": signature, "Log-Type": log_type, "x-ms-date": rfc1123date},
    data=body
)
```

---

## 7. Detection Rules Reference

The following log patterns are significant for SIEM alerting:

| Pattern | `level` | `component` | `action` in audit | Alert |
|---|---|---|---|---|
| Multiple failed admin logins | — | — | `rate_limit_exceeded` on `/auth/login` | Brute-force attempt |
| Bulk IOC export | — | — | `export_*` action | Data exfiltration risk |
| Audit chain failure | ERROR | audit | `audit_integrity_failed` | Tamper attempt |
| Feed sync repeatedly failing | ERROR | fetcher | — | Feed availability issue |
| Log retention cleanup | INFO | maintenance | — | Informational |

See [Runbook](runbook.md) for incident classification and escalation guidance.
