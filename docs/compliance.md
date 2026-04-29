# Compliance Controls

Status: introduced for `compliance-1.0`.
Framework: ISO 27001 A.18 (Compliance), NIST CSF.

---

## 1. Applicable Frameworks

| Framework | Applicability | Assessment date |
|---|---|---|
| ISO 27001:2022 | Adopted as reference for controls | 2026-04-29 |
| NIST CSF 2.0 | Adopted for detection and response | 2026-04-29 |
| GDPR | Review required if EU personal data processed | Not assessed |

---

## 2. Controls Matrix

### ISO 27001 — Delivered Controls

| Control ID | Title | Status | Evidence / Implementation |
|---|---|---|---|
| A.9.2 | Access control policy | Partial | Admin session auth + token, CSRF, `/docs/access-control.md` |
| A.12.3.1 | Information backup | Delivered | `scripts/backup.sh`, `docs/disaster-recovery.md` |
| A.12.4.1 | Event logging | Delivered | `AppLog` model, `/api/logs`, `/logs` UI, all fields structured |
| A.12.4.2 | Protection of log information | Delivered | `AuditLog` HMAC-SHA256 hash chain, `app/audit_integrity.py` |
| A.12.4.3 | Administrator and operator logs | Delivered | All admin actions in `audit_log` with actor + IP + hash |
| A.12.4.4 | Clock synchronisation | Infra | Host NTP; container timestamps derived from host |
| A.14.2 | Security in development | Delivered | `docs/ssdlc.md`, CI gates (OSV, bandit, ruff, mypy, pytest) |
| A.16.1 | Information security incidents | Delivered | `docs/incident-response.md` |
| A.17.1 | Information security continuity | Delivered | `docs/disaster-recovery.md`, RTO/RPO defined |
| A.18.1.3 | Protection of records | Delivered | Audit hash chain, log retention policy (`LOG_RETENTION_DAYS`) |
| A.18.2.2 | Compliance with policies | Partial | `CLAUDE.md` enforces documentation-driven delivery |
| A.18.2.3 | Technical compliance review | Partial | OSV scanner, pip-audit, bandit in CI |

### NIST CSF — Delivered Controls

| Function | Category | Status | Evidence |
|---|---|---|---|
| PR.AC | Identity Management and Access Control | Partial | Admin session auth, token-based API |
| PR.DS | Data Security | Partial | Encrypted settings, TLS edge, audit chain |
| PR.IP | Information Protection | Delivered | `docs/ssdlc.md`, CI gates, change control |
| DE.CM | Security Continuous Monitoring | Partial | Prometheus metrics, AppLog, SIEM export (`/api/logs?format=cef`) |
| DE.DP | Detection Processes | Partial | Rate limit audit, audit chain integrity schedule |
| RS.RP | Response Planning | Delivered | `docs/incident-response.md` |
| RS.AN | Analysis | Partial | Audit trail export, log export with checksum |
| RC.RP | Recovery Planning | Delivered | `docs/disaster-recovery.md` |

---

## 3. Audit Trail Verification

The audit log implements a cryptographic hash chain (HMAC-SHA256 keyed with `SECRET_KEY`). Each row stores:
- `log_hash` — HMAC of the row's canonical payload
- `previous_hash` — hash of the preceding row (creates the chain)

**Verify chain integrity**:
```
GET /admin/audit/verify
```
Returns `{"valid": true, "verified_count": N, ...}`. A `valid: false` response means at least one row was modified or deleted.

**Full compliance report** (includes control references):
```
GET /admin/audit/report
```

**Scheduled verification**: the scheduler runs `verify_audit_chain()` every `AUDIT_INTEGRITY_VERIFY_INTERVAL_S` seconds (default: 3600) and logs the result to `AppLog` with `component=audit`.

---

## 4. Log Retention

Application logs (`app_logs` table) are automatically purged after `LOG_RETENTION_DAYS` days (default: 90). Set the env var to adjust:

```env
LOG_RETENTION_DAYS=365  # retain for 1 year
```

Audit logs (`audit_log` table) are **not automatically purged** — they are protected by the hash chain and should be retained according to your compliance requirement (ISO 27001 recommends at least 1 year for audit records).

---

## 5. Integrity-Verified Log Export

For SIEM ingestion or audit evidence packages:

```bash
# JSON export with SHA-256 checksum
curl -s "https://<host>/api/logs/export?since=2026-01-01&until=2026-04-29" \
  -H "Cookie: session=<admin-session>" \
  -o logs-export.json \
  -D - | grep X-Export-Checksum

# CEF format for SIEM push
curl -s "https://<host>/api/logs?format=cef&since=2026-01-01" \
  -H "Cookie: session=<admin-session>"
```

The `X-Export-Checksum: sha256:<hex>` header on `/api/logs/export` allows a recipient to independently verify the export was not tampered with in transit.

---

## 6. Independent Review

ISO 27001 A.18.2.1 requires periodic independent review of the information security posture. Recommended cadence:

| Review type | Frequency | Owner |
|---|---|---|
| Audit chain integrity | Automated (hourly) + quarterly manual | Security lead |
| Risk register review | Quarterly | Service owner |
| Vulnerability / patch status | Monthly (Dependabot + OSV) | Maintainer |
| DR restore test | Quarterly | Operations |
| SSDLC controls review | Every release | Security lead |

---

## 7. Known Gaps

| Gap | Risk | Target milestone |
|---|---|---|
| WORM / append-only storage for audit log | Tamper via direct DB access | compliance-1.1 |
| Secret scanning in CI (GitHub Secret Scanning) | Credential commit | compliance-1.1 |
| Formal GDPR DPIA | If personal data processed | compliance-1.1 |
| SIEM real-time streaming | Delay in threat detection | 1.8.0 / compliance-1.1 |
