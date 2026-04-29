# Incident Response Plan

Status: introduced for `compliance-1.0`.
Framework: NIST CSF RS.RP, ISO 27001 A.16 (Information Security Incident Management).

---

## 1. Scope

This plan covers security and operational incidents affecting the ioc-service application, its data stores (PostgreSQL, Redis), and the threat intelligence data managed within.

---

## 2. Incident Classification

| Severity | Description | Examples | Response SLA |
|---|---|---|---|
| **Critical** | System compromise or data breach | Admin token leak, DB dump exfiltrated, feed credential stolen | Immediate (<15 min) |
| **High** | Service disruption or unauthorized access | Repeated 401/403 from unexpected IPs, brute-force on /auth/login, privilege escalation | <1 hour |
| **Medium** | Policy violation or suspicious activity | Anomalous bulk export (>10 000 IOCs), config change outside maintenance window | <4 hours |
| **Low** | Informational or minor | Single failed login, feed sync failure, cert expiry >30 days away | <24 hours |

---

## 3. Detection Sources

| Source | What it detects | Where to look |
|---|---|---|
| Audit log hash chain | Tamper attempts on audit records | `GET /admin/audit/verify` — returns `valid: false` if chain is broken |
| AppLog `WARNING`/`ERROR` level | Feed failures, internal errors | `GET /api/logs?level=WARNING\|ERROR` or `/logs` (Problems quick-filter) |
| Audit log `rate_limit_exceeded` action | Brute-force or scraping | `GET /admin/audit/report` — filter action=rate_limit_exceeded |
| Audit log `admin_login` / `admin_logout` | Session anomalies | `/admin/audit/report` |
| Prometheus metrics | Throughput, error-rate anomalies | `/metrics` (requires METRICS_AUTH_TOKEN) |
| nginx access log | 4xx/5xx spike from single source | `docker compose logs nginx` |

---

## 4. Incident Response Procedure

### Step 1 — Detect and triage

1. Identify the detection source and severity level.
2. Assign an incident owner and open an incident record (GitHub issue with `security` label, or internal ticket).
3. Record initial indicators: timestamp, source IP, affected endpoints, affected data.

### Step 2 — Contain

| Incident type | Containment action |
|---|---|
| Brute-force on `/auth/login` | Rate limiter activates automatically. If still active: set `ADMIN_PANEL_ENABLED=false` and redeploy → admin surface returns 404. |
| Leaked admin API token | Rotate `ADMIN_API_TOKEN` in DB via `UPDATE app_settings SET value=<new-token> WHERE key='admin_api_token'`; invalidate all admin sessions via Redis `FLUSHDB` on session store. |
| Compromised feed credential | Update credential in admin settings panel or DB. Rotate at feed provider. Trigger full re-sync. |
| Suspicious bulk export | Check `/admin/audit/report` for export action entries. Revoke admin session if actor is unknown. |
| Suspected DB access | Change `DATABASE_URL` password immediately. Rotate `SECRET_KEY` (triggers re-keying of encrypted settings and audit chain reset). Redeploy. |
| Audit chain tampering detected | Preserve DB snapshot for forensics. Rebuild audit chain from backup. Escalate to Critical. |

### Step 3 — Investigate

1. Export affected log window: `GET /api/logs/export?since=<T1>&until=<T2>` — retain the `X-Export-Checksum` header for evidentiary integrity.
2. Export audit trail: `GET /admin/audit/report` — verify `integrity.valid == true` before treating as authoritative.
3. Preserve Docker logs: `docker compose logs --no-color app worker nginx > incident-<date>.log`.
4. Document timeline in the incident record.

### Step 4 — Eradicate and recover

1. Apply the relevant containment action (Step 2).
2. Redeploy from known-good image: `scripts/deploy_ghcr_variant.sh ioc-service <last-known-good-tag>`.
3. Restore from backup if data integrity is in question (see `docs/disaster-recovery.md`).
4. Verify audit chain after recovery: `GET /admin/audit/verify`.

### Step 5 — Post-incident review

Within 5 business days of resolution:
1. Update the incident record with root cause, timeline, and evidence references.
2. Update `docs/risk-register.md` if a new or escalated risk is identified.
3. Add detection rule or test to prevent recurrence.
4. Update `change.log` with lessons learned.

---

## 5. Escalation Contacts

Populate this table for your deployment:

| Role | Contact | Availability |
|---|---|---|
| Service Owner | _(fill in)_ | Business hours |
| Security Lead | _(fill in)_ | On-call for Critical/High |
| Data Protection Officer | _(fill in)_ | Business hours |

---

## 6. Evidence Preservation Checklist

- [ ] Export logs with integrity checksum: `/api/logs/export`
- [ ] Export audit trail: `/admin/audit/report`
- [ ] Preserve Docker container logs (app, worker, nginx)
- [ ] Preserve PostgreSQL WAL / point-in-time snapshot if available
- [ ] Record all response actions with timestamps in the incident record
- [ ] Do **not** overwrite or rotate secrets until forensic copies are secured
