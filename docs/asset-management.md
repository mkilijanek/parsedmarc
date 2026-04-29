# Asset Management and Classification

Status: introduced for `compliance-1.0`.
Framework: ISO 27001 A.7 (Human Resource Security), A.8 (Asset Management).

---

## 1. Asset Classification Levels

| Level | Description | Handling requirements |
|---|---|---|
| **Public** | No restrictions; intended for external consumption | Integrity checks; no confidentiality requirement |
| **Internal** | For organization use only | Access control; audit on export |
| **Confidential** | Limited distribution; sensitive operational data | Restricted admin access; audit on every access/modification |
| **Restricted** | Need-to-know only; secret material | Encryption at rest; redaction in logs; rotation plan required |

Detailed handling requirements are defined in `docs/data-protection.md`.

---

## 2. Data Asset Inventory

| Asset | Classification | Storage | Owner | Retention | Notes |
|---|---|---|---|---|---|
| IOC indicators (IPs, domains, hashes, URLs) | Confidential | PostgreSQL `indicators` | Data Owner | Until inactive + 90 days | Core threat intelligence data |
| Feed source configuration | Confidential | PostgreSQL `feed_sources` | Service Owner | Indefinite | Feed names, URLs, sync schedules |
| Feed API credentials (keys, tokens) | Restricted | PostgreSQL `app_settings` (AES-GCM encrypted) | Service Owner | Until rotated | CrowdSec key, MISP key, MWDB key, etc. |
| Admin API token (`ADMIN_API_TOKEN`) | Restricted | DB `app_settings` or env var | Service Owner | Until rotated | Protects admin surface |
| `SECRET_KEY` | Restricted | Environment variable / secrets vault | Service Owner | Until rotated | Protects session cookies and AES-GCM encryption |
| Audit log entries | Confidential | PostgreSQL `audit_log` | Security Lead | Minimum 1 year | HMAC-chained; do not purge automatically |
| Application logs (`app_logs`) | Internal | PostgreSQL `app_logs` | Maintainer | `LOG_RETENTION_DAYS` (default 90) | Operational events; no secrets stored |
| Correlation snapshots | Internal | PostgreSQL `correlation_snapshots` | Service Owner | 30 days (rolling) | Pre-computed indicator correlations |
| Export job files | Confidential | Filesystem `EXPORT_JOB_DIR` | Service Owner | 30 days max | Bulk IOC exports; must be on encrypted storage |
| Configuration files (`.env`, `docker-compose*.yml`) | Restricted | Host filesystem / secrets vault | DevOps | Git history | Never commit `.env` to version control |
| Documentation and architecture | Internal | GitHub repository | Maintainer | Indefinite | `docs/`, `README.md`, `ROADMAP.md` |
| Container images | Internal | GHCR (`ghcr.io/mkilijanek/ioc-service`) | Maintainer | 90 days per tag | SBOM and provenance attestation per release |
| Backup files | Confidential | Host `/var/backups/ioc-service/` | DevOps | 30 days local / 90 days remote | Must be encrypted at rest |

---

## 3. Software Asset Inventory

| Component | Version | Source | License | Notes |
|---|---|---|---|---|
| Flask | 3.1.3 | PyPI | BSD-3-Clause | Web framework |
| SQLAlchemy | 2.0.36 | PyPI | MIT | ORM |
| Alembic | 1.18.4 | PyPI | MIT | DB migrations |
| gunicorn | 22.0.0 | PyPI | MIT | WSGI server |
| psycopg2-binary | 2.9.9 | PyPI | LGPL | PostgreSQL driver |
| redis | 5.0.8 | PyPI | MIT | Redis client |
| cryptography | 46.0.7 | PyPI | Apache-2.0 | AES-GCM, TLS |
| Flask-Limiter | 3.7.0 | PyPI | MIT | Rate limiting |
| pymisp | 2.4.179 | PyPI | BSD-2-Clause | MISP adapter |
| prometheus-client | 0.20.0 | PyPI | Apache-2.0 | Metrics |
| nginx | 1.27-alpine | Docker Hub | BSD-2-Clause | TLS edge proxy |
| PostgreSQL | 16 | Docker Hub | PostgreSQL License | Primary data store |
| Redis | 7 | Docker Hub | BSD-3-Clause | Cache / rate-limit store |

Full pinned versions: `requirements.txt`, `requirements-dev.txt`.

---

## 4. Asset Lifecycle

```
Acquisition → Inventory → Classification → Operation → Maintenance → Decommission
```

| Phase | Controls |
|---|---|
| Acquisition | Dependency vulnerability scan before adding to `requirements.txt`; PR review |
| Inventory | Update this document for new data assets; update `requirements.txt` for software |
| Classification | Assign classification level at creation; document handling requirements |
| Operation | Access controls enforced; audit logging active |
| Maintenance | Patch per SLAs in `docs/vulnerability-management.md`; credential rotation per policy |
| Decommission | Securely delete data per classification; revoke credentials; remove from inventory |

---

## 5. Credential and Key Inventory

| Credential | Classification | Storage | Rotation period | Rotation procedure |
|---|---|---|---|---|
| `SECRET_KEY` | Restricted | Env var / vault | Annually or on suspected compromise | Maintenance window required; re-keys encrypted settings and resets audit chain |
| `ADMIN_API_TOKEN` | Restricted | DB + env var | Quarterly | Rotate in DB via admin panel; update `.env` |
| Feed API keys | Restricted | DB (encrypted) | Per provider recommendation | Update via admin settings; trigger re-sync |
| PostgreSQL password | Restricted | Env var / vault | Annually | Rolling restart required |
| TLS certificates | Confidential | Host filesystem | Before expiry (90-day warning) | `scripts/setup-ssl.sh` or ACME renewal |

---

## 6. Acceptable Use

- Feed API credentials must only be used by the ioc-service application; do not share with third-party tools.
- IOC data classified as Confidential must not be exported to unauthenticated endpoints or shared without explicit authorization.
- Admin API token and SECRET_KEY must not be logged, included in error messages, or committed to version control.
- Export files (`EXPORT_JOB_DIR`) must be purged after 30 days; the host filesystem must use encryption at rest.

---

## 7. Human Resource Security (ISO 27001 A.7)

| Control | Implementation |
|---|---|
| A.7.1.1 — Screening | Define as an HR process outside the application scope |
| A.7.2.2 — Security awareness | `CLAUDE.md`, `docs/ssdlc.md`, `docs/incident-response.md` are the awareness baseline for all contributors |
| A.7.3.1 — Termination | Revoke admin session + rotate `ADMIN_API_TOKEN` + remove user from any GitHub team grants |
