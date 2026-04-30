# Risk Register

Status: updated for `1.8.0` + `compliance-1.0` (2026-04-30).

## Method

Risk score is calculated as `likelihood x impact`. Both values use a 1-5 scale.

Risk levels:
- `critical`: score 20-25
- `high`: score 12-19
- `medium`: score 6-11
- `low`: score 1-5

Treatment values:
- `mitigate`: reduce likelihood or impact through controls
- `accept`: explicitly accept residual risk
- `transfer`: move part of risk through insurance or contract
- `avoid`: remove the activity creating the risk

## Register

| ID | Threat | Vulnerability | Asset | Likelihood | Impact | Level | Treatment | Owner | Status | Review |
|---|---|---|---|---:|---:|---|---|---|---|---|
| R001 | Unauthorized admin access | Weak or leaked admin token | Admin surface | 3 | 5 | high | mitigate with session auth, CSRF, RBAC and audit | Security | done (1.4.2) | quarterly |
| R002 | Feed outage or API throttling | External provider instability | Feed ingestion | 4 | 3 | high | mitigate with circuit breakers, retries, DLQ and job backoff | Platform | done (1.8.0) | monthly |
| R003 | Schema drift | ORM, Alembic and SQL init divergence | PostgreSQL schema | 3 | 4 | high | mitigate with schema drift CI gate and PostgreSQL tests | Database | done (1.5.1) | every release |
| R004 | Audit tampering | Mutable database logs | Audit trail | 2 | 5 | high | mitigate with HMAC hash chain and scheduled verification | Security | done (compliance-1.0) | monthly |
| R005 | Vulnerable dependency | Delayed patching | Application runtime | 3 | 4 | high | mitigate with Dependabot, pip-audit, bandit and OSV Scanner CI gates | Platform | done (1.8.0) | weekly |
| R006 | Unencrypted backup leak | Manual backup handling | Database backups | 2 | 4 | medium | encrypted backup script and documented restore controls | Operations | done (compliance-1.0) | quarterly |
| R007 | Large export leakage | Unapproved bulk export | Export files | 2 | 4 | medium | audit every export and require restricted filesystem retention | Security | done (1.8.0) | monthly |
| R008 | DBCircuitBreaker false open | Transient DB hiccup trips circuit unnecessarily | API availability | 2 | 4 | medium | enforced cooldown + single half-open probe; monitor open-transition rate | Platform | mitigated (`1.8.1`) | monthly |
| R009 | DLQ accumulation | Unmonitored dead-letter jobs mask systemic feed failures | Sync pipeline | 3 | 3 | medium | DLQ inventory endpoint, manual requeue, metric-based alerting | Platform | accepted | monthly |
| R010 | SSE endpoint exposure | Public event stream leaks operational metadata to unauthenticated clients | Operational telemetry | 2 | 2 | low | documented as public-read surface; consider future restriction | Security | accepted | quarterly |
| R011 | Cache warming failure | Redis unavailability causes cold caches for dashboard widgets | Dashboard UX | 2 | 2 | low | cache warming is best-effort; dashboard falls back to live queries | Platform | accepted | monthly |

## Review Process

- Review this file before each milestone release.
- Add a new row when a new high-impact threat or vulnerability is identified.
- Close a risk only when the treatment is implemented and the residual risk is accepted.
- Record material changes in `change.log`.
