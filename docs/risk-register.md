# Risk Register

Status: introduced for `1.5.1`.

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
| R001 | Unauthorized admin access | Weak or leaked admin token | Admin surface | 3 | 5 | high | mitigate with session auth, CSRF, RBAC and audit | Security | in progress | quarterly |
| R002 | Feed outage or API throttling | External provider instability | Feed ingestion | 4 | 3 | high | mitigate with circuit breaker, retries and job backoff | Platform | in progress | monthly |
| R003 | Schema drift | ORM, Alembic and SQL init divergence | PostgreSQL schema | 3 | 4 | high | mitigate with schema drift CI gate and PostgreSQL tests | Database | in progress | every release |
| R004 | Audit tampering | Mutable database logs | Audit trail | 2 | 5 | high | mitigate with HMAC hash chain and scheduled verification | Security | in progress | monthly |
| R005 | Vulnerable dependency | Delayed patching | Application runtime | 3 | 4 | high | mitigate with Dependabot and pip-audit CI gate | Platform | in progress | weekly |
| R006 | Unencrypted backup leak | Manual backup handling | Database backups | 2 | 4 | medium | require encrypted backup target and documented restore controls | Operations | planned | quarterly |
| R007 | Large export leakage | Unapproved bulk export | Export files | 2 | 4 | medium | audit every export and require restricted filesystem retention | Security | in progress | monthly |

## Review Process

- Review this file before each milestone release.
- Add a new row when a new high-impact threat or vulnerability is identified.
- Close a risk only when the treatment is implemented and the residual risk is accepted.
- Record material changes in `change.log`.
