# Secure Software Development Lifecycle (SSDLC)

Status: introduced for `compliance-1.0`.
Framework: ISO 27001 A.14.2 (Security in Development and Support Processes).

---

## 1. Policy

All code changes to ioc-service must pass the automated quality and security gates defined in this document before merging to `main` or publishing a release. The `CLAUDE.md` file at the repository root encodes the documentation-driven delivery policy that governs when and how changes are made.

---

## 2. Automated Security Gates (CI)

Every push and pull request to `main` triggers the following checks. All must pass before a release is created.

| Gate | Tool | Failure action |
|---|---|---|
| Dependency vulnerability scan | `pip-audit -r requirements.txt` (CI) + OSV Scanner reusable workflow | Block merge |
| SAST — high/critical findings | `bandit -r app --severity-level high` | Block merge |
| Static analysis / lint | `ruff check app tests` | Block merge |
| Type checking | `mypy app` | Block merge |
| Unit + integration tests | `pytest -q` (568+ tests) | Block merge |
| Container OS/package scan | OSV Scanner on Docker image layers | Block merge |

CI definition: `.github/workflows/ci.yml`.
OSV Scanner definition: `.github/workflows/osv-scanner.yml` (`google/osv-scanner-action` v2 reusable workflow).

---

## 3. Dependency Management

- Runtime dependencies: `requirements.txt` — pinned exact versions.
- Dev/test dependencies: `requirements-dev.txt` — pinned exact versions.
- Transitive vulnerability pins are added explicitly with a comment (see `zipp`, `filelock`, `pip` entries).
- GitHub Dependabot monitors `requirements.txt` and `requirements-dev.txt` for advisory alerts.
- Patch SLAs are defined in `docs/vulnerability-management.md`.

---

## 4. Change Control

| Control | Implementation |
|---|---|
| All changes documented before implementation | `change.log` journal entry required (see `CLAUDE.md`) |
| Changes to `main` require a passing CI run | Branch protection rule (see repo Settings → Branches) |
| Release tagging requires human approval | Release tags are created manually; release workflow runs on `release: published` event |
| Breaking changes require milestone tracking | GitHub milestones with acceptance criteria |

---

## 5. Secure Coding Standards

| Area | Standard |
|---|---|
| Secrets | Must never be committed; `.env` is gitignored; `SECRET_KEY` generation removed from entrypoints |
| SQL | SQLAlchemy ORM only; raw SQL via `text()` requires explicit review |
| Authentication | Admin surface protected by session token, rate-limited, CSRF-guarded |
| Audit trail | Admin actions written to `audit_log` with HMAC hash chain |
| Input validation | All user inputs validated at route boundary; structured error responses |
| XSS / injection | Templates use Jinja2 auto-escaping; API responses are JSON |

---

## 6. Secret Detection

- `.gitignore` excludes `.env`, `.env.*`, credential files.
- `CLAUDE.md` prohibits committing secrets and requires explicit `SECRET_KEY` provisioning.
- Pre-commit hook (optional): add `detect-secrets` or `truffleHog` to `requirements-dev.txt` for local enforcement.
- CI does not currently run automated secret scanning; enabling GitHub Secret Scanning is recommended when available on this repository tier.

---

## 7. Threat Model Summary

| Asset | Threat | Control |
|---|---|---|
| Admin panel | Brute-force / token leak | Rate limit + session auth + CSRF + audit log |
| PostgreSQL | SQL injection | ORM parameterized queries |
| Feed credentials | Credential exposure | Encrypted `app_settings` (AES-GCM at rest) |
| Audit log | Tampering | HMAC-SHA256 hash chain + scheduled integrity verification |
| Export files | Unauthorized bulk access | Admin-only export trigger + audit entry per export |
| Dependencies | Transitive CVE | OSV scanner + Dependabot + pip-audit |

Full risk register: `docs/risk-register.md`.

---

## 8. Outsourced / Third-Party Components

| Component | Source | Verification |
|---|---|---|
| Python runtime | python:3.12-slim Docker image | Pinned digest in Dockerfile |
| nginx | nginx:1.27-alpine | Pinned in `nginx/Dockerfile.tls` |
| Python packages | PyPI | Pinned versions, OSV-scanned |
| GitHub Actions | github.com marketplace | Pinned at `@sha` or `@vX.Y.Z` |

---

## 9. Security Review Checklist (pre-release)

- [ ] All CI gates green
- [ ] `docs/vulnerability-management.md` — no deferred critical/high CVEs
- [ ] `docs/risk-register.md` reviewed and updated
- [ ] `change.log` records all changes since last release
- [ ] Audit log integrity verified: `GET /admin/audit/verify`
- [ ] Release notes document any security-relevant changes
