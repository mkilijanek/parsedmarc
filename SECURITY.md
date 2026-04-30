# Security Policy

## Supported Versions
Currently supporting release line `1.8.x`.

## Reporting Vulnerabilities
Create a private security report in GitHub Security Advisories for this repository.
If unavailable, open a private channel with repository maintainers and include:
- affected version/tag
- reproduction steps
- impact assessment
- proposed fix or mitigation

## Security Features
- TLS 1.2+ only
- Rate limiting
- Session-protected admin surface with CSRF tokens
- HMAC-SHA256 audit log hash chain with integrity verification
- Admin audit logging with source IP capture
- AES-GCM encrypted storage for secrets and feed credentials
- SQL injection prevention (SQLAlchemy parameterized queries)
- XSS protection (Jinja2 auto-escaping)
- CSRF protection
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- DBCircuitBreaker against database outages, with enforced cooldown and single half-open probe semantics
- Dead Letter Queue for permanently-failed sync jobs
- Correlation IDs in API error responses
- Migration-first startup (no runtime schema creation)

## Best Practices
1. Rotate secrets every 90 days
2. Use strong passwords (32+ chars)
3. Enable firewall
4. Regular updates
5. Monitor logs and audit chain integrity (`/admin/audit/verify`)
6. Backup data and verify backup recoverability quarterly
7. Run DB migrations before restarting app/worker on upgrades
8. Provision `SECRET_KEY` and `ADMIN_API_TOKEN` explicitly in deployment secrets
9. Deploy Prometheus/Grafana for operational visibility
10. Review `docs/compliance.md` controls matrix before each release
