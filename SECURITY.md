# Security Policy

## Supported Versions
Currently supporting release line `1.4.x`.

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
- Session-protected admin surface
- Admin audit logging with source IP capture
- SQL injection prevention
- XSS protection
- CSRF protection
- Security headers
- Correlation IDs in API error responses
- Migration-first startup (no runtime schema creation)

## Best Practices
1. Rotate secrets every 90 days
2. Use strong passwords (32+ chars)
3. Enable firewall
4. Regular updates
5. Monitor logs
6. Backup data
7. Run DB migrations before restarting app/worker on upgrades
8. Provision `SECRET_KEY` and `ADMIN_API_TOKEN` explicitly in deployment secrets
