# Security Policy

## Supported Versions

We actively support the latest **stable release** of this project, as well as the most recent **previous release**. Only these versions will receive security updates.

| Version       | Supported          |
|---------------|--------------------|
| `latest`      | ✅ Yes             |
| Previous tag  | ✅ Yes             |
| Older versions| ❌ No              |

To ensure you're protected, please always use the latest image:
docker pull ghcr.io/<your-org-or-user>/parsedmarc:latest

---

## Reporting a Vulnerability

If you discover a vulnerability or security issue, please report it **privately**.

- 🔐 GitHub: [Create a Security Advisory](https://github.com/mkilijanek/parsedmarc/security/advisories)

Please do **not** file public issues or disclose the problem until we've had a chance to fix it.

---

## Response Expectations

- We will **acknowledge** vulnerability reports within **48 hours**
- For valid reports, a **patch or mitigation** will be released within **7–14 days**
- You will be credited as a reporter **unless anonymity is requested**

---

## Tools Used for Vulnerability Management

This project uses:

- [Snyk](https://snyk.io) for automated image scanning and continuous monitoring
- GitHub Code Scanning for visible alerts on pull requests and pushes

Scans are performed **on every commit to `main`**, all PRs, and **weekly** via scheduled jobs.

---

## Keep Secure

- Always pull and verify **signed images** using [cosign](https://github.com/sigstore/cosign)
- Review attached [SLSA Provenance](https://slsa.dev) to verify image origin and integrity

---

Thank you for helping make this project safer!
