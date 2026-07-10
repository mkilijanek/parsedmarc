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

## Known Accepted Risks

The following vulnerabilities are tracked but currently **not actionable** — there is no upstream fix available yet, and we lack a supportable way to patch around them. They are re-evaluated whenever the underlying base image is rebuilt (every 14 days) or a fix becomes available.

### CVE-2026-45186 — `expat`/`libexpat1` algorithmic complexity DoS

- **Affected images:** `Dockerfile.hardened` (`:distroless` tag) and `Dockerfile-debian.locked` (`-debian` locked tag) — both built on `gcr.io/distroless/python3-debian13`.
- **Severity:** High (CVSS 3.1: 7.5) — denial of service only, no code execution or data exposure. A moderately-sized crafted XML document can trigger O(n²) behavior in expat's attribute-name collision checks before v2.8.1.
- **Why we're tracking it closely rather than dismissing it:** parsedmarc parses DMARC aggregate/forensic report XML via `xml.parsers.expat` and `xmltodict`, and those reports arrive from arbitrary external sending mail servers. A malicious or spoofed report could target this parser directly, so this sits on an attacker-reachable input path rather than being purely incidental base-OS surface.
- **Why it isn't fixed yet:** Debian trixie (13) still ships `expat 2.7.1-2`; the patched `2.8.1+` has landed in Debian sid (`2.8.2-1`) but hasn't been backported to trixie. Both `Dockerfile.hardened` and `Dockerfile-debian.locked` use a distroless final stage with no package manager, so there is no `apt`/`apk`-level pin available like the ones used to remediate the Alpine musl/OpenSSL CVEs — the fix has to come from an updated `gcr.io/distroless/python3-debian13` base image once Debian ships a patched `expat` package.
- **Mitigation in the meantime:** run parsedmarc behind normal resource limits (CPU/memory quotas, timeouts) so a hung parse can't exhaust the host; prefer the `alpine`/`ubi` image variants where this specific CVE does not apply if DoS resilience against malicious report senders is a priority.
- **Re-check trigger:** next `distroless/python3-debian13` base image digest bump (tracked via Dependabot) or the 14-day scheduled rebuild.

---

## Keep Secure

- Always pull and verify **signed images** using [cosign](https://github.com/sigstore/cosign)
- Review attached [SLSA Provenance](https://slsa.dev) to verify image origin and integrity

---

Thank you for helping make this project safer!
