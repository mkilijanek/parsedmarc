# DMARCbis Migration Checklist (dev)

Tracks readiness for upstream DMARCbis work (local issue #29, upstream PR #659).

## Trigger

Start migration execution when upstream ships a stable release containing PR #659-equivalent changes.

## Checklist

1. Confirm upstream release notes and breaking changes.
2. Update this repo's default parsedmarc version on `dev`.
3. Validate image build and release workflows with the new version.
4. Review config examples and terminology updates (`forensic` vs `failure` where applicable).
5. Run container scan workflows (Trivy/Snyk) on the new image tags.
6. Publish migration notes for operators using existing configs/dashboards.

## Decision log

- 2026-03-03: checklist created; waiting for upstream merge/release.
- 2026-03-08: upstream PR #659 still open; no image/default-version change applied yet.
- 2026-10-15: upstream shipped RFC 9989/9990/9991 (DMARCbis) support in the 10.x line; this repo moves to 11.0.3. Remaining items: operator migration notes (step 6) and config terminology review (step 4: `forensic` -> `failure` keys are accepted as aliases upstream).
