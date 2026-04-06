# Release 1.4.1 Issues And Review Notes

Date: 2026-04-06

## Archive Integration Findings

- The archive `ioc-service-refactored-v1.4.0.zip` is not safe for blind overwrite of `main`.
- Its own `REFACTORING_SUMMARY.md` describes the route split as still incomplete.
- The extracted `app/utils.py` still polls `/health` from the startup loader, which conflicts with the current liveness/readiness contract finalized in `1.2.1`.
- The archive adds documentation/PDF artifacts that were not needed for runtime correctness and were intentionally not copied into the release branch.

## Dependabot Findings

- No repository-scoped open Dependabot issues were returned by the GitHub connector at review time.
- The release workflow still used outdated actions (`docker/login-action@v3`, `actions/upload-artifact@v4`); these were updated in `1.4.1`.
- Dependabot automation was not configured in-tree; `.github/dependabot.yml` was added for GitHub Actions and pip dependencies.
- During push, GitHub reported open Dependabot security alerts for `requests` and `cryptography` on the default branch; both were fixed immediately in a follow-up commit on `main`.

## Release Scope Chosen

- Imported the safe source-level modularization from the archive by extracting `/logs` and `/api/logs` into `app/routes/logs.py`.
- Kept the current `main` code path and health contracts intact.
- Verified behavior with targeted tests and a full test-suite run before release.
