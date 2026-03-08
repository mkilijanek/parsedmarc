# Operations Runbook (dev)

This runbook addresses local tracking issues #26, #27 and #28 with deploy-time mitigations.

## #26 Graph transient failures

- Keep container restart policy enabled (`restart: unless-stopped`).
- Prefer short poll cycles over very large mailboxes to reduce long-lived connections.
- Collect and retain container logs; Graph failures are often intermittent network resets.
- If using Kubernetes, use restartable workload types and alert on crash-loop frequency.

## #27 `since` + `watch` performance

- Split operation into two phases:
- Backfill phase: finite `since` window, `watch = false`, explicit `batch_size`.
- Steady-state phase: `watch = true`, smaller mailbox, shorter check interval.
- Avoid first run against very large historical mailboxes with unbounded watch loops.

Recommended pattern:
1. Backfill historical window (`since = 7d`, tune `batch_size`).
2. Switch to steady state (`since = 1d`, `watch = true`).

## #28 sink failures and exit code safety

- Upstream may not always surface sink write failures as non-zero exit codes.
- For one-shot/batch executions, wrap parsedmarc with `scripts/run-parsedmarc-safe.sh`.
- The wrapper preserves parsedmarc output and forces non-zero exit for known sink error markers.
- The wrapper now preserves original non-zero parsedmarc exit codes when no sink marker is present.

Example:
```sh
./scripts/run-parsedmarc-safe.sh -c /home/parsedmarc/ini/parsedmarc.ini
```

Notes:
- The wrapper is a defensive mitigation, not a replacement for upstream fixes.
- Keep mailbox delete/move behavior conservative until sink reliability is verified.

Validation:
```sh
./scripts/test-run-parsedmarc-safe.sh
```
