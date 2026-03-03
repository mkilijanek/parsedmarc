# Upstream Tracking (dev)

This file tracks upstream `domainaware/parsedmarc` issues/PRs that are relevant to this containerized repository (`mkilijanek/parsedmarc`).

## Selected upstream items

1. Upstream issues #593 and #479 (MS Graph transient failures)
- Problem: intermittent Graph connection resets can crash processing loops.
- Relevance here: this image is commonly used with long-running mailbox polling; unexpected exits reduce reliability.
- Action in this repo: track and align runtime guidance/health behavior once upstream publishes a robust retry strategy.

2. Upstream issues #581 and #584 (`since` + `watch` behavior/performance)
- Problem: `since` filtering and mailbox polling behavior can be surprising or slow for large mailboxes.
- Relevance here: directly impacts operators running this image against O365/IMAP.
- Action in this repo: track upstream fix status and document safe configuration defaults/workarounds.

3. Upstream issues #574 and #367 (exit status on sink failures)
- Problem: failures writing to downstream systems may not consistently return non-zero status.
- Relevance here: container orchestrators depend on process exit codes for reliability and data safety.
- Action in this repo: track upstream behavior and provide defensive runbook guidance.

4. Upstream PR #659 (DMARCbis support and forensic->failure terminology)
- Problem/Change: major schema and naming updates are incoming.
- Relevance here: affects release messaging, compatibility notes, and potentially default docs/config examples.
- Action in this repo: prepare migration note once upstream change merges and ships.

## Out-of-scope upstream PRs for now

- PR #658 and #650 (Google SecOps integrations) are feature additions in upstream core project and do not require immediate changes in this container wrapper repository.
