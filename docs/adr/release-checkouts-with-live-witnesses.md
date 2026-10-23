---
date: 2026-10-23
---

# Release checkouts with live witnesses

## Status

Proposed.

## Context

A primary checkout has no worktree-removal event that releases its artifacts.
Persisting a permanent release flag would also authorize cleanup after development resumes.

## Decision

Require an explicit checkout release backed by a live native filesystem monitor, directory identity, current-content fingerprint, and free producer locks.
Start monitoring before recording the baseline and synchronize event delivery before validating a release.
Keep records and the private local query channel outside the checkout.
Revoke a release on a reported write, incomplete event coverage, a changed fingerprint, or monitor exit.
Keep artifact recognition, nested source protection, and deletion leases unchanged in authority.
Refuse unsupported event barriers instead of interpreting a missing monitor as release evidence.

## Consequences

Release is temporary authority for recognized artifacts and never authority to remove checkout sources.
The private Unix channel is restricted to the current user and remains cancellable when a client is idle.
Native event delivery, producer lock compliance, and SHA-256 collision resistance remain external assumptions.
Inotify does not establish history coverage for memory-mapped writes that restore their previous bytes.
Current-content fingerprints detect changed bytes but cannot recover such missing history.
Windows release remains unsupported until its native synchronization contract is implemented and tested.

See [the release adapter](../../crates/cli/src/release.rs), [the evidence decision](../../crates/core/src/ownership.rs), and [native ownership tests](../../crates/cli/tests/ownership.rs).
