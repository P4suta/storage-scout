---
date: 2026-10-23
status: proposed
---

# Unlink descendant symbolic links

## Status

Proposed.

## Context

Build outputs and dependency directories commonly contain symbolic links.
Rejecting every descendant link prevents otherwise eligible artifacts from being cleaned.
Following a link would cross the artifact's deletion boundary.

## Decision

Keep linked roots and linked candidates ineligible.
Measure descendant links themselves without visiting their targets.
Bind their names, stored destinations, and identities into the candidate fingerprint.
Read the same facts during discovery and apply-time measurement.
Continue to require the existing ownership, exclusion, identity, freshness, and writer-lock checks.

Unix deletion already unlinks non-directory entries relative to an open parent descriptor.
Windows removes directory reparse points with `RemoveDirectory` and file reparse points with file deletion.
Link deletion never retries by changing permissions, because permission changes could affect a referent.

Blanket refusal loses reclaimable artifacts without strengthening the existing no-follow deletion boundary.
Resolving link destinations or deleting them would grant authority beyond the selected artifact.

## Consequences

External, internal, dangling, and cyclic links do not by themselves prevent cleanup.
Adding, removing, or retargeting a link invalidates a previously discovered candidate.
Changing a referent does not invalidate the candidate or grant authority to modify that referent.
The existing SHA-256 collision-resistance and cooperative writer-lock assumptions still apply.

The changed boundary depends on native filesystem semantics rather than a new pure authorization decision.
Regression tests exercise production discovery, dry runs, capability-based deletion, and automatic reaping on real temporary files.
They check referent bytes and permissions, stale plans, root-link rejection, and dependency executable links.
These checks cover the adapter's exercised executions rather than proving every operating-system interleaving.

See [Rust's no-follow metadata operation](https://doc.rust-lang.org/std/fs/fn.symlink_metadata.html), [link reading](https://doc.rust-lang.org/std/fs/fn.read_link.html), and [Windows junction deletion](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-removedirectoryw).
