---
date: 2026-10-23
---

# Attribute storage with lower bounds

## Status

Proposed.

## Context

A failed descendant measurement must not erase bytes already measured in its parent.
Concurrent filesystem activity makes a change in a volume-wide free-space counter unsuitable evidence for one cleanup operation.

## Decision

Carry known byte counts and a failure count through every aggregate measurement.
Report incomplete values as lower bounds and refuse to infer reclaimable bytes from them.
Reconcile measured physical allocation against each volume's used bytes, retain the unattributed remainder, and expose overcount separately.
Keep quota-available space separate from physical free space.
Report a known zero after a refused execution and unknown physical reclamation after a mutation whose effects cannot be isolated.
Keep container-engine reclamation in its own accounting domain.

## Consequences

Attributed bytes plus unattributed bytes equal the volume's used bytes without pretending that shared or overlapping measurements are exclusive ownership.
Known cache layouts identify tools even when their contents lack cleanup authority.
Manager-reported reclamation and image sizes are not added to host-volume free-space observations.
No cleanup decision depends on a clock or a free-space threshold.

See [byte decisions](../../crates/core/src/size.rs), [scan accounting](../../crates/cli/src/scan.rs), and [measurement](../../crates/cli/src/measure.rs).
