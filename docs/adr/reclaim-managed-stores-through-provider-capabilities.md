---
date: 2026-10-23
---

# Reclaim managed stores through provider capabilities

## Status

Proposed.

## Context

Toolchain installations and container stores have reference rules that a filesystem deletion cannot enforce.
Removing an image by its reviewed ID can also race with a new tag or container reference.

## Decision

Attribute managed resources separately and require an explicit review with the reinstallable tier.
Mint an opaque core clearance only for a current, complete, unreferenced resource.
Re-read checkout pins, manager configuration, installation identity, and manager reference state before toolchain removal.
Use rustup for Rust installations and mise for its other installations, preserving unresolved and externally linked installations.
Read project configuration as data and disable manager hooks, environment evaluation, and automatic installation.
Bind container operations to one local endpoint and engine identity.
Review the engine's atomic unused-image or unused-build-cache predicate rather than promising a fixed set of object IDs.
Provide no volume or container removal capability.

## Consequences

Unknown configuration, incomplete manager output, and a changed installation prevent removal.
The supplied checkout roots define the checkout reference scope; tracked manager configuration adds references outside that scope.
Dynamic version requests remain protected when they cannot be resolved without executing configuration.
Engine usage requires API 1.53 or later and reports shared resource sizes without summing them as exclusive host allocation.
The engine rechecks tags and container references inside its pruning operation.
Native manager and engine behavior remains an external trust assumption, while source gates confine the mutators to their capability adapters.

See [managed decisions](../../crates/core/src/managed.rs), [provider coordination](../../crates/cli/src/managed.rs), and [the engine adapter](../../crates/cli/src/platform/engine.rs).
