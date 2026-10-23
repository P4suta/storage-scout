# Source-bound cleanup assurance

## Status

Proposed.

## Context

Cleanup authority must follow the current owner, protected location, identity, contents, and writer locks.
An explicit selection can't release ownership.
A detached model can't establish that the production code follows its rules.

## Decision

Keep cleanup decisions in the existing pure Rust core.
Require an opaque deletion grant inside a `Clearance`, after the gate pipeline, and prove the grant's constructor over every settlement and mandate.
Use Kani for production decision contracts, Z3 for the integer obligations, and Quint with TLC for the finite plan/apply protocol.
Replay model traces through the native public API, keep corpus and Miri checks, and preserve the existing mutation gate.
Read ownership facts afresh at deletion and include ancestor owner locks in every mutating operation's survey.
Use the existing Rust xtask to enforce the public decision inventory, required results, negative control, and source identity.

## Consequences

Manual and automatic cleanup both refuse active, kept, and unclaimed artifacts.
Inspection and interactive selection follow the same ownership rule.
The watcher retains its survey and sharing stocks, while a deletion check reads fresh Git facts.
Verifier artifacts and Miri sysroots belong to a checkout's individual run.
The assurance contract states finite proof bounds and external assumptions instead of treating tests or model checking as a whole-program theorem.

See [the enforced inventory](../../assurance.toml), [the gate](../../xtask/src/assurance.rs), and [the verification domains](../assurance.md).
