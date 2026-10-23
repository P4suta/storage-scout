---
date: 2026-10-23
---

# Use upstream mutation testing

## Status

Proposed.
This decision changes the mutation provider in [source-bound cleanup assurance](0001-source-bound-cleanup-assurance.md).

## Context

Cleanup verification needs observable evidence that tests detect changed behavior.
Its mutation engine must have a pinned upstream interface independent of personal assurance tooling.
Native cleanup tests also need scratch locations that admit the artifacts they exercise.
A host's temporary-storage protections can otherwise prevent those tests from reaching their intended gates.

## Decision

Use [cargo-mutants](https://github.com/sourcefrog/cargo-mutants) as the mutation engine.
Pin its version through the mise task and define the safety scope in [the upstream configuration](../../.cargo/mutants.toml).
Run workspace tests for each selected mutation.
Discover native modules through explicit path attributes and select backend files for the current host.
Proof harnesses stay in the Kani inventory and outside the native mutation catalog.

Keep the repository adapter limited to source snapshots, scratch ownership, process invocation, and native report validation.
Match every reported mutation to the generated catalog and require a successful baseline.
Require a nonempty completed run with detected mutations, and distinguish unviable builds from detected mutations.
Reject missed mutations, timeouts, duplicate or missing results, and stale source evidence.
Keep upstream filters available for development, and run the complete configured catalog at the release gate.

Don't transfer another instrumenter's expected outcomes into exclusions for this engine.
Keep the fast check in the local push hook and ordinary change workflow.
Keep full mutation and the other expensive assurance layers at the explicit release gate.

## Consequences

The project no longer needs an unreleased personal mutation provider or its configuration language.
Mutation catalogs and results from different engines remain incomparable without a new assessment.
The complete workspace campaign can be expensive, so a selected development run establishes evidence only for its recorded catalog.
Mutation testing complements the implementation proofs and native boundary tests in [the assurance contract](../assurance.md).
Coverage alone doesn't establish that tests detect a corrupted decision.
Cargo-mutants' [conditional-compilation limitations](https://mutants.rs/limitations.html) still require separate native platform checks.
