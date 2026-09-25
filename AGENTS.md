# Contributor rules

## Structure

- `crates/core` is `#![no_std]` and `#![forbid(unsafe_code)]`: every decision lives there and receives facts as plain data.
  `mise run pure` builds it for bare metal to prove it cannot do I/O or read a clock.
- `crates/cli` is the shell: `platform` makes system calls, `observe`/`measure`/`busy`/`owners` read facts, `apply` deletes, `dedupe` shares identical files, `hook`/`coalesce`/`store` start and coordinate runs, the rest is CLI and rendering.
- Ownership decides what `auto` may take: `released`/`landed` are reaped, `active`/`unclaimed` are evicted only under a trigger, `kept` never.
  Git is read through typed queries in `observe::git` with fsmonitor off and never writes.
- `crates/testkit` builds fixtures; `xtask` enforces the structural rules (`cargo xtask gates`).

## Rules the build enforces

- No comments.
  The only exception is a `// SAFETY:` line on an `unsafe` block, and `unsafe` exists only in `crates/cli/src/platform`.
- Deletion is a capability: `apply::capability::Authorized` holds a `Clearance` (minted only by `core::gate::clear` after the whole `PIPELINE`) and the `Lease` on every lock the tool uses.
  `remove_tree` is reachable only from it.
- Sharing is a capability too: `dedupe::capability::Shareable` holds a `ShareClearance` (minted only by `core::gate::clear_share`) and the `Lease`.
  `platform::Tree` rewrites files only through it, re-identifying each file by handle and comparing it byte for byte at that moment.
- `Gate` declaration order is the pipeline, and `share::PairGate` order decides which pairs of files may share.
  A new rule is a new variant; every gate matches every question exhaustively.
- No wildcard matches on our enums, no `Result::ok`/`unwrap_or`/`map_or`, no `Path::exists`, no bool parameters, no `HashMap`/`HashSet`.
- No time: clocks and file times are banned by `clippy.toml`.
  The one exception is `platform`, which carries a duplicate's times unchanged onto its replacement.
- Untrusted input (`auto.toml`, `owner.json`) is decoded only in `ingress`; files storage-scout writes are opened only in `store`; processes start only in `observe::git` and `platform::spawn`.
- Runs are started by events (`--event`, `--detach`) and coalesce on a lock and a flag; nothing waits on a clock.
- Refusals are `Rejection` values; tests match them with `matches!`.
- JSON is `schema_version: 2`; fields are only added within a version (`tests/schema/v2.json`).

## Tests

- Real deletion happens only under temporary directories inside the repository (`testkit::tempdir`).
- OS differences go through `testkit` (`Built::Unavailable`), never `#[cfg]` on a test.
- Every surviving mutant is either a missing test or a claim with a reason in `.rust-mutants.toml`.
  `question-to-unwrap` is not measured: it turns a reported refusal into a panic, and both stop before anything changes.
  `ignore-question-statement` and `return-ok-default` are, because they turn a failure into success.
- Pull requests measure only the files they change, on btrfs so sharing runs; `STORAGE_SCOUT_REQUIRE_SHARING=1` makes the sharing tests fail instead of skipping.
  Full measurement is local: `mise run mutants`, and `mise run verify` for the whole contract.

```sh
mise run check     # fmt, clippy, gates, pure, tests, doctests
mise run cross     # clippy for Windows, macOS, and Linux targets
mise run mutants          # mutation testing, every file
mise run mutants:branch   # only what this branch changes, as a pull request does
```
