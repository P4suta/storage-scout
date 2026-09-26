# Handoff: the resident watcher's CPU cost

Written 2026-09-26 when work stopped on branch `perf/work-follows-change`.
Updated 2026-09-27 after PR #11 merged and macOS restart state was implemented on `perf/persistent-watch-state`.
The completion update below supersedes the original remaining-work list, while the investigation is retained as history.

## Why this branch exists

After PR #8 (merged as `136abb1`) put `storage-scout watch` into production on all three machines, the user reported heavy CPU on every machine.
On Windows, Defender nearly hung, because files were created in bulk by development work and removed by storage-scout the moment they became safe.

Measured before this branch:

| Machine | Watcher CPU | Notes |
|---|---|---|
| Mac | 440 CPU-min in 9 h (about 0.8 of a core, all day) | the main thread was pegged in `Pool::share` |
| Linux | 184% average, 16.7 CPU-h in 9 h | every rayon worker busy; only one record per hour |
| Windows | 2,970 CPU-s since boot, while Defender (`MsMpEng`) spent 4,080 CPU-s | |

## Root causes found

1. `Pool::share` counted the lengths of every file in every stock on every write event, so the cost grew with the whole pool, not with the change.
2. A sighting surveyed (walked in full) every candidate it found, only to read nested markers.
   Saving one source file re-sighted the project and walked its whole `target`.
3. Sighting stat-ed every file of every directory it walked.
   On Windows each stat opens the file, and Defender inspects every open.
4. `process` walked the whole candidate up to three times per event batch: `busy::survey`, the prune pass's own survey, and dedupe's admission and full inventory.
5. Every change in a busy directory outside the candidates re-read all of that directory's subdirectories: `appear` sighted the parent with `Reach::Children`, which on `/tmp` or a domyjob root meant hundreds of `read_dir` calls per event.
6. Every git hook and every ref update ran `reown`, which surveyed every candidate.
   The per-turn `Scout::refreshed()` clone also threw away the git answers, so every worktree was asked again.
7. On Linux, a hook ran `resight`: a full walk of every root.
8. FSEvents dropped events (flags `UserDropped | MustScanSubDirs`).
   - Each drop became `Change::Lost`, and each `Lost` reprocessed every candidate in full, which starved the event queue again and caused the next drop.
   - Cause 1: the whole process, rayon workers included, ran at default QoS, so the dispatch queue that drains FSEvents was starved.
   - Cause 2: a latency of 0 sent one message per file operation.

## What the branch changes (uncommitted when work stopped, committed with this file)

- Events name the entry that changed and what happened: `Change::Entry { path, event: Event::{Appeared, Vanished, Written, Unsure} }` (`crates/cli/src/platform.rs`).
  - inotify and ReadDirectoryChangesW report entries.
  - FSEvents reports only the directory that changed (`Unsure`), coalesced over one second with `NoDefer` (`COALESCED` in `events_macos.rs`).
- Scanning (`scan.rs`):
  - a sighting no longer surveys the candidates it finds, nor stats files;
  - `sight_into(parent, (child, reach))` sights one directory with its parent as context;
  - every sighting returns `walked`, the directories outside candidates that it walked;
  - host tracking is gone.
- `auto::lets_go` and `auto::confirmed`: a settlement is confirmed from the candidate's own survey (locks free, nested markers) just before reaping.
  Deletion's gate still re-checks independently.
- The sharing pool (`dedupe.rs`):
  - keeps a live `lengths` index (`len -> {(root, relative)}`);
  - `Pool::note(root, &BTreeMap<PathBuf, Event>)` updates a stock per changed path, and an `Unsure` directory is re-listed shallowly;
  - `share` samples free space only on the volumes of the items it shares.
- Pruning (`prune.rs`): `run_changed(found, survey, Scope::Changed(paths), …)` reuses the watcher's survey and only touches the unit and object directories the changes lie under.
- The watcher (`watch.rs`):
  - Every candidate carries its cached survey, pending changes, whether it must be processed whole, and its git repository.
  - Outside candidates:
    - a new directory is examined with `Reach::Everything`;
    - a new or rewritten evidence file (`EVIDENCE`) re-checks its directory with `Reach::Children`;
    - an `Unsure` directory is re-listed, and only subdirectories not in `walked` are examined.
  - Inside a candidate, changes accumulate until its lock is free.
  - Ownership:
    - Git answers are kept across turns.
    - A ref change (`refs`, `packed-refs`, `HEAD`, `worktrees` under a `.git`) invalidates only that repository's worktrees and re-checks only its candidates.
    - A hook now writes its repository into the station flag (`Station::raise`), and the watcher reads it with `Station::take`.
  - A lost stream re-sights and marks each profile's `deps`, `incremental`, `build` and `examples` as changed, instead of reprocessing everything.
  - On Linux every walked directory and every repository's `.git/refs` tree is watched (about 53,000 of the 123,599 allowed watches).
    `Coverage::Partial` (ENOSPC) falls back to re-sighting on hooks.
  - All work runs at background priority (`platform::background`, also the rayon start handler); event intake stays above it (FSEvents queue at user-initiated QoS).
  - Debug tracing: `turn`, `process`, `examine`, and `lost` with its raw flag.
    Run `storage-scout -vv watch …` to see them.
- testkit: `remove_file`.

Measured on the Mac with the last build of this branch (other agents building heavily at the same time):
- Startup: about 4.5 CPU-min for the one-time full inventory of about 744 targets.
- The next 10 minutes: about 37% of a core on average, with long stretches at 0% and bursts.
  - 0 lost of 1,126 turns;
  - 257 partial processes, 0 whole;
  - 681 examined directories;
  - 55 ref turns and 3 hook turns.

Status of checks for the final code:
- Mac: `mise run check` passed (273 tests) and `mise run cross` passed.
- Linux: the suite passed on an earlier revision of this branch, not yet on the final code.
- Windows: an earlier revision hung in the watch integration test `a_cache_whose_key_is_gone_is_reaped_as_soon_as_a_hook_says_so`, and the final code has not been run there.

## Last known production state

Everything was stopped when this work began and was not reverified or changed during the repository work.

| Machine | Watcher | Policy | Installed binary |
|---|---|---|---|
| Mac | `launchctl disable gui/$UID/dev.dotfiles.storage-scout`, not loaded | `~/.config/storage-scout/auto.toml.paused` (hooks are no-ops without `auto.toml`) | an early build of this branch in `~/.cargo/bin` |
| Linux | `systemctl --user disable --now storage-scout.service` | `~/.config/storage-scout/auto.toml.paused` | main at `136abb1` |
| Windows | `Disable-ScheduledTask -TaskName storage-scout` | unchanged (Windows runs no storage-scout git hooks) | main at `136abb1` |

To resume, once a validated build is installed:
- Mac:
  1. `mv ~/.config/storage-scout/auto.toml.paused ~/.config/storage-scout/auto.toml`
  2. `launchctl enable gui/$(id -u)/dev.dotfiles.storage-scout`
  3. `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.dotfiles.storage-scout.plist`
- Linux: move the policy back, then `systemctl --user enable --now storage-scout.service`.
- Windows: `Enable-ScheduledTask -TaskName storage-scout; Start-ScheduledTask -TaskName storage-scout`.
- Install: `cargo install --locked --path crates/cli` on each machine.
  On Windows, stop the task and `storage-scout.exe` first, because the running exe is locked.

## Completion update

PR #11 merged the event-scoped watcher as `2fff2e7`.
Its CI passed the macOS, Linux, Windows, mutation, and CodeQL jobs, including the Windows watch test that had previously hung.
It added the directory-level `Unsure` tests, refreshed mutation claims, documented the one-second FSEvents transport batching, and updated the watcher documentation.

The macOS restart work on `perf/persistent-watch-state` adds a durable redb inventory paired atomically with the last processed FSEvents ID.
A warm restart restores only candidates whose current root identity still matches, replays historical events before normal processing, and inventories only new or replaced candidates.
`MustScanSubDirs`, dropped events, wrapped IDs, and changed roots discard the cache and establish a fresh pre-scan event boundary, while malformed or damaged state is rebuilt automatically.
Restored paths and file facts are decoded strictly, and every later sharing operation still re-identifies and compares the files at the moment of replacement.

The final local checks on the Mac passed:

- `mise run check`: 301 of 301 tests, formatting, Clippy, structural gates, bare-metal core, and documentation tests.
- `mise run cross`: Windows, macOS arm64, and Linux x86_64/arm64 Clippy checks.
- `cargo deny --offline check`: advisories, bans, licenses, and sources.
- CI-pinned `rust-mutants`: 298 changed-file mutants, 284 killed, 14 reasoned expectations, zero unexplained survivors, zero waits, and zero unreached mutants.

## Remaining external work

The required `domyjob` and `multi-machine` skills were unavailable in the working environment, so no direct SSH substitute was used and production remained untouched.
Once those skills are available:

1. Reverify that all three production watchers and policies are still stopped as recorded above.
2. After the persistence branch is merged, install the merged build on all three machines, restore each policy, and resume each watcher together.
3. Measure steady-state CPU on all three machines and Defender CPU on Windows with the merged build.
4. Profile any remaining bursts: new-duplicate hashing, shallow listing of large `deps` directories, and ordinary walks through rust-mutants scratch targets are the likely sources.
5. If Windows restart cost remains material, implement USN-journal-backed inventory persistence as a separately tested Windows change; Linux has no equivalent history.

## Related, outside this repository

- rust-mutants (in njutest):
  - ADR 0043 "a test may decline to measure" (njutest #207, in batch #209): once it is in a revision CI pins, bump `NJUTEST_REV` and make testkit write `<thread name>\t<stable why>` to `$RUST_MUTANTS_DECLINE_NOTICE`.
    Write only when a skip ends the whole test, and never with paths in the words.
  - Claims on files not compiled for the target become inapplicable automatically.
  - njutest #204 made repeat runs compile nothing.
- The local bare hub `~/git/njutest.git` lags GitHub and lacks the CI pin.
  Build rust-mutants from the njutest checkout at `NJUTEST_REV`.
