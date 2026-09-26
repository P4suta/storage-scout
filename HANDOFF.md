# Handoff: the resident watcher's CPU cost

Written 2026-09-26 when work stopped on branch `perf/work-follows-change`.
Updated 2026-09-27 after PR #12 merged, the validated build was deployed on all three machines, and production measurements were completed.
The completion and rollout updates below supersede the earlier production-state table and remaining-work list, while the investigation is retained as history.

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

## Production state before the final rollout

This table is historical.
Everything was stopped when the repository work began and had not yet been reverified.

| Machine | Watcher | Policy | Installed binary |
|---|---|---|---|
| Mac | `launchctl disable gui/$UID/dev.dotfiles.storage-scout`, not loaded | `~/.config/storage-scout/auto.toml.paused` (hooks are no-ops without `auto.toml`) | an early build of this branch in `~/.cargo/bin` |
| Linux | `systemctl --user disable --now storage-scout.service` | `~/.config/storage-scout/auto.toml.paused` | main at `136abb1` |
| Windows | `Disable-ScheduledTask -TaskName storage-scout` | unchanged (Windows runs no storage-scout git hooks) | main at `136abb1` |

The final installation-and-resume phase used this sequence:

- Install: `cargo install --locked --force --path crates/cli` on each machine.
  On Windows, stop the task and `storage-scout.exe` first, because the running exe is locked.
- Mac:
  1. `mv ~/.config/storage-scout/auto.toml.deploy-paused ~/.config/storage-scout/auto.toml`
  2. `launchctl enable gui/$(id -u)/dev.dotfiles.storage-scout`
  3. `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.dotfiles.storage-scout.plist`
- Linux: move `auto.toml.deploy-paused` back to `auto.toml`, then `systemctl --user enable --now storage-scout.service`.
- Windows: `Enable-ScheduledTask -TaskName storage-scout; Start-ScheduledTask -TaskName storage-scout`.

## Completion update

PR #11 merged the event-scoped watcher as `2fff2e7`.
Its CI passed the macOS, Linux, Windows, mutation, and CodeQL jobs, including the Windows watch test that had previously hung.
It added the directory-level `Unsure` tests, refreshed mutation claims, documented the one-second FSEvents transport batching, and updated the watcher documentation.

The macOS restart work on `perf/persistent-watch-state` adds a durable redb inventory paired atomically with the last processed FSEvents ID.
A warm restart restores only candidates whose current root identity still matches, replays historical events before normal processing, and inventories only new or replaced candidates.
`MustScanSubDirs`, dropped events, wrapped IDs, and changed roots discard the cache and establish a fresh pre-scan event boundary, while malformed or damaged state is rebuilt automatically.
Restored paths and file facts are decoded strictly, and every later sharing operation still re-identifies and compares the files at the moment of replacement.
PR #12 merged that work as `4d3af23`.

The final local checks on the Mac passed:

- `mise run check`: 301 of 301 tests, formatting, Clippy, structural gates, bare-metal core, and documentation tests.
- `mise run cross`: Windows, macOS arm64, and Linux x86_64/arm64 Clippy checks.
- `cargo deny --offline check`: advisories, bans, licenses, and sources.
- CI-pinned `rust-mutants`: 298 changed-file mutants, 284 killed, 14 reasoned expectations, zero unexplained survivors, zero waits, and zero unreached mutants.

## Production rollout completed

The external work was completed from merged `main` at `4d3af23` on 2026-09-27.
The completed `domyjob` build was installed on the Mac first because the older local client treated the completed audit entry's `epoch` field as malformed.
The compatible build read both peer logs without changing or rewitnessing them, and `domyjob doctor` then reported matching healthy Linux and Windows peers.

The preflight found that Windows and the Mac watcher were stopped, but Linux had unexpectedly been active for 3 hours 20 minutes and had already consumed 9 hours 30 minutes of CPU.
Linux was disabled and stopped, and the Mac and Linux policies were moved to `auto.toml.deploy-paused` so hooks could not start work during validation.
The active and older `.paused` copies were byte-for-byte identical on each machine, and the active copy was restored after installation.

The same working tree passed the OS-specific code checks before installation:

- Linux: formatting, Clippy, structural gates, the bare-metal core build, 298 of 298 tests, and documentation tests.
- Windows: formatting, Clippy, structural gates, the bare-metal core build, 297 of 297 tests, and documentation tests.
- The full Linux wrapper's only failure was `actionlint` looking for a Git worktree inside domyjob's source snapshot.
- The full Windows wrapper's only failure was the machine's Scoop `typos` shim failing to start; the platform-independent repository lint had already passed on the Mac and in CI.

`cargo install --locked --force --path crates/cli` replaced the binary on all three machines while every watcher remained stopped.
The installed hashes changed from `00b36020…` to `8d4e5527…` on the Mac, `d40f8f78…` to `9958a3ff…` on Linux, and `907da006…` to `6d14b549…` on Windows.
The policies and watchers were then resumed in one parallel phase.

The final production state is:

| Machine | Watcher | Policy | Installed binary |
|---|---|---|---|
| Mac | LaunchAgent enabled and running | `~/.config/storage-scout/auto.toml` active | merged `4d3af23` build |
| Linux | user service enabled and active | `~/.config/storage-scout/auto.toml` active | merged `4d3af23` build |
| Windows | scheduled task enabled and running, with one watcher process | policy active | merged `4d3af23` build |

A final health check reconfirmed those states, active policies, the absence of `auto.toml.deploy-paused`, version `0.4.0`, and the installed hashes above.
The audited remote checks succeeded as `linux:50SP7K9NS9WRCS6W` and `win:EENC1M3C6AS99R8X`.

## Production measurements

Linux used no measurable CPU in a 30-second steady-state window.
Its first start completed in about 4 seconds and used about 12 CPU seconds, after which its cumulative CPU advanced only with real changes.

Windows used no measurable watcher CPU in a 30-second steady-state window, and Defender used no measurable CPU in the same window.
A controlled Windows restart reached CPU quiescence in 36.6 seconds, used 41.625 watcher CPU seconds, and added 0 Defender CPU seconds.
The latest start watched 154 candidates and changed nothing.
That one-time login or reboot cost did not reproduce the former continuous load or Defender amplification, so USN-journal persistence is not justified by the production measurement.
It remains a separate future change only if a user-visible restart cost is later demonstrated.

The Mac's first production start created the persistent inventory while several unrelated builds were active.
It reached `start` in 7 minutes 44 seconds after using 6 minutes 53 seconds of CPU, watched 738 candidates, and changed nothing.
The redb state later occupied 209,027,072 bytes, about 199 MiB, for about 740 candidates.

Other agents continuously started rust-mutants campaigns and ordinary Cargo builds throughout the Mac observation, so a whole 30-second production window with no external writes was not available.
The watcher nevertheless reached exact 0% intervals between turns.
During sustained mutation churn, representative 30-second windows used 20.1% and 24.9% of one core, rather than the pre-fix continuous load of about 80% of one core.
Startup and accumulated-event windows were higher and are not steady-state measurements.

A 10-second sample during a Mac burst put the main thread in directory discovery: 5,337 samples in `fstatat`, 962 in `getdirentries64`, and 371 in `getattrlist`.
Open handles named rust-mutants scratch targets, njutest pre-push targets, and ordinary project targets rather than a whole-pool hashing loop.
This confirms that remaining bursts are the expected walks that discover newly created build trees, while idle work is absent.

A Mac restart in the middle of an active turn exercised the durable checkpoint and FSEvents history path under three simultaneous build and mutation workloads.
The new process opened the existing redb state, replayed the interrupted changes, pruned 8,774 entries totaling 776.1 MiB, shared 257 files totaling 93.6 MiB, and reached `start` after 361 seconds without losing the service or policy.
That is an extreme-load recovery measurement, not an idle warm-start benchmark.

## Related work completed outside this repository

njutest batch #209 landed ADR 0043, "a test may decline to measure", and storage-scout PR #11 pinned `NJUTEST_REV` to that batch at `937da69`.
The testkit writes `<thread name>\t<stable why>` to `$RUST_MUTANTS_DECLINE_NOTICE` only when an unavailable capability ends the whole test, and its tests enforce that paths do not enter the stable reason.
The pinned njutest also makes claims on files not compiled for a target inapplicable automatically, while njutest #204 prevents repeat runs from recompiling unchanged code.
The final mutation campaign above used that CI-pinned revision.

The local bare hub `~/git/njutest.git` was fast-forwarded from `58e0a68` to GitHub `main` at `f0084f1`.
The pinned `937da69` commit is present and is an ancestor of that hub's `main`.

No actionable work remains from this handoff.
