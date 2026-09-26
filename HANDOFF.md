# Handoff: the resident watcher's CPU cost

Written 2026-09-26 when work stopped on branch `perf/work-follows-change`.
Everything still to do is in this file; nothing lives in agent memory.

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

## Production state when work stopped

Everything is stopped and will not restart by itself.

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

## Remaining work, in order

1. Verify the final code on all three machines.
   - Run `domyjob run linux,win -- cargo test --workspace --locked`.
   - Investigate the Windows hang in `a_cache_whose_key_is_gone_is_reaped_as_soon_as_a_hook_says_so` (`crates/cli/tests/watch.rs`) if it recurs.
   - Hooks now carry a repository.
     - In a domyjob workspace there is no `.git`, so the flag is empty and the watcher re-checks every candidate.
     - When the flag carries a repository, candidates outside it are not re-checked.
2. Add unit tests for the directory-level (`Unsure`) path, which is what macOS delivers: `Session::targets` diffing against `walked`, evidence re-checks, and `Pool::note` with an `Unsure` directory whose subdirectory vanished.
   The current watch unit tests mostly drive entry-level events.
3. Measure steady-state CPU again on all three machines, and profile the remaining bursts.
   - On the Mac, build with `CARGO_PROFILE_RELEASE_STRIP=none` and resolve `sample` addresses with `atos`.
   - On Linux, `perf` and ptrace are blocked (`perf_event_paranoid=4`, `ptrace_scope=1`), so use the debug trace.
   - Likely remaining costs:
     - hashing new duplicate candidates;
     - shallow re-listing of large `deps` directories on every change in them;
     - examining new directories inside rust-mutants scratch targets (`…/rust-mutants-target-*/pristine`), which are not recognised as Cargo targets and so are walked as ordinary directories.
4. On Windows, check Defender's CPU with the new build, which runs at thread background mode and no longer opens every file during sightings.
5. Decide on the FSEvents coalescing latency.
   - `COALESCED = 1.0` seconds is an OS batching parameter.
     It decides nothing, but AGENTS.md says nothing waits on a clock.
   - Either document why it is allowed, or find another way to stop `UserDropped` under load (the background priority split alone did not stop it).
6. Startup still pays a full inventory of every target (4 to 6 CPU-min on the Mac) on every watcher start.
   - macOS: FSEvents can replay events since a stored event id.
   - Windows: the USN journal can do the same.
   - Persisting the pool with the last event id would make a restart proportional to what changed while it was down.
     Linux has no such history.
7. Mutation-testing configuration (`.rust-mutants.toml`) is stale for the rewritten code.
   - Line skips: `watch.rs` 344 (refresh no longer exists), `dedupe.rs` 369, `unix.rs` 232/260–264/268/446/561/568, and `events_linux.rs` 130.
   - Claims about `Session::lets_go`, `Session::refresh`, `Session::written`, `Session::appear`, `Session::turn`, `Session::follow`, `remember_hosts` and `follow_hosts` refer to functions that were renamed or removed.
   - Run `rust-mutants run --changed-from origin/main` on the Mac (with `STORAGE_SCOUT_REQUIRE_SHARING=1`) and on Linux (from the pinned `NJUTEST_REV` build), then re-anchor.
8. Update README and AGENTS.md: entry-level events, directory-level FSEvents with coalescing, background priority, repository-scoped ownership refresh, and hooks carrying their repository.
9. Commit in reviewable pieces if possible, open a PR, let CI (including btrfs mutation testing) pass, merge, reinstall on all three machines, and resume as above.

## Related, outside this repository

- rust-mutants (in njutest):
  - ADR 0043 "a test may decline to measure" (njutest #207, in batch #209): once it is in a revision CI pins, bump `NJUTEST_REV` and make testkit write `<thread name>\t<stable why>` to `$RUST_MUTANTS_DECLINE_NOTICE`.
    Write only when a skip ends the whole test, and never with paths in the words.
  - Claims on files not compiled for the target become inapplicable automatically.
  - njutest #204 made repeat runs compile nothing.
- The local bare hub `~/git/njutest.git` lags GitHub and lacks the CI pin.
  Build rust-mutants from the njutest checkout at `NJUTEST_REV`.
