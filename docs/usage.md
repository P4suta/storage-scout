# Storage-scout usage

Disk-usage scanner and safety-first build-artifact cleaner for Windows, macOS, and Linux.

Whole-artifact cleanup uses ownership and live writer locks.
It doesn't use age, modification times, or available disk space to grant deletion.

Waste is only what facts prove:

- a cache whose owner let it go, or whose worktree's work has landed (reaped whole);
- a file the tool that wrote it will never read again (pruned);
- bytes that already exist elsewhere on the volume (shared, losslessly).

Whole-artifact deletion refuses active, unclaimed, and kept ownership.

## Install

```sh
cargo install --locked --path crates/cli
```

## Usage

```sh
storage-scout scan ~/projects                     # usage report, with each artifact's owner
storage-scout clean ~/projects                    # pick artifacts to delete (dry-run by default)
storage-scout clean ~/projects --id <ID> --execute --yes
storage-scout prune ~/projects                    # remove files rustc never reads again (dry-run by default)
storage-scout dedupe ~/projects                   # share identical files between build outputs (dry-run by default)
storage-scout auto --execute                      # use configured roots or per-user defaults
storage-scout watch                               # stay resident and do the same the moment something changes
storage-scout explain <PATH> --phase reap         # why a directory is or is not deleted
storage-scout doctor                              # what this host protects
```

Add `--json` for machine-readable output (`schema_version: 3`).

## Managed stores

Inspect container resources or toolchains through their native management API.
Toolchain commands require all checkout roots whose pins must be preserved.

```sh
storage-scout stores --provider docker --include-tier reinstallable --json
storage-scout stores ~/projects --provider rustup --include-tier reinstallable --json
storage-scout stores ~/projects --provider mise --include-tier reinstallable --json
storage-scout stores ~/projects --provider rustup --include-tier reinstallable --id SHA256 --execute --yes --json
```

Execution accepts reviewed candidate IDs and revalidates each operation.
An incomplete reference survey or an unresolved dynamic pin prevents removal.
Rustup defaults, overrides, checkout pins, and tracked mise configuration protect Rust versions.
Mise also has to report an installation as prunable, and Rust installations are left to rustup.
Supported pin layouts include Rust toolchain files, Cargo `rust-version`, mise configuration and locks, task tools, and `lean-toolchain`.
Inspection disables automatic toolchain installation and project hook or environment evaluation.

Docker candidates describe all currently unused, untagged images or all currently unused build cache on the reviewed engine.
These are explicit predicates, so the engine rechecks current references atomically when it prunes.
Tagged images, volumes, and containers retain protection.
Engine-reported reclaimed bytes remain separate from physical host-volume reclamation.
The engine's detailed usage endpoint requires API 1.53 or later.

## Who owns an artifact

| Settlement | Meaning |
|---|---|
| `released` | a released owner marker with free locks, a forgotten worktree, or a live checkout release |
| `landed` | a clean git worktree whose work is already in the remote's default branch, or whose upstream branch is gone |
| `active` | a writer holds a lock, a worktree has unlanded or uncommitted work, or its primary checkout has no valid release |
| `kept` | a marker says a person kept it |
| `unclaimed` | nothing claims it |

`auto` and `watch` reap `released` and `landed` artifacts; `active`, `unclaimed`, and `kept` ones are never deleted.
A marker inside a directory protects it while its lock is held or it is kept, and never releases it.
The policy only says where to look:

```toml
[select]
roots = ["/Users/me/projects"]

[report]
log_file = "/Users/me/.local/state/storage-scout/auto.jsonl"
```

## Pruning what rustc never reads again

Inside a Cargo target that is still in use, these files are dead by rustc's own rules:

| Rule | What |
|---|---|
| `stale-object` | a debug object in `deps/`, `examples/`, or `build/*/` from an earlier rustc run, that the unit's linked image no longer names (macOS keeps these for the debugger) |
| `superseded-session` | an incremental session older than the one rustc loads next; rustc deletes it itself the next time it compiles that crate |
| `abandoned-session` | an incremental session whose rustc ended before finishing it |

Every cargo lock in the target is held while it is pruned, each session is taken under rustc's own session lock (`fcntl` on macOS, `flock` on Linux, `LockFileEx` on Windows), and each file is re-identified before it is removed.
A unit whose image cannot be read keeps all its objects.

## Sharing identical files

Parallel worktrees build the same dependencies into separate `target/` directories.
`dedupe` makes identical files share their blocks, so the bytes stay where the build expects them and the disk holds them once.

| Filesystem | How |
|---|---|
| APFS | clone the kept file next to the duplicate, carry its mode, times, and extended attributes over, and swap the two names atomically |
| btrfs, XFS | `FIDEDUPERANGE`: the kernel compares the bytes and shares them in place |
| others | not shared |

- Only Cargo targets and owner-marked directories take part: their writers take locks, and those locks are held while their files are rewritten.
- Every file is re-identified by handle and compared byte for byte at the moment it is shared; a swap that cannot be verified is undone.
- On APFS, executables and files with several names are left alone, since a replacement would be verified again by the system or split the names.
- Files under 64 KiB are not worth the work and are skipped.

## Running on events

`watch` is the resident form: run it as a login agent (launchd, systemd `--user`, a Task Scheduler logon task).
It keeps candidate surveys and the sharing inventory in memory, runs at background priority, and reacts only to what changed:

- a write inside a cache updates that cache's changed files, waits for its writer to release its lock, then prunes and shares only the affected work;
- an owner releasing its lock reaps what it owned;
- a new directory is examined when it appears, while a directory already walked is only re-listed for new children and evidence.

Filesystem events come from FSEvents on macOS, `ReadDirectoryChangesW` on Windows, and inotify on Linux.
Windows and Linux name the entry that appeared, vanished, or was written.
FSEvents names the changed directory, so macOS re-lists that directory shallowly; the operating system coalesces notifications for one second with `NoDefer` to keep the event stream responsive under build bursts.
That second is transport batching only: it neither makes a cleanup decision nor causes storage-scout to poll or wait before deciding.
On macOS, `watch` stores its sharing inventory and the last processed FSEvents ID in one durable transaction.
After a restart it replays intervening events and inventories only new or replaced candidates; missing history or malformed state is discarded and rebuilt automatically.
macOS and Windows observe every directory below their roots, while Linux registers every directory it walks and each repository's ref tree individually.
A ref update under `.git/refs`, `packed-refs`, `HEAD`, or `worktrees` invalidates only that repository's cached ownership answers.
Linux also uses git hooks for ownership changes known only to git:

```sh
storage-scout auto --execute --detach --event post-merge -- "$@"
storage-scout auto --execute --detach --event post-checkout -- "$@"
storage-scout auto --execute --detach --event reference-transaction -- "$@"   # stdin forwarded
```

Irrelevant events exit at once.
When a watcher is running, a hook records its repository and raises the flag, so only that repository's candidates are re-checked; a hook whose repository is unknown safely re-checks every candidate.
Without a watcher the hook starts one full `auto` run, and concurrent runs coalesce into one.
A manual `auto --execute` request always re-checks the whole policy, including when it hands work to a running watcher.

## Safety

- Only recognised artifacts are candidates: a `target/` next to `Cargo.toml`, a `CACHEDIR.TAG` directory, an owner-marked directory, and so on.
- System areas are never touched; application-owned areas (`~/Library`, `AppData`, `$TMPDIR`, …) admit only self-declared caches.
- Links, reparse points, and mount boundaries are never crossed; deletion walks by directory handle.
- Every candidate is re-checked immediately before deletion, and the locks of the tools that use it are held while it is removed.
- Sharing never changes a file's bytes, mode, or modification time, so builds do not see a change.

## Default roots and measurements

Without an implicit policy file, `auto` and `watch` use existing user cache, state, data, and temporary directories with the routine tier.
An explicit policy replaces those roots and tier grants.
An invalid or unreadable policy fails instead of enabling defaults.

Use `scan ROOT --measure both --min-size 0 --json` to include allocation and every measured directory.
Each volume reports its measured allocation, attributed bytes, unattributed remainder, and any overcount from shared allocation.
Attributed bytes plus the unattributed remainder equal the volume's sampled used bytes.
Logical-only scans leave physical allocation unattributed.
A partial measurement keeps the known byte count and reports its failure count.
Known cache layouts identify tools even when the cache has no deletion authority.

Predicted reclamation remains an estimate.
A rejected execution reports zero observed bytes.
After a mutation, observed physical reclamation is unknown because filesystem-wide free counters include other processes.

## Releasing a checkout

```sh
storage-scout release /path/to/checkout --json
```

The command records the release outside the checkout and starts a monitor.
A valid release requires the same directory identity and contents, a live monitor, and free writer locks.
A write revokes the release even if it restores the previous bytes.
Stopping the monitor also revokes the release.
Every ownership check asks the monitor to drain prior events and check the checkout again.

Only recognized build artifacts become candidates.
The release doesn't remove checkout source files.
Nested source checkouts protect ordinary build outputs, while released producer-owned scratch and cache trees keep their declared disposable scope.
SwiftPM and Gleam dependency checkouts remain within their managers' build directories.
Linked source worktrees retain protection in those directories.

Checkout release requires a synchronous filesystem event barrier.
The Windows backend refuses this operation.
Other cleanup commands retain their existing ownership gates.

## Applying several reviewed candidates

```sh
storage-scout clean /path/to/projects --id ID1,ID2,ID3 --execute --yes --min-size 0
```

The command discovers the roots once and revalidates each selected candidate before applying it.

## License

MIT OR Apache-2.0
