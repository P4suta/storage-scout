# storage-scout

Disk-usage scanner and safety-first build-artifact cleaner for Windows, macOS, and Linux.

It removes waste the moment it is waste, and nothing else.
Nothing is decided by time or by how full the disk is: no ages, no mtimes, no schedules, no thresholds.

Waste is only what facts prove:

- a cache whose owner let it go, or whose worktree's work has landed (reaped whole);
- a file the tool that wrote it will never read again (pruned);
- bytes that already exist elsewhere on the volume (shared, losslessly).

Anything someone still owns is never deleted, however full the disk gets.

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
storage-scout auto --execute                      # reap, prune, and share once, per ~/.config/storage-scout/auto.toml
storage-scout watch                               # stay resident and do the same the moment something changes
storage-scout explain <PATH> --phase reap         # why a directory is or is not deleted
storage-scout doctor                              # what this host protects
```

Add `--json` for machine-readable output (`schema_version: 3`).

## Who owns an artifact

| Settlement | Meaning |
|---|---|
| `released` | an owner marker (`owner.json` + `owner.lock`) whose lock is free, or a worktree git has forgotten |
| `landed` | a clean git worktree whose work is already in the remote's default branch, or whose upstream branch is gone |
| `active` | a lock is held, a worktree has unlanded or uncommitted work, or it is the primary checkout |
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

## Safety

- Only recognised artifacts are candidates: a `target/` next to `Cargo.toml`, a `CACHEDIR.TAG` directory, an owner-marked directory, and so on.
- System areas are never touched; application-owned areas (`~/Library`, `AppData`, `$TMPDIR`, …) admit only self-declared caches.
- Links, reparse points, and mount boundaries are never crossed; deletion walks by directory handle.
- Every candidate is re-checked immediately before deletion, and the locks of the tools that use it are held while it is removed.
- Sharing never changes a file's bytes, mode, or modification time, so builds do not see a change.

## License

MIT OR Apache-2.0
