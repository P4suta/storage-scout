# storage-scout

Disk-usage scanner and safety-first build-artifact cleaner for Windows, macOS, and Linux.

It deletes what its owner has let go of, and nothing is decided by time: no ages, no mtimes, no schedules.

## Install

```sh
cargo install --locked --path crates/cli
```

## Usage

```sh
storage-scout scan ~/projects                     # usage report, with each artifact's owner
storage-scout clean ~/projects                    # pick artifacts to delete (dry-run by default)
storage-scout clean ~/projects --id <ID> --execute --yes
storage-scout dedupe ~/projects                   # share identical files between build outputs (dry-run by default)
storage-scout auto --execute                      # reap, share, and evict per ~/.config/storage-scout/auto.toml
storage-scout explain <PATH> --phase reap         # why a directory is or is not deleted
storage-scout doctor                              # what this host protects
```

Add `--json` for machine-readable output (`schema_version: 2`).

## Who owns an artifact

| Settlement | Meaning |
|---|---|
| `released` | an owner marker (`owner.json` + `owner.lock`) whose lock is free, or a worktree git has forgotten |
| `landed` | a clean git worktree whose work is already in the remote's default branch, or whose upstream branch is gone |
| `active` | a lock is held, a worktree has unlanded or uncommitted work, or it is the primary checkout |
| `kept` | a marker says a person kept it |
| `unclaimed` | nothing claims it |

`auto` always reaps `released` and `landed` artifacts.
When a `[trigger]` is set and free space is below `min_free`, it first shares identical files, then evicts `active` and `unclaimed` artifacts that nothing holds, cheapest to regenerate and largest first, measuring free space after each one until `target_free`.
`kept` is never deleted by `auto`.

```toml
[trigger]            # optional: without it, auto only reaps
volume = "/"
min_free = "40GiB"
target_free = "80GiB"

[select]
roots = ["/Users/me/projects"]
```

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

`auto` is meant to be started by events, not a schedule.
From git hooks:

```sh
storage-scout auto --execute --detach --event post-merge -- "$@"
storage-scout auto --execute --detach --event post-checkout -- "$@"
storage-scout auto --execute --detach --event reference-transaction -- "$@"   # stdin forwarded
```

Irrelevant events exit at once, and concurrent runs coalesce into one.

## Safety

- Only recognised artifacts are candidates: a `target/` next to `Cargo.toml`, a `CACHEDIR.TAG` directory, an owner-marked directory, and so on.
- System areas are never touched; application-owned areas (`~/Library`, `AppData`, `$TMPDIR`, …) admit only self-declared caches.
- Links, reparse points, and mount boundaries are never crossed; deletion walks by directory handle.
- Every candidate is re-checked immediately before deletion, and the locks of the tools that use it are held while it is removed.
- Sharing never changes a file's bytes, mode, or modification time, so builds do not see a change.

## License

MIT OR Apache-2.0
