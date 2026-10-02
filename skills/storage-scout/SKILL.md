---
name: storage-scout
description: >-
  Inspect project disk usage and manage build artifacts with the storage-scout CLI.
  Use for storage-scout requests or questions about build cache size, cleanup eligibility, dead rustc files, and sharing duplicate build outputs.
---

# storage-scout

Use the installed `storage-scout` command on the machine whose storage the user wants to inspect.
Check `storage-scout --version` and the relevant subcommand's `--help` when the installed version or options are uncertain.
If the command is missing, locate the source checkout and follow its install instructions instead of guessing a download source.

## Inspect

- Run `storage-scout scan ROOT --measure both --json` to inspect project disk use and ownership; use `--depth` when the question needs a deeper scan.
- Run `storage-scout doctor --json` to see host protections and policy warnings.
- Run `storage-scout explain PATH --phase reap --json` to learn whether automatic reaping admits a particular artifact; omit `--phase reap` to examine manual cleanup eligibility.
- Use the smallest roots that answer the request and pass `--exclude PATH` for areas the user excludes.

## Plan and apply

- `storage-scout clean ROOT --json` discovers manual cleanup candidates without deleting them.
  Take an ID from that result and run `storage-scout clean ROOT --id ID --json` to validate a specific dry run.
  A noninteractive manual deletion uses `storage-scout clean ROOT --id ID --execute --yes --json` after reviewing the selected path, ownership, and dry-run result.
- `storage-scout prune ROOT --json` previews rustc files that will not be read again.
  `storage-scout dedupe ROOT --json` previews identical build files that can share storage while remaining at their paths.
  Add `--execute` only when the requested work authorizes the proposed change.
- `storage-scout auto --config POLICY --json` previews the configured policy.
  Inspect the policy's roots before running `auto --execute` or starting the resident `watch` process.
  Automatic reaping covers `released` and `landed` artifacts; `active`, `unclaimed`, and `kept` artifacts are not reaped.

The CLI rechecks candidates and locks when applying changes, so a dry run is evidence for a decision rather than a promise that execution will succeed.
Do not broaden roots or add `--include-tier` to overcome a refusal without examining the reason and the user's intended scope.
Treat `explain` exit code 1 as an ineligible result and `doctor` exit code 1 as a warning; read their output before diagnosing a command failure.
For machine-readable results, check `schema_version` and report the operation, affected paths or IDs, bytes reported by the CLI, and any refusals or failures.
