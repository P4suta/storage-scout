# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.
Report them privately through GitHub: <https://github.com/P4suta/storage-scout/security/advisories/new>

Include the affected version or commit, how to reproduce it, and what you observed.
You will get an acknowledgement within a week; fixes ship as a new release with a security advisory.

## Supported versions

Only the latest release receives security fixes.

## Scope

storage-scout deletes directories and rewrites files it judges safe to share.
In scope: deleting or rewriting anything outside a cleared candidate, following a link or crossing a mount, acting while a tool holds a candidate's lock, changing a shared file's bytes or metadata, and acting on untrusted input (`auto.toml`, `owner.json`) beyond what it declares.
