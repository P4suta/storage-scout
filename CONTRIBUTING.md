# Contributing

The rules the build enforces, and how to check a change, are in [AGENTS.md](AGENTS.md).

- Run `mise run check` before pushing; `mise run cross` if you touched `platform`.
- Pull requests are squash-merged; the title becomes the commit subject, in Conventional Commits form.
- A change to what storage-scout deletes or rewrites needs a test that fails without it.
