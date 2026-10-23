---
date: 2026-10-23
status: proposed
---

# Default user artifact roots

## Status

Proposed.

## Context

A fresh installation needs useful discovery without requiring a policy file.
Missing configuration must not be confused with malformed or explicitly requested configuration.
Default discovery must not change reclamation authority.

## Decision

When the implicit policy file is absent, discover existing user cache, state, data, and temporary directories.
Include the native macOS and Windows user areas and the XDG user directories used by command-line tools.
Ignore absent standard directories and reject unreadable or invalid user areas.
Use the routine tier and the existing settled-ownership and writer-lock gates.

An existing policy replaces these defaults.
An explicitly named missing file or an invalid policy remains an error.
Keep explicit and implicit configuration distinct when forwarding a detached invocation.
Use the implicit policy's absolute path as its coordination namespace without creating a policy file.

## Consequences

Automatic cleanup and the resident watcher share the same configuration selection.
A dry run does not install configuration or grant authority over active or unclaimed artifacts.
Known artifact layouts and existing external ownership declarations remain the recognition boundary.
Native integration tests use isolated user environments and real temporary artifacts.
The operating system's user-directory conventions and cooperative writer locks remain external assumptions.
