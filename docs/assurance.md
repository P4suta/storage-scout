# Cleanup assurance

Run `just check` for the fast checks and the assessed decision inventory.
Pull requests run that fast gate and cross-target checks.
Run `just assure` for repository checks, implementation proofs, model replay, and full mutation testing.
Run `mise run assure` for the proof, model, corpus, fuzz, and interpreter layers.
The assurance task resolves its own pinned tools and sets up Kani.
The runner reads the single Miri nightly pin from `tools/miri/rust-toolchain.toml` and installs that interpreter before use.
Mutation commands resolve pinned upstream `cargo-mutants` from the task configuration.
Their snapshots live in a private directory below the project's `target`, so temporary-directory protection cannot skip the cleanup tests.
Set `STORAGE_SCOUT_MUTATION_TMPDIR` to an absolute directory on a sharing filesystem when measuring native sharing.
The runner removes its scratch directory on return unless `--leak-dirs` requests preservation.
When mounting a checkout into a container, set `CARGO_TARGET_DIR` and `STORAGE_SCOUT_MUTATION_TMPDIR` to container-private directories.
The complete workspace baseline and mutation builds then use the container's own filesystem and writer locks.
Run `mise run mutants:dry` to record the catalog at `target/mutation-catalog.json`.
For one file, use `mise run mutants -- --no-config --file PATH`.
The adapter retains locked workspace tests when overriding the default file scope.
The release gate runs the full catalog and rejects missing results, missed mutants, timeouts, and a run with no detected mutations.
Its four fixed shards use the same source and filters, with at most two shards running together.
Build failures remain unviable outcomes, separate from detected mutations.
Only the host's backend files participate in native mutation testing.
Kani harnesses belong to the proof gate and don't compile into ordinary test binaries, so the mutation catalog excludes proof files and namespaces.
Cargo-mutants still has conditional-compilation and macro limitations, and native platform tests remain required.
On owner machines, run bounded verification through the installed container policy.
The manual or reusable release workflow also requires native OS tests, btrfs and XFS sharing, coverage, the minimum Rust version, and CodeQL on the same candidate.
It publishes verification artifacts, never a release.

| Layer | Contract and domain | Implementation link |
| --- | --- | --- |
| Kani and CBMC | All settlement and mandate pairs, ownership protection priorities, marker variants, linked-worktree evidence, lock presence, and sharing metadata | Production decision functions and the private deletion-grant constructor |
| Kani with Z3 | Saturating addition, subtraction, and three-term totals over the full `u64` domain | `Bytes` methods |
| Kani pipeline | Every refusal mask over the declared gates; identification and abstention | The production `pipeline` function |
| Kani pruning | Three distinct sessions, every working/finalized combination, full `u128` stamps, ties, and every 16-byte lock prefix | Production `doomed` and the lock-name helper |
| Kani gate checks | A failed, incomplete, or vacuous result must never pass | Production receipt-count validation |
| Kani managed stores | Every resource, reference, completeness, tier, and reviewed identity state; exact version reflexivity over every 16-byte sequence and normalization over every 17-byte sequence | Production managed clearance and the byte helpers used by the UTF-8 API |
| Quint and TLC | The complete finite reachable graph for one artifact's plan, owner/protection changes, one identity/content change, apply, and interruption between calls | Fresh ITF traces replay through `Scout::plan` and `Scout::apply` on real temporary files |
| cargo-fuzz | Seed 16, 1,024 executions per target, inputs up to 1,024 bytes | Core parsers and `AutoPolicy::parse`, with shared round-trip contracts and native corpus replay |
| Miri | Core unit-test executions under the pinned nightly's default checks | Production core functions; generated sysroot belongs to this run |
| Native checks and mutation | Filesystem, Git, leases, replacement, failure handling, and larger collections | Repository tests and pinned cargo-mutants |

The TOML inventory lists the exact public decision surface and each bounded proof domain.
Removing an inventory module, required result, corpus, or model fails the gate.
The gate copies the source and lockfiles into its own run directory and rejects a receipt when the source or tool configuration changes during verification.
Its negative control changes the production deletion predicate to admit every owner and requires an assertion counterexample from the expected harness.
Generated evidence lives under `target/assurance-*`; it includes the source fingerprint, verifier results, and model traces.

These layers don't prove the whole executable for every input or operating-system schedule.
Iterator composition, arbitrary-length names and collections, and native adapters also require the repository's tests and corpus checks.
The finite model treats an apply call as one operation and covers interruption between calls; native failure tests cover errors within the operation, without promising rollback of a partial deletion.
Filesystem identities, lock semantics, truthful ownership observations, and writers following their declared lock protocol remain external assumptions.
Git facts are read again for each deletion check instead of trusting the resident cache.
Ancestor owner locks join the lease, and a missing permanent owner lock never counts as free.
Freshness uses SHA-256-based fingerprints and assumes collision resistance; it doesn't prove an injective mapping from arbitrary file contents to a finite digest.
Managed reclamation trusts the native manager and engine APIs to operate on the requested installation or their atomic unused-resource predicate.
Checkout release additionally trusts native event delivery and barriers; inotify does not establish write-history coverage for memory-mapped writes.
Current-content fingerprints still detect changed bytes, but cannot establish that an unreported write occurred and was restored.
Windows checkout release and SwiftPM locking currently refuse unsupported native barriers or lock locations.

Verus would require a verified Rust dialect or a separate implementation refinement for this workspace.
Alloy or a Prolog policy model would need its own implementation binding and would overlap the selected decision and protocol checks.
Add either when a new relational or inductive obligation needs that capability, together with its source binding and a required gate.

Tool scope follows [Kani's supported Rust semantics](https://model-checking.github.io/kani/rust-feature-support.html), [Quint's model-checking semantics](https://quint.sh/docs/model-checkers), and [Miri's execution and platform limits](https://github.com/rust-lang/miri).
