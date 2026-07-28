# Contributor rules

- 任意パス削除APIを作らない。削除は `ArtifactCandidate` → `CleanupPlan` → applyのみ。
- dry-runを既定にし、非対話削除には `--id --execute --yes` を要求する。
- 削除直前にidentity、証拠、usage/mtime、reparse、保護領域、除外を再検証する。
- reparse pointを辿らない。Windows/AppData/cwd/実行バイナリの保護を外さない。
- JSONの `schema_version: 1` を維持する。
- 実削除テストはリポジトリ内のtest用一時ディレクトリだけで行う。

```powershell
cargo fmt --check
cargo nextest run --all-targets --all-features
cargo test --doc --all-features
cargo clippy --all-targets --all-features -- -D warnings
```
