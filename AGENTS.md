# Contributor rules

- 任意パス削除APIを作らない。削除は `ArtifactCandidate` → `CleanupPlan` → applyのみ。
- dry-runを既定にし、非対話削除には `--id --execute --yes` を要求する。
  例外は `auto` だけで、その二重ロックは「TOMLポリシーが削除範囲を宣言している」
  ことと「`--execute` が明示されている」こと。選ぶ候補は純関数 `decide` が決める。
- 削除直前にidentity、証拠(kind と provenance)、usage/mtime、reparse、保護領域、
  除外、使用中(busy)を再検証する。
- 証拠は2軸: kind(何か)と provenance(誰が保証するか)。`declared` は
  `CACHEDIR.TAG`(署名検証)か `.rustc_info.json` + profile ディレクトリ。
  `AppData` 等のアプリ所有領域では `declared` しか候補にしない。
- reparse pointを辿らない。Windows/Program Files/ProgramData/profile root/cwd/
  実行バイナリの保護を外さない。
- JSONの `schema_version: 1` を維持する。フィールドは追加のみ。
- 実削除テストはリポジトリ内のtest用一時ディレクトリだけで行う。
  `AppData` 配下を使うテストは discovery/dry-run に限る。

```powershell
cargo fmt --check
cargo nextest run --all-targets --all-features
cargo test --doc --all-features
cargo clippy --all-targets --all-features -- -D warnings
```
