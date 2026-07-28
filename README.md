# storage-scout

Windows 10/11向けの高速な容量調査＋安全重視のビルド成果物クリーナー。

```powershell
cargo build --release
./target/release/storage-scout.exe --help
```

## Scan

`scan` は読み取り専用。reparse point / junction / symlink は辿らない。

```powershell
storage-scout scan D:\src
storage-scout scan D:\src --top 30 --min-size 100MiB --depth 2
storage-scout scan D:\src --measure both --json --strict
```

全オプションは `storage-scout scan --help` を参照。

## Clean

`clean` は既知の成果物だけを検出する。既定はdry-runで、対話選択も初期未選択。

```powershell
storage-scout clean D:\src
storage-scout clean D:\src --include-tier reinstallable --execute
```

リスク階層は `routine`、`reinstallable`、`expensive`。後二者は
`--include-tier` で明示するまで選択できない。

非対話削除は、直前のJSONに含まれる候補IDを指定した場合だけ許可される。

```powershell
storage-scout clean D:\src --json
storage-scout clean D:\src --id <SHA256> --execute --yes --json
```

任意パス削除や `--all` はない。実行直前にcanonical path、file ID、成果物証拠、
サイズ・更新時刻、reparse状態、除外、保護領域を再検証する。Windows、Program
Files、ProgramData、Users/profile root、AppData、cwd、実行バイナリは保護される。

`--measure both` / `clean` は論理サイズ、Windows割当サイズ、hard-linkを考慮した
解放見込みを分けて報告する。JSONは `schema_version: 1`。終了コードは成功・中断・
選択なしが0、検証/削除失敗が1、CLI構文エラーが2。

全オプションは `storage-scout clean --help` を参照。

## Development

```powershell
cargo fmt --check
cargo nextest run --all-targets --all-features
cargo test --doc --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

実削除テストはリポジトリ内のtest用一時ディレクトリだけを対象にする。

MIT OR Apache-2.0
