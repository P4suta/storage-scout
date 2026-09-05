# storage-scout

Windows 10/11向けの高速な容量調査＋安全重視のビルド成果物クリーナー。
空き容量しきい値で自動的に回収する `auto` を備え、スケジュールタスクから無人運転できる。

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

## 検出の仕組み

成果物は「何か(kind)」と「誰が保証するか(provenance)」の2軸で認証する。

- `inferred`: ディレクトリ名と隣接するプロジェクトマニフェストが一致する
  (`target` + `Cargo.toml`、`node_modules` + `package.json` など)。
- `declared`: ディレクトリ自身がキャッシュであると宣言している。
  [Cache Directory Tagging Specification](https://bford.info/cachedir/) の
  `CACHEDIR.TAG`(署名を検証)か、Cargo が target 直下に書く `.rustc_info.json` +
  `debug`/`release` ディレクトリ。**名前や場所に依存しない**ので、`CARGO_TARGET_DIR`
  で `%TEMP%` 等へ外出しされた target も拾える。

`AppData` のようなアプリ所有領域では `declared` しか候補にならない。名前だけの
推定はそこでは信用しない。Windows、Program Files、ProgramData、Users/profile root、
cwd、実行バイナリはどちらの証拠でも保護される。

kind は `rust-target` `dotnet-output` `solution-build` `visual-studio-cache`
`gradle-output` `maven-target` `js-output` `python-cache` `cmake-output`
`node-modules` `python-venv` `unity-output` `tagged-cache`。

## Clean

`clean` は既知の成果物だけを検出する。既定はdry-runで、対話選択も初期未選択。

```powershell
storage-scout clean D:\src
storage-scout clean D:\src --include-tier reinstallable --execute
```

リスク階層は `routine`、`reinstallable`、`expensive`。後二者は
`--include-tier` で明示するまで選択できない。`tagged-cache` は `reinstallable`。

非対話削除は、直前のJSONに含まれる候補IDを指定した場合だけ許可される。

```powershell
storage-scout clean D:\src --json
storage-scout clean D:\src --id <SHA256> --execute --yes --json
```

任意パス削除や `--all` はない。実行直前にcanonical path、file ID、成果物証拠と
provenance、サイズ・更新時刻、reparse状態、除外、保護領域、**使用中かどうか**を
再検証する。使用中判定は Cargo が build 中に握る `.cargo-lock` 系のファイルロックを
試すことで行う(`cargo` 自身が "Blocking waiting for file lock" に使う機構と同じ)。

`--measure both` / `clean` は論理サイズ、Windows割当サイズ、hard-linkを考慮した
解放見込みを分けて報告する。JSONは `schema_version: 1`(フィールドは追加のみ)。
終了コードは成功・中断・選択なしが0、検証/削除失敗が1、CLI構文エラーが2。

全オプションは `storage-scout clean --help` を参照。

## Auto

`auto` は空き容量が下限を割ったときだけ、選択ルールに合う候補を**古い順に**、
目標の空き容量に届くまで回収する。ポリシーは TOML で宣言する。

```toml
# ~/.config/storage-scout/auto.toml
[trigger]
volume = 'C:\'          # 監視するボリューム上のパス
min_free = "40GiB"      # これを下回ったら動く
target_free = "80GiB"   # ここまで回復したら止める(省略時は該当候補を全て)

[select]
roots = ['C:\src', 'C:\Users\me\AppData\Local\Temp']
kinds = ["rust-target", "tagged-cache"]   # 省略時は全 kind
min_size = "100MiB"
older_than = "3d"                          # 最新ファイルがこれより古いものだけ
exclude = ['C:\src\keep-this']
include_tier = ["reinstallable"]           # 省略時は routine のみ

[report]
log_file = 'C:\Users\me\.local\state\storage-scout\auto.jsonl'  # 1行JSONを追記
```

```powershell
storage-scout auto                      # ~/.config/storage-scout/auto.toml を dry-run
storage-scout auto --config C:\policy.toml --json
storage-scout auto --execute            # 実削除
```

判定は純関数 `decide(trigger, free, candidates)` で、空き容量が下限以上なら走査すら
しない(idle)。下限未満なら候補を最終更新の古い順(同時刻なら回収見込みの大きい順)に
並べ、投影空き容量が `target_free` に達するまで選ぶ。実行中の build が握っている
target や、内部に reparse point があって厳密に測れない候補は `withheld` として理由付きで
除外し(1つの不良候補が run 全体を止めない)、選ばれた候補は `clean` と同じ再検証を経て
削除される。cwd や実行バイナリを含む root は拒否されるので、`auto` は root の外
(例: `%LOCALAPPDATA%\Programs` や `~/.local/bin`)に置いたバイナリで動かす。

`auto --execute` の二重ロックは「ポリシーファイルが何を消してよいかを宣言している」
ことと「コマンドラインで `--execute` が明示されている」こと。`--id`/`--yes` は不要
で、代わりにしきい値が引き金になる。

毎時実行するにはタスクスケジューラに登録する。

```powershell
schtasks /Create /TN "storage-scout auto" /SC HOURLY /RL LIMITED `
  /TR "\"$env:LOCALAPPDATA\Programs\storage-scout\storage-scout.exe\" auto --execute"
```

## Development

```powershell
cargo fmt --check
cargo nextest run --all-targets --all-features
cargo test --doc --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

実削除テストはリポジトリ内のtest用一時ディレクトリだけを対象にする。

MIT OR Apache-2.0
