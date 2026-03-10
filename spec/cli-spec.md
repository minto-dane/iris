# Iris CLI Specification

## 1. グローバルオプション

すべてのコマンドは以下を共有してよい。

- `--root <path>`: state root の上書き
- `--transport <direct|daemon>`: 実行 transport の明示選択。既定は `direct`
- `--socket <path>`: daemon transport 使用時の socket path 上書き
- `--dry-run`: 変更を適用せず計画のみ表示
- `--yes`: 確認を自動承認
- `--batch`: 非対話・機械可読寄り出力
- `--json`: JSON 出力

`--json` と `--batch` は frontend 表示制御であり、backend core option ではない。
`--socket` は `--transport daemon` 時のみ有効であり、それ以外では CLI は失敗 MUST。

## 2. コマンド階層

- `iris install <pkg> [pkg...]`
- `iris remove <pkg> [pkg...]`
- `iris purge <pkg> [pkg...]`
- `iris update [pkg...]`
- `iris search <query>`
- `iris info <pkg>`
- `iris verify [--full] [pkg...]`
- `iris repair [pkg...]`
- `iris audit`
- `iris generation list`
- `iris generation switch <N>`
- `iris generation rollback`
- `iris generation diff <A> <B>`
- `iris generation gc`
- `iris orphan list`
- `iris orphan show <pkg>`
- `iris orphan purge <pkg>`
- `iris orphan purge --all`
- `iris repo add <url> <key>`
- `iris repo sync`
- `iris history`
- `iris pin <pkg>`
- `iris why <pkg>`

## 3. 出力原則

1. 対話モードでは人間可読文を優先する。
2. `--batch` または `--json` では安定したキー名を持つ構造化出力を提供する。
3. `--dry-run` は適用計画、対象 package、generation 変化、削除対象 config の扱いを表示する。
4. CLI は core response を整形する adapter として振る舞う SHOULD。

## 3.1 frontend / daemon 関係

- CLI の既定実行経路は direct とする。
- CLI は `--transport daemon` 指定時のみ `irisd` を利用してよい。
- CLI は daemon 接続失敗時に direct へ fallback してはならない MUST NOT。
- CLI は daemon を自動起動してはならない MUST NOT。
- CLI が `irisd` を利用する場合も、command 意味論は本仕様から変えてはならない。
- daemon transport の wire format は `spec/daemon-spec.md` に従う。

## 4. 終了コード

- `0`: 成功
- `1`: 一般失敗
- `2`: 検証失敗または破損検出
- `3`: ユーザ入力または確認拒否
- `4`: 依存解決失敗
- `5`: 署名・信頼検証失敗

## 5. 対話確認

破壊的コマンドは既定で以下を確認 SHOULD:

- remove/purge 対象 package
- orphan 化される config 数
- 作成される新 generation
- rollback 可能性

`--yes` がある場合は確認せず続行する。

## 6. JSON 出力の最小要件

`--json` 出力は以下のトップレベルを SHOULD 含む。

- `command`
- `ok`
- `message`
- `data`

## 7. エラー表示

エラー時には次の情報を含める SHOULD:

- 高レベル理由
- 失敗した package または path
- 次に実行すべき recovery hint