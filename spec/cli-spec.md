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
- `iris self status`
- `iris self update`
- `iris self stage`
- `iris self bootstrap`
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
- `iris daemon status`
- `iris daemon log [--lines <n>]`

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

## 3.2 daemon observability commands

- `iris daemon status` は `<state-root>/run/daemon-status.json` に永続化された直近 verify 状態を読む read-only command とする。
- `iris daemon log` は `<state-root>/log/daemon-verify.jsonl` の末尾側から新しい順に読む read-only command とする。
- `iris daemon log --lines <n>` は実装定義の安全上限内に制限 MUST される。
- artifact が未生成の場合、command は失敗ではなく「まだ記録がない」ことを表す構造化成功応答を返してよい MAY。
- これらの command は direct / daemon transport のどちらでも同じ意味論を保つ MUST。

## 3.3 self-update commands

- `iris self status` は managed `iris` package の installed state, repository latest, update availability, source provenance, current state schema, staged bootstrap plan を返す read-only command とする。
- `iris self update` は managed `iris` package だけを対象にする破壊的 command とし、意味論は `iris update iris` と一致する MUST。
- `iris self update` は `--dry-run` / `--yes` を受け付け、通常 update と同じ generation-based transaction を使う MUST。
- state root に managed `iris` package が存在しない場合、`iris self update` は明示的失敗を返す MUST。
- repository の最新 `iris` manifest が `package.self_upgrade.bootstrap = true` を宣言し、現在 state schema からの staged/bootstrap migration を要求する場合、`iris self update` と `iris update iris` は fail-closed で拒否 MUST。
- `iris self stage` は bootstrap-required な `iris` update に対して plan artifact を stage する command とする。plan artifact path は `<state-root>/bootstrap/self-upgrade-plan.json` でなければならない MUST。
- `iris self stage` は `--dry-run` 時に plan preview を返し、artifact を書き込んではならない MUST NOT。
- `iris self bootstrap` は staged plan を読み、必要な generation activation と supported schema migration を apply する command とする。
- `iris self bootstrap` は resume-safe であるべきであり、generation activation 済み phase から再開できる SHOULD。
- これらの command は FreeBSD Base / OS 本体更新を意味してはならない MUST NOT。

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

frontend は JSON 応答の整形失敗で panic してはならない MUST NOT。予期しない serialize 失敗時でも、CLI は最小限の structured error JSON または安定した失敗出力を返して終了コード `1` を返す MUST。

## 7. エラー表示

エラー時には次の情報を含める SHOULD:

- 高レベル理由
- 失敗した package または path
- 次に実行すべき recovery hint