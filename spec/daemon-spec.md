# Iris Daemon Specification

## 1. 適用範囲

本仕様は `irisd` の local IPC 境界、request / response schema、バックグラウンド検証 scheduler、および hardening 後の security / robustness 要件を規定する。

## 2. transport

1. `irisd` は Unix domain socket を MUST 利用する。
2. 既定 socket path は `<state-root>/run/irisd.sock` を MUST とする。
3. 現行仕様では TCP / UDP / HTTP listen を提供してはならない MUST NOT。
4. 1 connection は 1 request を処理 MUST とする。
5. 現行 daemon は単一 frontend 経路を主対象とし、同時多重 client 処理を保証しない MAY。

## 3. socket 作成要件

1. `run/` directory は `0700` 相当であり、group / other 権限を持ってはならない MUST NOT。
2. socket file は `0600` 相当を SHOULD とする。
3. daemon は `<state-root>/run/irisd.lock` を用いた advisory lock ベースの single-instance 保護を実装 MUST とする。
4. lock file の存在自体は live daemon を意味しない。live 判定は kernel が保持する lock に基づいて行う MUST とする。
5. 既存 lock file は再利用 MAY とし、別 process が lock を保持している場合、起動は失敗 MUST とする。
6. 起動時、既存 path が socket の場合のみ stale endpoint として unlink MAY。
7. 既存 path が regular file / directory / symlink の場合、起動は失敗 MUST。
8. client は接続前に socket 親ディレクトリが symlink でないこと、owner が呼び出し元と一致すること、socket が実ソケットであり、過度に緩い permission でないことを検証 SHOULD。

## 4. request schema

request は JSON object であり、少なくとも以下を含む SHOULD:

- `version: integer`
- `request: object`

`request` は core request enum に decode 可能でなければならない。

daemon は request 読み込みに対して implementation-defined な安全上限を設け、上限超過 request を拒否 MUST とする。

## 5. response schema

response は JSON object であり、少なくとも以下を含む SHOULD:

- `version: integer`
- `response.ok: boolean`
- `response.message: string`
- `response.data: any`

transport-level decode failure でも、可能な限り structured error response を返す SHOULD。

daemon / client は IPC read / write の双方に有限 timeout を適用 SHOULD とする。

## 6. core boundary

1. backend core は CLI-specific option に依存してはならない MUST NOT。
2. `json`, `batch`, 色付け、表形式整形は frontend 側の責務 MUST。
3. backend core は typed request / typed option / structured response を受理・返却 MUST。

## 7. 対応 command 意味論

CLI が daemon transport を明示した場合、daemon は direct 実行と同じ command 意味論を提供 MUST。

最小自己診断 command として `ping` を提供 SHOULD。

## 8. security requirements

1. request は未知 field や不正型で panic してはならない MUST NOT。
2. daemon は request ごとに shell を起動してはならない MUST NOT。
3. destructive operation は transport 経由でも core 側 validation を再利用 MUST。
4. error message は内部 secret や鍵内容を出力してはならない SHOULD NOT。
5. daemon は local filesystem state root の外を信頼境界として扱ってはならない SHOULD。
6. CLI / client は daemon 接続失敗時に別 transport へ自動切替してはならない MUST NOT。
7. CLI / client は daemon を自動起動してはならない MUST NOT。
8. daemon は accept 後に target OS に適した peer credential API（例: FreeBSD 系では `getpeereid(2)`）で接続元 owner を確認し、原則として daemon 実行 owner と同一 uid の接続のみ受理 SHOULD とする。
9. oversized / malformed request は panic ではなく明示的エラー応答として処理 SHOULD とする。

## 9. privilege boundary

1. `irisd` は専用の unprivileged owner で動作 SHOULD とする。
2. 起動時 effective uid が `0` の場合、`irisd` は明示的な privilege drop target を伴わずに常駐継続してはならない MUST NOT。
3. `irisd` は `--user <name|uid>` を privilege drop target 指定として提供 SHOULD とする。
4. `--group <name|gid>` は任意 override として提供 MAY するが、`--user` を伴わない単独指定は失敗 MUST とする。
5. root 以外の実行主体が `--user` または `--group` を指定した場合、起動は失敗 MUST とする。
6. root 実行時の privilege drop は、supplementary groups の clear、`setgid(2)`、`setuid(2)` の順で実施 SHOULD とする。
7. privilege drop は socket bind、lock 取得、status/log artifact 作成より前に完了 MUST しなければならない。
8. drop target の解決失敗、drop API の失敗、drop 後も uid `0` または gid `0` に留まる状態は fail-closed で拒否 MUST とする。
9. daemon が信頼する owner identity は privilege drop 後の effective uid/gid MUST とする。
10. state root とその下位 directory は最終 daemon owner が安全に利用できる状態であることを前提 SHOULD とし、そうでない場合 daemon は起動失敗 MAY とする。
11. `run` / `log` / `tmp` のような sensitive state directory は owner-private permission に保たれる SHOULD とし、実装は初期 layout 作成時にそれらを正規化 MAY とする。

## 10. versioning

1. protocol version は整数で管理 MUST。
2. 非互換変更時は version を増やす MUST。
3. 現行 protocol version は `1` MUST とする。

## 11. background verification

1. `irisd` は既定で起動直後に full verify を 1 回実行 MUST とする。
2. `irisd` は既定で定期 full verify を実行 SHOULD とし、間隔は CLI option で設定可能でなければならない。
3. verify interval が `0` の場合、周期 verify は無効 MUST とする。
4. current generation が存在しない場合、daemon は verify を致命的失敗として扱ってはならない MUST NOT。代わりに skipped 状態を記録 SHOULD とする。
5. scheduler は複数 frontend 同時接続を前提にせず、逐次 request 処理と両立 MUST する。

## 12. daemon status artifacts

1. daemon は直近 verify 結果を `<state-root>/run/daemon-status.json` に原子的に書き込む MUST。
2. status file 更新では同一 directory 内の一意 temp file を `create_new` / no-follow 相当で作成し、write・flush / sync・rename・親 directory の sync を行う SHOULD。
3. daemon は既存 status artifact または temp artifact が symlink / non-file / unexpected owner / unsafe permission の場合、fail-closed で更新拒否 MUST とする。
4. daemon は各 verify 実行結果を `<state-root>/log/daemon-verify.jsonl` に追記 SHOULD する。
5. verify log 追記時は no-follow 相当の open と open 後 metadata 検証を行い、symlink / non-file / unexpected owner / unsafe permission を fail-closed で拒否 SHOULD とする。
6. verify log 追記後は flush / sync と親 directory の sync を行い、部分書き込みや新規作成の durability 欠落を黙殺してはならない MUST NOT。
7. daemon は verify log の on-disk 保持量に implementation-defined 上限を設け SHOULD とし、上限超過時は古い entry を削減または compaction して最近の履歴を優先保持 MAY とする。
8. status record は少なくとも以下を含む SHOULD:
   - `trigger` (`startup` または `interval`)
   - `status` (`ok` / `warning` / `error` / `skipped`)
   - `started_at`
   - `finished_at`
   - `message`
   - `issue_count`
   - `report` または `error`
9. status artifact の書き込み失敗は daemon 実装上のエラーとして扱い、黙殺してはならない MUST NOT。

## 13. daemon observability read API

1. backend core は persisted daemon status / log artifact を読む read-only request を提供 MAY とする。
2. `daemon status` は `<state-root>/run/daemon-status.json` のみを参照し、daemon 生存確認や自動起動を含んではならない MUST NOT。
3. `daemon log` は `<state-root>/log/daemon-verify.jsonl` のみを参照し、返却件数を request 引数で制御できても安全上限で clamp MUST する。
4. observability read は implementation-defined な byte 上限内で処理 SHOULD とし、過大または破損した artifact は明示的エラーとして返す SHOULD。
5. observability read は symlink を追従してはならない MUST NOT。可能なら no-follow open と open 後 metadata 検証を用いる SHOULD。
6. observability read は artifact parent directory の安全性、および opened file の regular-file / owner / permission を検証し、信頼できない artifact を fail-closed で拒否 SHOULD とする。
7. artifact が存在しない場合、backend は null / 空配列を含む structured success を返してよい MAY。
8. direct transport と daemon transport は同一の read semantics を提供 MUST する。
9. observability artifact を格納する `run` / `log` parent directory は owner-private permission を既定 SHOULD とし、実装は state layout 初期化時に安全側へ正規化 MAY とする。

## 14. daemon runtime options

1. `irisd` は startup verify を無効化する option を提供 MAY とする。
2. `irisd` は verify interval 秒数を設定する option を提供 SHOULD とする。
3. `irisd` は privilege drop target として `--user <name|uid>` を提供 SHOULD とする。
4. `irisd` は privilege drop group override として `--group <name|gid>` を提供 MAY とする。
5. runtime option は transport の fail-closed 意味論を変更してはならない MUST NOT。