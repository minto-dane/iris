# irisd Overview

## 目的

`irisd` は Iris backend の local-only 常駐デーモンであり、主目的はバックグラウンド検証と、必要時に CLI から明示的に委譲される操作の実行である。

## 層構成

1. `libiris` core
   - install / remove / update
   - verify / repair / audit
   - generation / orphan / repo / history
2. `irisd`
   - Unix socket listener
   - request decode / validation
   - backend dispatch
   - structured response encode
3. frontends
   - `iris` CLI
   - 任意の local frontend

## 現在の提供範囲

現行の `irisd` は以下を提供する。

- local Unix domain socket
- JSON request / response
- schema version field
- CLI からの明示 daemon transport
- 1 connection = 1 request の単純モデル
- 同時多重 frontend を前提にしない単一経路運用
- 起動時 full verify
- 周期 full verify
- 直近 verify 状態の status file 保存
- persisted status / verify log の read-only 読み出し

## セキュリティ方針

- socket は state root 配下の `run/irisd.sock` に配置する
- `run` directory は owner-only を前提とする
- `log` / `tmp` directory も owner-only を前提とし、新規作成時は private permission で作成する
- `run/irisd.lock` には advisory lock を取り、kernel が保持する lock により single-instance を強制する
- lock file は残存しうるが、ファイル存在そのものではなく lock 保持の有無で live daemon を判定する
- 既存 socket の再利用はせず、stale socket のみを安全に unlink する
- 非 socket file / symlink / directory が同パスに存在する場合は起動失敗とする
- CLI は `--transport daemon` 指定時のみ接続し、自動 fallback / 自動起動を行わない
- client 側も socket 親ディレクトリの symlink / permission / owner と、socket 種別 / permission / owner を検証し、安全でない endpoint には接続しない
- daemon 側でも accept 後に OS に適した peer credential API（FreeBSD 系では `getpeereid(2)`）で接続元を確認し、原則として同一 uid 接続のみを受け付ける
- request は明示 enum / struct へ decode できるもののみ受理する
- request / response の I/O には有限 timeout を適用し、request 読み込みはサイズ上限つきで扱う
- shell 実行、任意 path 実行、動的コード評価は行わない
- transport error と domain error を分けて応答する

## 権限モデル

- `irisd` は **専用の unprivileged owner** で走らせるのを基本とする
- root で起動する場合でも、**常駐前に privilege drop を完了**しなければならない
- root 起動時に `--user` がない場合は fail-closed で起動拒否する
- `--group` は任意 override だが、`--user` なしでは受け付けない
- root 以外で `--user` / `--group` を指定した場合も fail-closed とする
- privilege drop は **supplementary groups clear → setgid → setuid** の順で行う
- drop は socket / lock / status / log を作る前に終わっている必要がある
- drop 後の effective uid/gid が daemon owner identity になり、その owner を基準に socket / lock / artifact ownership と peer credential 検証を行う
- target uid または gid が `0` に残る構成は拒否する
- state root は最終 daemon owner が安全に利用できる前提とし、そうでない場合は起動失敗になる

## フロントエンド責務

- 引数 / UI state を core request に変換する
- response の整形表示を担当する
- `json`, `batch`, color, table 表示は frontend 側の関心とする

## backend 責務

- request の意味解釈
- dry-run / destructive check / integrity check
- filesystem / DB / repository 更新
- verify / repair / audit のドメイン結果生成

## scheduler 挙動

- 既定では daemon 起動後に full verify を 1 回実行する
- 既定では一定間隔ごとに full verify を繰り返す
- current generation が存在しない場合は daemon 自体を落とさず、`skipped` として status に記録する
- verify のドメイン失敗は直近 status に記録し、transport fallback を起こさない
- request 処理は単純さと予測可能性を優先し、単一経路の逐次処理を維持する
- malformed / oversized request は panic ではなく structured error response として返す

## 状態ファイル

- `<state-root>/run/daemon-status.json`: 直近 verify の要約と詳細
- `<state-root>/log/daemon-verify.jsonl`: verify 実行ごとの append-only 履歴

status は **同一 directory 内の一意 temp file** を `create_new` / no-follow 相当で作ってから、
write → sync → rename → parent dir sync の順で更新する。

`run` / `log` / `tmp` directory 自体も、artifact hardening の前提として
owner-private permission に維持される。

既存 status / temp path が symlink・non-file・unexpected owner・unsafe permission の場合は
**fail-closed** で更新を拒否する。

log は no-follow 相当で open し、open 後も file type / owner / permission を検証する。
append 後は flush / sync / parent dir sync を行い、書き込み失敗を黙殺しない。

また verify log は implementation-defined な保持上限を持ち、上限超過時は
**古い entry を削減して最近の履歴を優先保持**する。

status には最低限、以下が入る。

- trigger (`startup` / `interval`)
- status (`ok` / `warning` / `error` / `skipped`)
- started / finished timestamp
- summary message
- issue count
- verify report または error

## observability access

- `iris daemon status` は persisted status file を読む
- `iris daemon log` は persisted verify log の末尾側を読む
- どちらも daemon の自動起動や transport fallback を伴わない
- `--transport daemon` を使う場合も意味論は同一で、単に request 経路だけが変わる
- log 読み出しは件数と bytes を bounded に扱い、巨大ログの丸ごと返却はしない
- status / log 読み出しは symlink を追従せず、可能な限り no-follow open と open 後 metadata 検証で扱う
- parent directory / opened file の owner / permission / file type が信頼できない場合は自動修復せず fail-closed で拒否する
- status / log が未生成の環境では、「まだ記録がない」ことを成功応答として返す

## 運用設定

- `irisd --root <path>`: state root 指定
- `irisd --socket <path>`: socket path 明示指定
- `irisd --no-verify-on-start`: 起動時 verify 無効化
- `irisd --verify-interval-secs <n>`: 周期 verify 秒数。`0` で無効
- `irisd --user <name|uid>`: root 起動時の privilege drop target
- `irisd --group <name|gid>`: root 起動時の group override

## 拡張余地

- job queue
- progress event stream