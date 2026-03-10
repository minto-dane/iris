# Iris System Specification

## 1. 適用範囲

本仕様は Iris の CLI、libiris core、`irisd`、generation 管理、content-address store、verification、repair、orphan management の挙動を規定する。

## 2. 規範語

- MUST: 必須
- SHOULD: 強く推奨
- MAY: 任意

## 3. ルートディレクトリ

実装は既定で `/var/iris` を state root として MUST 利用する。テストや開発用途では別 root を指定 MAY とする。

必須サブディレクトリ:

- `store/blake3`
- `db`
- `cache/packages`
- `generations`
- `tmp`
- `log`
- `run`

## 4. ストア仕様

1. すべての管理対象ファイルは content-addressed object として MUST 保存される。
2. object path は `store/blake3/<hash[0..2]>/<hash>` 形式で MUST 一意化される。
3. generation tree 内の managed file は store object への symlink として MUST 表現される。
4. object の内容ハッシュは BLAKE3 で MUST 算出される。
5. 同一 hash の object は重複保存してはならない。

## 5. Manifest 仕様

1. package manifest は TOML で MUST 表現される。
2. `package.name`, `package.version`, `signature`, `files` は MUST 存在する。
3. 各 `files` entry は path, blake3, size, mode, type を MUST 持つ。
4. `type=config` の entry は `merge_strategy` を SHOULD 明示する。

## 6. Transaction Engine

### 6.1 状態機械

transaction state は以下を MUST 持つ。

- `planned`
- `prepared`
- `activated`
- `finalized`
- `failed`

### 6.2 フェーズ要件

PLAN:

- dependency resolution を行う MUST
- disk impact を算出する SHOULD
- destructive operation の計画を表示する MUST

PREPARE:

- package signature を検証する MUST
- store object を展開する MUST
- next generation tree を `tmp/txn-*` に構築する MUST

ACTIVATE:

- generation directory を rename(2) で可視化する MUST
- `current` symlink は temp symlink + rename で切替 MUST
- DB 更新は単一 transaction として行う MUST

FINALIZE:

- history record を残す MUST
- verify metadata を更新する SHOULD
- post-install failure は rollback 理由にしてはならない MUST

## 7. Generation 管理

1. generation は package set の完全スナップショットでなければならない。
2. `current` は常に存在する有効 generation を指していなければならない。
3. rollback は直前 generation へ current を切替える SHOULD。
4. GC は keep policy を超える古い generation を削除 MAY とする。
5. どの generation からも参照されない store object のみ GC 対象 MUST。

## 8. Verification

1. verify engine は package root hash と file hash の両方を扱えなければならない。
2. user-modified config は破損扱いしてはならない。
3. missing symlink, wrong symlink target, missing store object, hash mismatch は破損として MUST 検出される。
4. verification result は package 単位と file 単位の両方で参照可能 SHOULD。

## 9. Repair

実装は以下の順で repair strategy を試行 MUST:

1. generation link repair
2. store relink
3. cache restore
4. repository fetch restore
5. generation rollback

各試行は structured event として記録 SHOULD。

## 10. Orphan 管理

1. `remove` は config file を削除してはならない MUST。
2. remove 後、package state は `orphaned-config` に遷移 MUST。
3. reinstall 時、既存 config を再利用するか上書きするかを選択 MUST 可能とする。
4. batch mode では既存 config 優先 SHOULD。

## 11. Security

1. repository metadata と package manifest は署名検証 MUST。
2. trust root は Ed25519 keyring MUST。
3. content hash は BLAKE3 MUST。
4. privilege-requiring operations は backend boundary で分離 SHOULD。
5. frontend/backend 間の daemon transport は local Unix socket SHOULD。
6. socket endpoint は owner-only permission を SHOULD 使用する。
7. backend core は CLI の出力都合に依存してはならない SHOULD NOT。

## 12. Platform 拡張

1. ZFS helper は optional capability として実装 MAY。
2. ZFS 不在でも同一 transaction path が機能 MUST。
3. Capsicum sandbox は FreeBSD backend で有効化 SHOULD。

## 13. 履歴

history entry は少なくとも以下を SHOULD 含む:

- timestamp
- action
- requested packages
- result
- generation before / after
- reason または source

## 14. 開発向け適合条件

現段階のコードベースでは、CLI と library は以下を満たすことで適合とみなす。

- state root を作成できる
- manifest を読み書き・検証できる
- store object を追加できる
- generation を作成・列挙・切替できる
- remove/purge/orphan の状態遷移を表現できる
- verify / repair の dry-run と最小実装が動作する