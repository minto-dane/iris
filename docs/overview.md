# Iris Overview

## 目的

Iris は FreeBSD 14+ 向けの検証可能・修復可能・原子的なパッケージマネージャである。FHS 互換の配置を維持しつつ、ファイル単位のコンテンツアドレスストア、世代管理、起動時検証、自律修復を統合する。

## 設計原則

1. **Verifiability**: 管理下の全ファイルは BLAKE3 と Merkle Tree により検証可能でなければならない。
2. **Repairability**: 破損検出時は store 再リンク、cache 復元、mirror 再取得、generation rollback の順で修復を試みる。
3. **Atomicity**: install / remove / update / switch は rename(2) を用いた世代切替で中間状態を露出しない。

## システム構成

- `iris`: CLI フロントエンド
- `libiris`: コアライブラリ
- `irisd`: 起動時検証とバックグラウンド検証を担うデーモン
- `SQLite`: マニフェスト、世代、Merkle、孤児状態、履歴を保存
- `Content-address store`: `/var/iris/store/blake3/<prefix>/<hash>`

### frontend / backend 境界

- frontend は主として `iris` CLI を想定し、将来の local frontend を妨げない
- backend core は UI 非依存の request / response 契約を提供する
- `irisd` は backend core を Unix domain socket 上へ公開する local IPC adapter である
- CLI の既定 transport は direct とし、`--transport daemon` 指定時のみ `irisd` を利用する
- transport 切替で fallback や自動 daemon 起動は行わず、失敗時は fail-closed とする
- `json` や `batch` のような表示都合は frontend の責務であり、backend の責務ではない

## 主要ディレクトリ

- `/var/iris/store/`: ファイル実体
- `/var/iris/db/iris.db`: 単一 SQLite DB
- `/var/iris/cache/packages/`: ダウンロードキャッシュ
- `/var/iris/generations/<N>/`: 世代ごとのリンクツリー
- `/var/iris/generations/current`: 現在の世代への symlink
- `/var/iris/tmp/txn-XXXX/`: トランザクション作業領域
- `/var/iris/log/repair.log`: 修復ログ
- `/var/iris/log/daemon-verify.jsonl`: daemon verify 履歴ログ
- `/var/iris/run/irisd.sock`: `irisd` の local IPC socket
- `/var/iris/run/daemon-status.json`: daemon の直近 verify 状態

## データモデル概要

### Package

- 名前、版、revision、ABI、summary、maintainer
- source 情報 (port / repo)
- runtime / build 依存
- 署名情報
- files リスト

### File Entry

- `path`: FHS 配下の相対パス
- `blake3`: 実体ハッシュ
- `size`, `mode`, `flags`
- `type`: `binary | data | config`
- `merge_strategy`: `3way | overwrite` (`config` のみ)

### Generation

- generation number
- parent generation
- created timestamp
- installed package set
- current pointer の有無

### Orphaned Config

- package name
- path
- default hash
- current hash
- modified flag

## コマンド群

- Package: `install`, `remove`, `purge`, `update`, `search`, `info`
- Integrity: `verify`, `repair`, `audit`
- Generations: `generation list|switch|rollback|diff|gc`
- Orphans: `orphan list|show|purge`
- Repository: `repo add|sync`
- Introspection: `history`, `pin`, `why`

すべての破壊的コマンドは `--dry-run` を備え、既定では確認を要求する。`--yes` は自動承認、`--batch` は非対話出力を意味する。

## 実装ポリシー

1. FreeBSD 固有機能は trait / backend で抽象化する。
2. ZFS 補助機能は任意機能であり、コアロジックと分離する。
3. DB・store・generation の更新順は必ず transaction engine 経由とする。
4. `config` ファイルは remove 時に削除せず orphan 管理下へ移動する。
5. 破損検出とユーザ変更設定は区別する。
6. daemon 境界では request schema を固定し、frontend ごとの暗黙挙動を持ち込まない。
7. `irisd` は既定で local Unix socket のみを公開し、TCP listen を前提にしない。
8. CLI の daemon transport は明示 opt-in とし、fallback や自動起動を実装しない。
9. IPC endpoint は最小権限で作成し、破壊的操作は core 側でも再検証する。

## 実装フェーズ

### Phase 1

- CLI 骨格
- 設定読込
- package manifest parser
- store writer / linker
- generation state manager

### Phase 2

- transaction engine
- verify engine
- orphan manager
- operation history

### Phase 3

- daemon background verify scheduler
- repair scheduler
- privilege separation
- ZFS helper abstraction

## 非目標

- 本実装段階では実際の ports build pipeline を含めない。
- kernel module や boot environment への直接統合は後続段階とする。