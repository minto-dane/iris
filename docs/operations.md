# Iris Operations Guide

## install

`iris install <pkg> [pkg...]`

1. PLAN: 依存解決、競合検出、必要容量計算
2. PREPARE: manifest 取得、署名検証、store 展開、新世代構築
3. ACTIVATE: generation rename、`current` 切替、DB transaction
4. FINALIZE: post-install、Merkle 再計算、履歴記録

### remove と purge の違い

- `remove`: `binary` と `data` を unlink、`config` は orphan として保持
- `purge`: orphan config を含めて完全削除

## update

`iris update [pkg...]`

- 引数なしは全更新
- `config` は merge strategy に従う
- 失敗時は直前の current generation を維持する

## verify

`iris verify [--full]`

- 既定は package root / generation 整合性中心の高速検査
- `--full` は全ファイル BLAKE3 を再計算
- `config` のユーザ変更は破損として扱わない

## repair

`iris repair [pkg...]`

修復順序:

1. generation link の再構築
2. store からの再リンク
3. cache archive からの再展開
4. mirror から再取得
5. generation rollback

## generation

### list

- generation id, 作成時刻, package 数, current 印を表示

### switch

- `current` symlink を原子的に差し替える
- DB と実体の不整合があれば switch 前に拒否する

### rollback

- 直前 generation に切り替える sugar command

### diff

- package added / removed / upgraded / downgraded を列挙する

### gc

- keep ルール外の古い generations を削除
- 参照されない store objects を sweep
- orphan config は purge されるまで除外

## orphan

### list

- orphan package と残存 config path 一覧

### show

- default hash, current hash, modified flag を表示

### purge

- 未変更 config は既定で削除可能
- 変更済み config は確認必須
- `--force` で非対話削除

## repo

### add

- repository URL と trusted key を登録

### sync

- repository manifest を取得し、署名を検証する

## history / pin / why

- `history`: transaction log を時系列で表示
- `pin`: package version constraint を保存
- `why`: dependency path を説明

## 障害時の期待挙動

- PLAN/PREPARE 中断: `tmp/txn-*` のみが残る
- ACTIVATE 中断: rename の原子性により旧/新のいずれか一方のみ有効
- FINALIZE 中断: ファイル配置は完了、スクリプト再試行のみ必要

## 管理者向け推奨運用

- 破壊的操作前に `--dry-run` を確認する
- 定期的に `verify --full` を実行する
- `generation gc` は keep 数と audit ポリシーに従って行う
- `orphan list` を監視し、不要設定を定期 purge する