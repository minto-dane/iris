# Iris Package Manifest Specification

## 1. 形式

- UTF-8 encoded TOML document であること
- top-level table は `package`, `signature`, `dependencies`, `files` を利用する

## 2. package table

必須フィールド:

- `name: string`
- `version: string`
- `revision: integer`
- `arch: string`
- `abi: string`

任意フィールド:

- `summary: string`
- `maintainer: string`

### package.source

- `type: "port" | "repo" | "local"`
- `origin: string`
- `options: array<string>`

## 3. signature table

必須:

- `algorithm`: 現時点では `ed25519`
- `public_key`: trusted key identifier
- `value`: base64 signature

## 4. dependencies table

- `runtime`: dependency entry array
- `build`: dependency entry array

dependency entry:

- `name: string`
- `version: string`

## 5. files array

各要素は package payload の 1 ファイルを表す。

必須フィールド:

- `path: string`
- `blake3: string`
- `size: integer`
- `mode: string` (`0o755` ではなく `"0755"`)
- `type: "binary" | "data" | "config"`

任意フィールド:

- `flags: array<string>`
- `merge_strategy: "3way" | "overwrite"`

## 6. path 制約

1. `path` は相対パスでなければならない。
2. `..` を含んではならない。
3. NUL byte を含んではならない。
4. 同一 manifest 内で重複してはならない。

## 7. hash 制約

1. `blake3` は lowercase hex 文字列でなければならない。
2. 同じ hash を複数 file entry が参照してよい。
3. file content hash と size は payload 実体と一致しなければならない。

## 8. config file 規則

1. `type=config` の file は remove 時に削除されない。
2. `merge_strategy=3way` は旧 package default / 新 package default / 現在ファイルを元にマージする。
3. `merge_strategy=overwrite` は package default を優先する。
4. verify 時、user-modified config は allowlist として扱う。

## 9. 例

`nginx` manifest の典型例:

- `sbin/nginx`: binary
- `etc/nginx/nginx.conf`: config, `3way`
- `share/man/man8/nginx.8.gz`: data

## 10. バリデーションエラー

実装は少なくとも以下を reject MUST とする。

- 必須 table の欠落
- 必須 field の欠落
- 不正な mode 文字列
- 不正な hash 文字列
- 絶対パス、親ディレクトリ参照、重複 path
- `config` 以外に `merge_strategy` が指定されるケース