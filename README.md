# iris

Verifiable, repairable, generation-based package manager for UdonBSD.

## Status

This repository contains the current Rust implementation of Iris.

- content-addressed BLAKE3 store
- generation-based install / remove / rollback model
- SQLite-backed state tracking
- repository indexing for local paths and `file://` repositories
- Ed25519 trusted-key manifest verification during `repo sync`
- dependency-aware install / update planning
- managed `iris self status|update` support on top of the normal generation-based update path
- fast `verify` and full `verify --full`
- UI-neutral request/response core API and a minimal `irisd` Unix-socket daemon
- orphaned config preservation, `repair`, `history`, `pin`, and `why`
- package source/provenance visibility for repository and installed metadata, including Ports-style origin metadata

The long-form architecture and CLI specification live in:

- `docs/overview.md`
- `docs/operations.md`
- `spec/system-spec.md`
- `spec/manifest-spec.md`
- `spec/cli-spec.md`

## Current scope

The current implementation is suitable as a release-hardened core for the Iris model described in the spec. It includes a local `irisd` Unix-socket daemon that performs startup and periodic full verification, persists the latest daemon verify status under the state root, exposes read-only CLI access to persisted daemon status/log artifacts, supports explicit CLI delegation while keeping the default CLI path direct and fail-closed, and rejects long-running root execution unless an explicit privilege-drop target is configured.

## Build and test

- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo build --release`

## CLI overview

- package ops: `install`, `remove`, `purge`, `update`, `search`, `info`, `self status|update`
- integrity ops: `verify`, `repair`, `audit`
- generation ops: `generation list|switch|rollback|diff|gc`
- repository ops: `repo add <url> <trusted-key>`, `repo sync`
- state introspection: `history`, `pin`, `why`, `orphan list|show|purge`
- local daemon: `irisd --root <path>` serving JSON over `<state-root>/run/irisd.sock`
- root-start hardening: `irisd --user <name|uid> [--group <name|gid>] ...`
- daemon verification controls: `irisd --no-verify-on-start`, `irisd --verify-interval-secs <n>`
- explicit daemon transport: `iris --transport daemon [--socket <path>] ...`
- daemon observability: `iris daemon status`, `iris daemon log [--lines <n>]`

## Repository trust model

`iris repo add` stores a trusted Ed25519 public key for a repository. During `repo sync`, each package manifest must:

1. declare `signature.algorithm = "ed25519"`
2. reference the configured trusted public key
3. contain a valid base64 Ed25519 signature over the unsigned manifest payload

If any manifest fails trust validation, the sync fails and the repository index is not replaced.

## Verification model

- default `verify`: fast integrity checks for generation layout, symlink/store presence, and managed file existence
- `verify --full`: recomputes BLAKE3 for managed store-backed files and config files
- config drift is reported as a warning rather than a hard corruption error
- `audit`: aggregates repository trust checks, full verification results, and orphan-config warnings into a structured report
- `irisd` background verification uses full verify, records the latest result in `run/daemon-status.json`, and appends per-run records to `log/daemon-verify.jsonl`

## Example workflow

1. `iris repo add file:///srv/iris/repo <base64-ed25519-public-key>`
2. `iris repo sync`
3. `iris install hello`
4. `iris verify`
5. `iris verify --full`
6. `iris history`

## Development notes

- the implementation is developed and tested in this repository on Linux, while targeting the FreeBSD-oriented Iris design
- integration coverage for lifecycle, signature rejection, dependency resolution, and full verification lives in `tests/iris_flow.rs`
