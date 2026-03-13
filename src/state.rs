use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use crate::error::{IrisError, Result};
use crate::models::{
    GenerationSummary, HistoryEntry, InstalledPackageRecord, OrphanRecord, PackageManifest,
    PackageState, RepoPackageRecord,
};

pub const STATE_SCHEMA_VERSION_INITIAL: u32 = 1;
pub const STATE_SCHEMA_VERSION_CURRENT: u32 = 2;

#[derive(Debug, Clone)]
pub struct StateLayout {
    pub root: PathBuf,
}

impl StateLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn ensure(&self) -> Result<()> {
        for path in [
            self.store_dir(),
            self.db_dir(),
            self.cache_packages_dir(),
            self.repo_cache_dir(),
            self.generations_dir(),
            self.orphans_dir(),
        ] {
            ensure_directory(&path, None)?;
        }

        ensure_directory(&self.bootstrap_dir(), Some(0o700))?;
        ensure_directory(&self.run_dir(), Some(0o700))?;
        ensure_directory(&self.tmp_dir(), Some(0o700))?;
        ensure_directory(&self.log_dir(), Some(0o700))?;
        Ok(())
    }

    pub fn store_dir(&self) -> PathBuf {
        self.root.join("store/blake3")
    }

    pub fn db_dir(&self) -> PathBuf {
        self.root.join("db")
    }

    pub fn db_path(&self) -> PathBuf {
        self.db_dir().join("iris.db")
    }

    pub fn cache_packages_dir(&self) -> PathBuf {
        self.root.join("cache/packages")
    }

    pub fn repo_cache_dir(&self) -> PathBuf {
        self.root.join("cache/repos")
    }

    pub fn generations_dir(&self) -> PathBuf {
        self.root.join("generations")
    }

    pub fn generation_dir(&self, id: i64) -> PathBuf {
        self.generations_dir().join(id.to_string())
    }

    pub fn current_link(&self) -> PathBuf {
        self.generations_dir().join("current")
    }

    pub fn bootstrap_dir(&self) -> PathBuf {
        self.root.join("bootstrap")
    }

    pub fn bootstrap_plan_path(&self) -> PathBuf {
        self.bootstrap_dir().join("self-upgrade-plan.json")
    }

    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    pub fn daemon_socket_path(&self) -> PathBuf {
        self.run_dir().join("irisd.sock")
    }

    pub fn daemon_lock_path(&self) -> PathBuf {
        self.run_dir().join("irisd.lock")
    }

    pub fn daemon_status_path(&self) -> PathBuf {
        self.run_dir().join("daemon-status.json")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }

    pub fn orphan_file_dir(&self, package: &str) -> PathBuf {
        self.orphans_dir().join(package)
    }

    pub fn orphans_dir(&self) -> PathBuf {
        self.root.join("orphans")
    }

    pub fn repair_log_path(&self) -> PathBuf {
        self.log_dir().join("repair.log")
    }

    pub fn daemon_verify_log_path(&self) -> PathBuf {
        self.log_dir().join("daemon-verify.jsonl")
    }
}

fn ensure_directory(path: &Path, mode: Option<u32>) -> Result<()> {
    let mut created = false;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(IrisError::InvalidInput(format!(
                    "refusing to use symlinked state directory: {}",
                    path.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(IrisError::InvalidInput(format!(
                    "state path is not a directory: {}",
                    path.display()
                )));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            created = true;
        }
        Err(err) => return Err(err.into()),
    }

    if created && let Some(mode) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct IrisDb {
    path: PathBuf,
}

impl IrisDb {
    pub fn open(layout: &StateLayout) -> Result<Self> {
        layout.ensure()?;
        let db = Self {
            path: layout.db_path(),
        };
        db.init()?;
        Ok(db)
    }

    pub fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        Ok(conn)
    }

    fn init(&self) -> Result<()> {
        let conn = self.connect()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS repositories (
                url TEXT PRIMARY KEY,
                key TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS repo_packages (
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                revision INTEGER NOT NULL,
                summary TEXT NOT NULL,
                source_url TEXT NOT NULL,
                manifest_path TEXT NOT NULL,
                payload_root TEXT NOT NULL,
                manifest_toml TEXT NOT NULL,
                PRIMARY KEY(name, version, revision, source_url)
            );

            CREATE TABLE IF NOT EXISTS generations (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER,
                created_at TEXT NOT NULL,
                is_current INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS generation_packages (
                generation_id INTEGER NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                revision INTEGER NOT NULL,
                manifest_toml TEXT NOT NULL,
                PRIMARY KEY(generation_id, package_name)
            );

            CREATE TABLE IF NOT EXISTS installed_packages (
                name TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                revision INTEGER NOT NULL,
                state TEXT NOT NULL,
                generation_id INTEGER,
                manifest_toml TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS orphans (
                package_name TEXT NOT NULL,
                path TEXT NOT NULL,
                default_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                modified INTEGER NOT NULL,
                PRIMARY KEY(package_name, path)
            );

            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                packages_json TEXT NOT NULL,
                result TEXT NOT NULL,
                generation_before INTEGER,
                generation_after INTEGER,
                reason TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pins (
                package_name TEXT PRIMARY KEY,
                constraint_text TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )?;

        let mut schema_version = current_schema_version(&conn)?;
        if schema_version == 0 {
            set_schema_version(&conn, STATE_SCHEMA_VERSION_INITIAL)?;
            schema_version = STATE_SCHEMA_VERSION_INITIAL;
        }

        match schema_version {
            STATE_SCHEMA_VERSION_INITIAL => Ok(()),
            STATE_SCHEMA_VERSION_CURRENT => {
                ensure_state_migrations_table(&conn)?;
                Ok(())
            }
            version => Err(IrisError::Unsupported(format!(
                "unsupported state schema version {version}; supported versions are {} and {}",
                STATE_SCHEMA_VERSION_INITIAL, STATE_SCHEMA_VERSION_CURRENT
            ))),
        }
    }

    pub fn state_schema_version(&self) -> Result<u32> {
        let conn = self.connect()?;
        current_schema_version(&conn)
    }

    pub fn apply_self_schema_migration(
        &self,
        package_version: &str,
        from_state_schema: u32,
        target_state_schema: u32,
    ) -> Result<()> {
        let conn = self.connect()?;
        let current = current_schema_version(&conn)?;
        if current != from_state_schema {
            return Err(IrisError::InvalidInput(format!(
                "state schema migration expects current schema {}, found {}",
                from_state_schema, current
            )));
        }

        match (from_state_schema, target_state_schema) {
            (1, 2) => {
                let tx = conn.unchecked_transaction()?;
                ensure_state_migrations_table_tx(&tx)?;
                tx.execute(
                    "INSERT INTO state_migrations(package_name, package_version, from_schema, target_schema, applied_at)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                    params!["iris", package_version, 1_u32, 2_u32, Utc::now().to_rfc3339()],
                )?;
                tx.execute_batch("PRAGMA user_version = 2;")?;
                tx.commit()?;
                Ok(())
            }
            _ => Err(IrisError::Unsupported(format!(
                "unsupported self schema migration path {} -> {}",
                from_state_schema, target_state_schema
            ))),
        }
    }

    pub fn add_repo(&self, url: &str, key: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO repositories(url, key, added_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(url) DO UPDATE SET key = excluded.key",
            params![url, key, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn repositories(&self) -> Result<Vec<(String, String)>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare("SELECT url, key FROM repositories ORDER BY url")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn clear_repo_packages(&self, source_url: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "DELETE FROM repo_packages WHERE source_url = ?1",
            params![source_url],
        )?;
        Ok(())
    }

    pub fn upsert_repo_package(
        &self,
        manifest: &PackageManifest,
        source_url: &str,
        manifest_path: &Path,
        payload_root: &Path,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT OR REPLACE INTO repo_packages(
                name, version, revision, summary, source_url, manifest_path, payload_root, manifest_toml
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                manifest.package.name,
                manifest.package.version,
                manifest.package.revision,
                manifest.package.summary,
                source_url,
                manifest_path.to_string_lossy(),
                payload_root.to_string_lossy(),
                manifest.to_toml()?
            ],
        )?;
        Ok(())
    }

    pub fn replace_repo_packages(
        &self,
        source_url: &str,
        packages: &[(PackageManifest, PathBuf, PathBuf)],
    ) -> Result<()> {
        let conn = self.connect()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM repo_packages WHERE source_url = ?1",
            params![source_url],
        )?;
        for (manifest, manifest_path, payload_root) in packages {
            tx.execute(
                "INSERT INTO repo_packages(
                    name, version, revision, summary, source_url, manifest_path, payload_root, manifest_toml
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    manifest.package.name.as_str(),
                    manifest.package.version.as_str(),
                    manifest.package.revision,
                    manifest.package.summary.as_str(),
                    source_url,
                    manifest_path.to_string_lossy(),
                    payload_root.to_string_lossy(),
                    manifest.to_toml()?
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn search_repo_packages(&self, query: &str) -> Result<Vec<RepoPackageRecord>> {
        let conn = self.connect()?;
        let needle = format!("%{}%", query);
        let mut stmt = conn.prepare(
            "SELECT source_url, manifest_path, payload_root, manifest_toml
             FROM repo_packages
             WHERE name LIKE ?1 OR summary LIKE ?1
             ORDER BY name ASC",
        )?;
        let rows = stmt.query_map(params![needle], Self::repo_package_from_row)?;
        let mut packages = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        sort_repo_package_records(&mut packages);
        Ok(packages)
    }

    pub fn latest_repo_package(&self, name: &str) -> Result<Option<RepoPackageRecord>> {
        Ok(self.repo_packages_for_name(name)?.into_iter().next())
    }

    pub fn repo_packages_for_name(&self, name: &str) -> Result<Vec<RepoPackageRecord>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT source_url, manifest_path, payload_root, manifest_toml
             FROM repo_packages
             WHERE name = ?1",
        )?;
        let rows = stmt.query_map(params![name], Self::repo_package_from_row)?;
        let mut packages = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        sort_repo_package_records(&mut packages);
        Ok(packages)
    }

    pub fn repo_package_for_manifest(
        &self,
        manifest: &PackageManifest,
    ) -> Result<Option<RepoPackageRecord>> {
        let conn = self.connect()?;
        let manifest_toml = manifest.to_toml()?;
        let mut stmt = conn.prepare(
            "SELECT source_url, manifest_path, payload_root, manifest_toml
             FROM repo_packages
             WHERE name = ?1 AND version = ?2 AND revision = ?3 AND manifest_toml = ?4
             LIMIT 1",
        )?;
        stmt.query_row(
            params![
                manifest.package.name.as_str(),
                manifest.package.version.as_str(),
                manifest.package.revision,
                manifest_toml,
            ],
            Self::repo_package_from_row,
        )
        .optional()
        .map_err(Into::into)
    }

    fn repo_package_from_row(row: &Row<'_>) -> rusqlite::Result<RepoPackageRecord> {
        let manifest_toml: String = row.get(3)?;
        let manifest: PackageManifest = toml::from_str(&manifest_toml).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(err))
        })?;
        Ok(RepoPackageRecord {
            source_url: row.get(0)?,
            manifest_path: row.get(1)?,
            payload_root: row.get(2)?,
            manifest,
        })
    }

    pub fn current_generation_id(&self) -> Result<Option<i64>> {
        let conn = self.connect()?;
        conn.query_row(
            "SELECT id FROM generations WHERE is_current = 1 LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn next_generation_id(&self) -> Result<i64> {
        let conn = self.connect()?;
        let max_id: Option<i64> = conn.query_row("SELECT MAX(id) FROM generations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?;
        Ok(max_id.unwrap_or(0) + 1)
    }

    pub fn insert_generation(&self, id: i64, parent_id: Option<i64>) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO generations(id, parent_id, created_at, is_current) VALUES(?1, ?2, ?3, 0)",
            params![id, parent_id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn set_current_generation(&self, id: i64) -> Result<()> {
        let conn = self.connect()?;
        let tx = conn.unchecked_transaction()?;
        Self::set_current_generation_tx(&tx, id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn clear_current_generation(&self) -> Result<()> {
        let conn = self.connect()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("UPDATE generations SET is_current = 0", [])?;
        tx.commit()?;
        Ok(())
    }

    pub fn activate_generation(
        &self,
        generation_id: i64,
        parent_id: Option<i64>,
        packages: &BTreeMap<String, PackageManifest>,
        action: &str,
        requested_packages: &[String],
    ) -> Result<()> {
        let conn = self.connect()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO generations(id, parent_id, created_at, is_current) VALUES(?1, ?2, ?3, 0)",
            params![generation_id, parent_id, Utc::now().to_rfc3339()],
        )?;
        for manifest in packages.values() {
            tx.execute(
                "INSERT INTO generation_packages(generation_id, package_name, version, revision, manifest_toml)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    generation_id,
                    manifest.package.name.as_str(),
                    manifest.package.version.as_str(),
                    manifest.package.revision,
                    manifest.to_toml()?
                ],
            )?;
        }
        Self::set_current_generation_tx(&tx, generation_id)?;
        Self::record_history_tx(
            &tx,
            action,
            requested_packages,
            "ok",
            parent_id,
            Some(generation_id),
            action,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_generations(&self) -> Result<Vec<GenerationSummary>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT g.id, g.parent_id, g.created_at, g.is_current,
                    COUNT(gp.package_name)
             FROM generations g
             LEFT JOIN generation_packages gp ON gp.generation_id = g.id
             GROUP BY g.id, g.parent_id, g.created_at, g.is_current
             ORDER BY g.id DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(GenerationSummary {
                id: row.get(0)?,
                parent_id: row.get(1)?,
                created_at: row.get(2)?,
                current: row.get::<_, i64>(3)? == 1,
                package_count: row.get::<_, i64>(4)? as usize,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn generation_packages(
        &self,
        generation_id: i64,
    ) -> Result<BTreeMap<String, PackageManifest>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT package_name, manifest_toml
             FROM generation_packages
             WHERE generation_id = ?1
             ORDER BY package_name",
        )?;
        let rows = stmt.query_map(params![generation_id], |row| {
            let name: String = row.get(0)?;
            let manifest_toml: String = row.get(1)?;
            let manifest: PackageManifest = toml::from_str(&manifest_toml).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            Ok((name, manifest))
        })?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().collect())
    }

    pub fn replace_generation_packages(
        &self,
        generation_id: i64,
        packages: &BTreeMap<String, PackageManifest>,
    ) -> Result<()> {
        let conn = self.connect()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM generation_packages WHERE generation_id = ?1",
            params![generation_id],
        )?;
        for manifest in packages.values() {
            tx.execute(
                "INSERT INTO generation_packages(generation_id, package_name, version, revision, manifest_toml)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    generation_id,
                    manifest.package.name,
                    manifest.package.version,
                    manifest.package.revision,
                    manifest.to_toml()?
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_installed_package(
        &self,
        manifest: &PackageManifest,
        state: PackageState,
        generation_id: Option<i64>,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT OR REPLACE INTO installed_packages(name, version, revision, state, generation_id, manifest_toml)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                manifest.package.name,
                manifest.package.version,
                manifest.package.revision,
                state.as_str(),
                generation_id,
                manifest.to_toml()?
            ],
        )?;
        Ok(())
    }

    pub fn remove_installed_package(&self, name: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "DELETE FROM installed_packages WHERE name = ?1",
            params![name],
        )?;
        Ok(())
    }

    pub fn installed_package(&self, name: &str) -> Result<Option<InstalledPackageRecord>> {
        let conn = self.connect()?;
        conn.query_row(
            "SELECT state, generation_id, manifest_toml FROM installed_packages WHERE name = ?1",
            params![name],
            |row| {
                let state: String = row.get(0)?;
                let generation_id: Option<i64> = row.get(1)?;
                let manifest_toml: String = row.get(2)?;
                let manifest: PackageManifest = toml::from_str(&manifest_toml).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?;
                Ok(InstalledPackageRecord {
                    state: PackageState::from_db(&state),
                    generation_id,
                    manifest,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn list_installed_packages(&self) -> Result<Vec<InstalledPackageRecord>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT state, generation_id, manifest_toml
             FROM installed_packages
             ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            let state: String = row.get(0)?;
            let generation_id: Option<i64> = row.get(1)?;
            let manifest_toml: String = row.get(2)?;
            let manifest: PackageManifest = toml::from_str(&manifest_toml).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            Ok(InstalledPackageRecord {
                state: PackageState::from_db(&state),
                generation_id,
                manifest,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn replace_installed_packages(&self, records: &[InstalledPackageRecord]) -> Result<()> {
        let conn = self.connect()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM installed_packages", [])?;
        for record in records {
            tx.execute(
                "INSERT INTO installed_packages(name, version, revision, state, generation_id, manifest_toml)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    record.manifest.package.name.as_str(),
                    record.manifest.package.version.as_str(),
                    record.manifest.package.revision,
                    record.state.as_str(),
                    record.generation_id,
                    record.manifest.to_toml()?
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn replace_orphans(&self, package_name: &str, entries: &[OrphanRecord]) -> Result<()> {
        let conn = self.connect()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM orphans WHERE package_name = ?1",
            params![package_name],
        )?;
        for entry in entries {
            tx.execute(
                "INSERT INTO orphans(package_name, path, default_hash, current_hash, modified)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    entry.package_name,
                    entry.path,
                    entry.default_hash,
                    entry.current_hash,
                    if entry.modified { 1_i64 } else { 0_i64 }
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_orphans(&self, package: Option<&str>) -> Result<Vec<OrphanRecord>> {
        let conn = self.connect()?;
        let (sql, params_vec): (&str, Vec<String>) = if let Some(package) = package {
            (
                "SELECT package_name, path, default_hash, current_hash, modified FROM orphans WHERE package_name = ?1 ORDER BY package_name, path",
                vec![package.to_string()],
            )
        } else {
            (
                "SELECT package_name, path, default_hash, current_hash, modified FROM orphans ORDER BY package_name, path",
                vec![],
            )
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = if params_vec.is_empty() {
            stmt.query_map([], |row| {
                Ok(OrphanRecord {
                    package_name: row.get(0)?,
                    path: row.get(1)?,
                    default_hash: row.get(2)?,
                    current_hash: row.get(3)?,
                    modified: row.get::<_, i64>(4)? == 1,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt.query_map(params![params_vec[0]], |row| {
                Ok(OrphanRecord {
                    package_name: row.get(0)?,
                    path: row.get(1)?,
                    default_hash: row.get(2)?,
                    current_hash: row.get(3)?,
                    modified: row.get::<_, i64>(4)? == 1,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows)
    }

    pub fn delete_orphans(&self, package: Option<&str>) -> Result<()> {
        let conn = self.connect()?;
        match package {
            Some(name) => {
                conn.execute("DELETE FROM orphans WHERE package_name = ?1", params![name])?;
            }
            None => {
                conn.execute("DELETE FROM orphans", [])?;
            }
        }
        Ok(())
    }

    pub fn record_history(
        &self,
        action: &str,
        packages: &[String],
        result: &str,
        generation_before: Option<i64>,
        generation_after: Option<i64>,
        reason: &str,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO history(timestamp, action, packages_json, result, generation_before, generation_after, reason)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                Utc::now().to_rfc3339(),
                action,
                serde_json::to_string(packages)?,
                result,
                generation_before,
                generation_after,
                reason
            ],
        )?;
        Ok(())
    }

    fn set_current_generation_tx(tx: &Transaction<'_>, id: i64) -> Result<()> {
        tx.execute("UPDATE generations SET is_current = 0", [])?;
        let updated = tx.execute(
            "UPDATE generations SET is_current = 1 WHERE id = ?1",
            params![id],
        )?;
        if updated != 1 {
            return Err(IrisError::InvalidInput(format!(
                "generation {} does not exist",
                id
            )));
        }
        Ok(())
    }

    fn record_history_tx(
        tx: &Transaction<'_>,
        action: &str,
        packages: &[String],
        result: &str,
        generation_before: Option<i64>,
        generation_after: Option<i64>,
        reason: &str,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO history(timestamp, action, packages_json, result, generation_before, generation_after, reason)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                Utc::now().to_rfc3339(),
                action,
                serde_json::to_string(packages)?,
                result,
                generation_before,
                generation_after,
                reason
            ],
        )?;
        Ok(())
    }

    pub fn list_history(&self) -> Result<Vec<HistoryEntry>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT timestamp, action, packages_json, result, generation_before, generation_after, reason
             FROM history
             ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let packages_json: String = row.get(2)?;
            let packages: Vec<String> = serde_json::from_str(&packages_json).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            Ok(HistoryEntry {
                timestamp: row.get(0)?,
                action: row.get(1)?,
                packages,
                result: row.get(3)?,
                generation_before: row.get(4)?,
                generation_after: row.get(5)?,
                reason: row.get(6)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn pin_package(&self, package_name: &str, constraint_text: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT OR REPLACE INTO pins(package_name, constraint_text, created_at)
             VALUES(?1, ?2, ?3)",
            params![package_name, constraint_text, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn pinned_packages(&self) -> Result<BTreeMap<String, String>> {
        let conn = self.connect()?;
        let mut stmt =
            conn.prepare("SELECT package_name, constraint_text FROM pins ORDER BY package_name")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let rows = rows.collect::<rusqlite::Result<Vec<(String, String)>>>()?;
        Ok(rows.into_iter().collect())
    }

    pub fn delete_generation(&self, generation_id: i64) -> Result<()> {
        let conn = self.connect()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM generation_packages WHERE generation_id = ?1",
            params![generation_id],
        )?;
        tx.execute(
            "DELETE FROM generations WHERE id = ?1",
            params![generation_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn sort_repo_package_records(records: &mut [RepoPackageRecord]) {
    records.sort_by(compare_repo_package_records);
}

fn compare_repo_package_records(left: &RepoPackageRecord, right: &RepoPackageRecord) -> Ordering {
    left.manifest
        .package
        .name
        .cmp(&right.manifest.package.name)
        .then_with(|| {
            compare_repo_versions(
                &left.manifest.package.version,
                &right.manifest.package.version,
            )
        })
        .then_with(|| {
            right
                .manifest
                .package
                .revision
                .cmp(&left.manifest.package.revision)
        })
        .then_with(|| left.source_url.cmp(&right.source_url))
        .then_with(|| left.manifest_path.cmp(&right.manifest_path))
}

fn compare_repo_versions(left: &str, right: &str) -> Ordering {
    // Try to parse as SemVer (handle optional leading "v")
    let left_trimmed = left.strip_prefix('v').unwrap_or(left);
    let right_trimmed = right.strip_prefix('v').unwrap_or(right);

    match (
        semver::Version::parse(left_trimmed),
        semver::Version::parse(right_trimmed),
    ) {
        (Ok(left_ver), Ok(right_ver)) => {
            // Both versions are valid SemVer, compare using SemVer rules
            right_ver.cmp(&left_ver)
        }
        _ => {
            // Fall back to the existing logic if either version is not valid SemVer
            let left_parts: Vec<_> = left.split(['.', '-', '_']).map(str::trim).collect();
            let right_parts: Vec<_> = right.split(['.', '-', '_']).map(str::trim).collect();
            let len = left_parts.len().max(right_parts.len());

            for idx in 0..len {
                let left_part = left_parts.get(idx).copied().unwrap_or("0");
                let right_part = right_parts.get(idx).copied().unwrap_or("0");
                let ordering = match (left_part.parse::<u64>(), right_part.parse::<u64>()) {
                    (Ok(left_num), Ok(right_num)) => left_num.cmp(&right_num),
                    _ => left_part.cmp(right_part),
                };
                if !ordering.is_eq() {
                    return ordering;
                }
            }

            Ordering::Equal
        }
    }
}

fn current_schema_version(conn: &Connection) -> Result<u32> {
    let version = conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    u32::try_from(version).map_err(|_| {
        IrisError::InvalidInput(format!(
            "database user_version does not fit in u32: {version}"
        ))
    })
}

fn set_schema_version(conn: &Connection, version: u32) -> Result<()> {
    conn.execute_batch(&format!("PRAGMA user_version = {version};"))?;
    Ok(())
}

fn ensure_state_migrations_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS state_migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            package_version TEXT NOT NULL,
            from_schema INTEGER NOT NULL,
            target_schema INTEGER NOT NULL,
            applied_at TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn ensure_state_migrations_table_tx(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS state_migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            package_version TEXT NOT NULL,
            from_schema INTEGER NOT NULL,
            target_schema INTEGER NOT NULL,
            applied_at TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{IrisDb, StateLayout};
    use crate::Result;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    #[test]
    fn ensure_sets_private_permissions_on_sensitive_directories() -> Result<()> {
        let root = tempdir()?;
        let layout = StateLayout::new(root.path());

        layout.ensure()?;

        for path in [
            layout.bootstrap_dir(),
            layout.run_dir(),
            layout.tmp_dir(),
            layout.log_dir(),
        ] {
            let mode = fs::metadata(path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }

        Ok(())
    }

    #[test]
    fn ensure_preserves_existing_sensitive_directory_permissions() -> Result<()> {
        let root = tempdir()?;
        let layout = StateLayout::new(root.path());

        for path in [
            layout.bootstrap_dir(),
            layout.run_dir(),
            layout.tmp_dir(),
            layout.log_dir(),
        ] {
            fs::create_dir_all(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }

        layout.ensure()?;

        for path in [
            layout.bootstrap_dir(),
            layout.run_dir(),
            layout.tmp_dir(),
            layout.log_dir(),
        ] {
            let mode = fs::metadata(path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }

        Ok(())
    }

    #[test]
    fn ensure_rejects_symlinked_sensitive_directory() -> Result<()> {
        let root = tempdir()?;
        let target = root.path().join("real-run");
        fs::create_dir_all(&target)?;
        symlink(&target, root.path().join("run"))?;

        let layout = StateLayout::new(root.path());
        let err = layout
            .ensure()
            .expect_err("symlinked sensitive directory should fail closed");

        assert!(err.to_string().contains("symlinked state directory"));
        Ok(())
    }

    #[test]
    fn set_current_generation_rolls_back_when_target_is_missing() -> Result<()> {
        let root = tempdir()?;
        let layout = StateLayout::new(root.path());
        let db = IrisDb::open(&layout)?;

        db.insert_generation(1, None)?;
        db.set_current_generation(1)?;

        let err = db
            .set_current_generation(2)
            .expect_err("missing generation should fail closed");

        assert!(err.to_string().contains("generation 2 does not exist"));
        assert_eq!(db.current_generation_id()?, Some(1));
        Ok(())
    }
}