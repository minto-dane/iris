use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryFrom;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::symlink;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{IrisRequest, IrisResponse, OperationOptions};
use crate::error::{IrisError, Result};
use crate::models::{
    AuditFinding, AuditReport, DaemonLogReadout, DaemonStatusReadout, DaemonVerifyStatus,
    FileEntry, FileType, InstalledPackageRecord, MergeStrategy, OrphanRecord, PackageManifest,
    PackageSelfUpgrade, PackageSource, PackageState, RepairAction, RepoPackageRecord, VerifyIssue,
    VerifyReport,
};
use crate::repo::{sync_repositories, validate_trusted_key, verify_manifest_signature};
use crate::state::{IrisDb, StateLayout};
use crate::store::ContentStore;

const DEFAULT_GENERATIONS_KEEP: usize = 5;
const DEFAULT_DAEMON_LOG_LINES: usize = 20;
const MAX_DAEMON_LOG_LINES: usize = 200;
const MAX_DAEMON_STATUS_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DAEMON_LOG_TAIL_BYTES: usize = 2 * 1024 * 1024;
const SELF_PACKAGE_NAME: &str = "iris";
const MAX_SELF_UPGRADE_PLAN_BYTES: u64 = 512 * 1024;
const MAX_BOOTSTRAP_TEMP_FILE_ATTEMPTS: usize = 64;

static BOOTSTRAP_PLAN_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub type CommandResponse = IrisResponse;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SelfUpgradePhase {
    Staged,
    GenerationActivated,
}

impl SelfUpgradePhase {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::GenerationActivated => "generation_activated",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SelfUpgradePlan {
    staged_at: String,
    phase: SelfUpgradePhase,
    generation_before: Option<i64>,
    activated_generation: Option<i64>,
    from_state_schema: u32,
    target_state_schema: u32,
    package: PackageManifest,
}

#[derive(Debug, Clone)]
pub struct Iris {
    pub layout: StateLayout,
    pub db: IrisDb,
    pub store: ContentStore,
}

impl Iris {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let layout = StateLayout::new(root);
        layout.ensure()?;
        let db = IrisDb::open(&layout)?;
        let store = ContentStore::new(layout.clone());
        let app = Self { layout, db, store };
        app.reconcile_generation_state()?;
        Ok(app)
    }

    pub fn execute(&self, request: IrisRequest) -> Result<IrisResponse> {
        match request {
            IrisRequest::Ping => Ok(IrisResponse::success("pong")),
            IrisRequest::DaemonStatus => self.daemon_status(),
            IrisRequest::DaemonLog { lines } => self.daemon_log(lines),
            IrisRequest::SelfStatus => self.self_status(),
            IrisRequest::SelfStage { options } => self.self_stage(options),
            IrisRequest::SelfBootstrap { options } => self.self_bootstrap(options),
            IrisRequest::SelfUpdate { options } => self.self_update(options),
            IrisRequest::Install { packages, options } => self.install(&packages, options),
            IrisRequest::Remove { packages, options } => self.remove(&packages, options),
            IrisRequest::Purge { packages, options } => self.purge(&packages, options),
            IrisRequest::Update { packages, options } => self.update(&packages, options),
            IrisRequest::Search { query } => self.search(&query),
            IrisRequest::Info { package } => self.info(&package),
            IrisRequest::Verify { packages, full } => self.verify(&packages, full),
            IrisRequest::Repair { packages, options } => self.repair(&packages, options),
            IrisRequest::Audit => self.audit(),
            IrisRequest::GenerationList => self.generation_list(),
            IrisRequest::GenerationSwitch { generation } => self.generation_switch(generation),
            IrisRequest::GenerationRollback => self.generation_rollback(),
            IrisRequest::GenerationDiff { from, to } => self.generation_diff(from, to),
            IrisRequest::GenerationGc => self.generation_gc(),
            IrisRequest::OrphanList => self.orphan_list(),
            IrisRequest::OrphanShow { package } => self.orphan_show(&package),
            IrisRequest::OrphanPurge {
                package,
                force,
                options,
            } => self.orphan_purge(package.as_deref(), force, options),
            IrisRequest::RepoAdd { url, key } => self.repo_add(&url, &key),
            IrisRequest::RepoSync => self.repo_sync(),
            IrisRequest::History => self.history(),
            IrisRequest::Pin { package } => self.pin(&package),
            IrisRequest::Why { package } => self.why(&package),
        }
    }

    pub fn repo_add(&self, url: &str, key: &str) -> Result<CommandResponse> {
        validate_trusted_key(key)?;
        self.db.add_repo(url, key)?;
        CommandResponse::with_data(
            format!("Registered repository {}", url),
            json!({ "url": url, "key": key }),
        )
    }

    pub fn repo_sync(&self) -> Result<CommandResponse> {
        let summaries = sync_repositories(&self.layout, &self.db)?;
        let total: usize = summaries.iter().map(|item| item.manifests).sum();
        CommandResponse::with_data(
            format!(
                "Synchronized {} repositories and indexed {} manifests",
                summaries.len(),
                total
            ),
            summaries,
        )
    }

    pub fn search(&self, query: &str) -> Result<CommandResponse> {
        let matches = self.db.search_repo_packages(query)?;
        let mut lines = vec![format!("Search results for {query}:")];
        for record in &matches {
            lines.push(format!(
                "- {} {} — {}{}",
                record.manifest.package.name,
                record.manifest.package.version,
                record.manifest.package.summary,
                provenance_suffix(&record.manifest)
            ));
        }
        if matches.is_empty() {
            lines.push("(no matches)".into());
        }
        CommandResponse::with_data(lines.join("\n"), matches)
    }

    pub fn info(&self, package: &str) -> Result<CommandResponse> {
        let installed = self.db.installed_package(package)?;
        let repo = self.db.latest_repo_package(package)?;
        let data = json!({
            "package": package,
            "installed": installed.as_ref().map(installed_to_json),
            "repository": repo.as_ref().map(|record| manifest_to_json(&record.manifest)),
        });
        let mut lines = vec![format!("Package: {package}")];
        if let Some(installed) = installed {
            lines.push(format!(
                "Installed: {} {} ({})",
                installed.manifest.package.name,
                installed.manifest.package.version,
                installed.state.as_str()
            ));
            if let Some(source) = installed.manifest.package.source.as_ref() {
                lines.push(format!("Installed source: {}", format_source(source)));
            }
        }
        if let Some(repo) = repo {
            lines.push(format!(
                "Repository: {} {} — {}",
                repo.manifest.package.name,
                repo.manifest.package.version,
                repo.manifest.package.summary
            ));
            if let Some(source) = repo.manifest.package.source.as_ref() {
                lines.push(format!("Repository source: {}", format_source(source)));
            }
        }
        CommandResponse::with_data(lines.join("\n"), data)
    }

    fn self_status(&self) -> Result<CommandResponse> {
        let installed = self.db.installed_package(SELF_PACKAGE_NAME)?;
        let repo = self.db.latest_repo_package(SELF_PACKAGE_NAME)?;
        let state_schema_version = self.db.state_schema_version()?;
        let staged_bootstrap_plan = self.read_self_upgrade_plan()?;
        let repo_bootstrap_requirement = repo
            .as_ref()
            .and_then(|record| record.manifest.package.self_upgrade.as_ref());
        let managed = installed
            .as_ref()
            .is_some_and(|record| record.state == PackageState::Installed);
        let update_available = match (&installed, &repo) {
            (Some(installed), Some(repo)) if managed => {
                manifests_differ(&installed.manifest, &repo.manifest)
            }
            _ => false,
        };

        let data = json!({
            "package": SELF_PACKAGE_NAME,
            "managed": managed,
            "installed": installed.as_ref().map(installed_to_json),
            "repository": repo.as_ref().map(|record| manifest_to_json(&record.manifest)),
            "update_available": update_available,
            "state_schema_version": state_schema_version,
            "staged_bootstrap_plan": staged_bootstrap_plan.as_ref().map(self_upgrade_plan_to_json),
            "repository_bootstrap_requirement": repo_bootstrap_requirement.map(self_upgrade_to_json),
        });

        let mut lines = vec![format!("Self package: {SELF_PACKAGE_NAME}")];
        lines.push(format!(
            "Managed install: {}",
            if managed { "yes" } else { "no" }
        ));

        if let Some(installed) = &installed {
            lines.push(format!(
                "Installed: {} {} ({})",
                installed.manifest.package.name,
                installed.manifest.package.version,
                installed.state.as_str()
            ));
            if let Some(source) = installed.manifest.package.source.as_ref() {
                lines.push(format!("Installed source: {}", format_source(source)));
            }
        } else {
            lines.push("Installed: (not managed in this state root)".into());
        }

        if let Some(repo) = &repo {
            lines.push(format!(
                "Repository: {} {} — {}",
                repo.manifest.package.name,
                repo.manifest.package.version,
                repo.manifest.package.summary
            ));
            if let Some(source) = repo.manifest.package.source.as_ref() {
                lines.push(format!("Repository source: {}", format_source(source)));
            }
        } else {
            lines.push("Repository: (not present in synced indexes)".into());
        }

        lines.push(format!(
            "Update available: {}",
            if update_available { "yes" } else { "no" }
        ));
        lines.push(format!("State schema: {state_schema_version}"));
        if let Some(plan) = staged_bootstrap_plan.as_ref() {
            lines.push(format!(
                "Staged bootstrap plan: {} {} phase={} schema {} -> {}",
                plan.package.package.name,
                plan.package.package.version,
                plan.phase.as_str(),
                plan.from_state_schema,
                plan.target_state_schema
            ));
        } else {
            lines.push("Staged bootstrap plan: none".into());
        }
        if let Some(requirement) = repo_bootstrap_requirement {
            lines.push(format!(
                "Repository bootstrap requirement: yes (schema {} -> {})",
                requirement.from_state_schema, requirement.target_state_schema
            ));
        } else {
            lines.push("Repository bootstrap requirement: no".into());
        }

        CommandResponse::with_data(lines.join("\n"), data)
    }

    fn self_update(&self, options: OperationOptions) -> Result<CommandResponse> {
        self.require_managed_self_install()?;
        self.ensure_self_update_uses_ordinary_path()?;

        let package = [SELF_PACKAGE_NAME.to_string()];
        self.update(&package, options)
    }

    fn self_stage(&self, options: OperationOptions) -> Result<CommandResponse> {
        let installed = self.require_managed_self_install()?;
        let repo = self.latest_self_repo_package()?;
        let requirement = required_bootstrap_self_upgrade(&repo.manifest)?;

        if !manifests_differ(&installed.manifest, &repo.manifest) {
            return Err(IrisError::InvalidInput(
                "latest repository iris package is already installed; no staged bootstrap upgrade is needed"
                    .into(),
            ));
        }

        let state_schema_version = self.db.state_schema_version()?;
        if state_schema_version != requirement.from_state_schema {
            return Err(IrisError::InvalidInput(format!(
                "cannot stage bootstrap self-upgrade for state schema {} -> {} while current schema is {}",
                requirement.from_state_schema,
                requirement.target_state_schema,
                state_schema_version
            )));
        }

        if let Some(existing) = self.read_self_upgrade_plan()?
            && existing.phase == SelfUpgradePhase::GenerationActivated
        {
            return Err(IrisError::InvalidInput(
                "a bootstrap self-upgrade is already in progress; run `iris self bootstrap` to resume"
                    .into(),
            ));
        }

        let plan = SelfUpgradePlan {
            staged_at: Utc::now().to_rfc3339(),
            phase: SelfUpgradePhase::Staged,
            generation_before: self.db.current_generation_id()?,
            activated_generation: None,
            from_state_schema: requirement.from_state_schema,
            target_state_schema: requirement.target_state_schema,
            package: repo.manifest.clone(),
        };

        if options.dry_run {
            return CommandResponse::with_data(
                format!(
                    "Dry-run staged bootstrap self-upgrade for iris {} (schema {} -> {})",
                    plan.package.package.version, plan.from_state_schema, plan.target_state_schema
                ),
                json!({
                    "action": "self_stage",
                    "will_write_plan": false,
                    "plan_path": self.layout.bootstrap_plan_path(),
                    "plan": self_upgrade_plan_to_json(&plan),
                }),
            );
        }

        self.stage_package_payload(&repo.manifest, Path::new(&repo.payload_root))?;
        self.write_self_upgrade_plan(&plan)?;
        CommandResponse::with_data(
            format!(
                "Staged bootstrap self-upgrade for iris {} (schema {} -> {})",
                plan.package.package.version, plan.from_state_schema, plan.target_state_schema
            ),
            json!({
                "plan_path": self.layout.bootstrap_plan_path(),
                "plan": self_upgrade_plan_to_json(&plan),
            }),
        )
    }

    fn self_bootstrap(&self, options: OperationOptions) -> Result<CommandResponse> {
        let mut plan = self.read_self_upgrade_plan()?.ok_or_else(|| {
            IrisError::InvalidInput(
                "no staged bootstrap self-upgrade plan exists; run `iris self stage` first".into(),
            )
        })?;
        validate_self_upgrade_plan(&plan)?;

        if options.dry_run {
            let next_action = match plan.phase {
                SelfUpgradePhase::Staged => "activate_generation_and_migrate_schema",
                SelfUpgradePhase::GenerationActivated => "migrate_schema",
            };
            return CommandResponse::with_data(
                format!(
                    "Dry-run bootstrap self-upgrade for iris {} from phase {}",
                    plan.package.package.version,
                    plan.phase.as_str()
                ),
                json!({
                    "action": "self_bootstrap",
                    "next_action": next_action,
                    "plan": self_upgrade_plan_to_json(&plan),
                }),
            );
        }

        if plan.phase == SelfUpgradePhase::Staged {
            let generation_id = if let Some(generation_id) =
                self.current_generation_matches_manifest(&plan.package)?
            {
                generation_id
            } else {
                let current_packages = self.current_package_map()?;
                let orphan_records = self.db.list_orphans(None)?;
                let mut next_packages = current_packages.clone();
                next_packages.insert(SELF_PACKAGE_NAME.to_string(), plan.package.clone());
                self.activate_generation(
                    "self-bootstrap",
                    &[SELF_PACKAGE_NAME.to_string()],
                    &current_packages,
                    &next_packages,
                    &orphan_records,
                )?
            };

            plan.phase = SelfUpgradePhase::GenerationActivated;
            plan.activated_generation = Some(generation_id);
            self.write_self_upgrade_plan(&plan)?;
        }

        let generation_id = plan.activated_generation.ok_or_else(|| {
            IrisError::InvalidInput(
                "bootstrap self-upgrade plan is missing activated generation metadata".into(),
            )
        })?;
        let current_generation = self.db.current_generation_id()?;
        if current_generation != Some(generation_id) {
            return Err(IrisError::InvalidInput(format!(
                "bootstrap self-upgrade expects current generation {}, found {:?}",
                generation_id, current_generation
            )));
        }

        self.db.upsert_installed_package(
            &plan.package,
            PackageState::Installed,
            Some(generation_id),
        )?;
        self.clear_orphan_files(SELF_PACKAGE_NAME)?;

        let current_schema = self.db.state_schema_version()?;
        if current_schema == plan.target_state_schema {
            self.remove_self_upgrade_plan()?;
            return CommandResponse::with_data(
                format!(
                    "Bootstrap self-upgrade already applied for iris {}; removed completed plan",
                    plan.package.package.version
                ),
                json!({
                    "generation": generation_id,
                    "from_state_schema": plan.from_state_schema,
                    "target_state_schema": plan.target_state_schema,
                    "plan_removed": true,
                }),
            );
        }
        if current_schema != plan.from_state_schema {
            return Err(IrisError::InvalidInput(format!(
                "bootstrap self-upgrade expects current schema {}, found {}",
                plan.from_state_schema, current_schema
            )));
        }

        self.db.apply_self_schema_migration(
            &plan.package.package.version,
            plan.from_state_schema,
            plan.target_state_schema,
        )?;
        self.remove_self_upgrade_plan()?;

        CommandResponse::with_data(
            format!(
                "Bootstrapped iris {} and migrated state schema {} -> {}",
                plan.package.package.version, plan.from_state_schema, plan.target_state_schema
            ),
            json!({
                "generation": generation_id,
                "package": manifest_to_json(&plan.package),
                "from_state_schema": plan.from_state_schema,
                "target_state_schema": plan.target_state_schema,
                "plan_removed": true,
            }),
        )
    }

    pub fn install(
        &self,
        packages: &[String],
        options: OperationOptions,
    ) -> Result<CommandResponse> {
        if packages.is_empty() {
            return Err(IrisError::InvalidInput(
                "install requires at least one package".into(),
            ));
        }

        let before = self.db.current_generation_id()?;
        let current_packages = self.current_package_map()?;
        let orphan_records = self.db.list_orphans(None)?;
        let mut next_packages = current_packages.clone();
        let plan = self.resolve_install_plan(packages)?;

        for name in &plan.ordered {
            let repo = plan
                .packages
                .get(name)
                .ok_or_else(|| IrisError::PackageNotFound(name.clone()))?;
            self.stage_package_payload(&repo.manifest, Path::new(&repo.payload_root))?;
            next_packages.insert(name.clone(), repo.manifest.clone());
        }

        if options.dry_run {
            return CommandResponse::with_data(
                format!(
                    "Dry-run install for {} requested package(s) resolving to {} total package(s)",
                    plan.requested.len(),
                    plan.ordered.len()
                ),
                json!({
                    "action": "install",
                    "requested_packages": plan.requested,
                    "resolved_packages": plan.ordered,
                    "current_generation": before,
                    "next_package_count": next_packages.len()
                }),
            );
        }

        let generation_id = self.activate_generation(
            "install",
            &plan.requested,
            &current_packages,
            &next_packages,
            &orphan_records,
        )?;

        for name in &plan.ordered {
            let manifest = next_packages
                .get(name)
                .ok_or_else(|| IrisError::PackageNotFound(name.clone()))?;
            self.db.upsert_installed_package(
                manifest,
                PackageState::Installed,
                Some(generation_id),
            )?;
            self.clear_orphan_files(name)?;
        }

        CommandResponse::with_data(
            format!(
                "Installed {} requested package(s) resolving to {} total package(s) into generation {}",
                plan.requested.len(),
                plan.ordered.len(),
                generation_id
            ),
            json!({
                "generation": generation_id,
                "requested_packages": plan.requested,
                "resolved_packages": plan.ordered,
            }),
        )
    }

    pub fn update(
        &self,
        packages: &[String],
        options: OperationOptions,
    ) -> Result<CommandResponse> {
        let installed = self.db.list_installed_packages()?;
        let installed_map: BTreeMap<String, InstalledPackageRecord> = installed
            .into_iter()
            .map(|record| (record.manifest.package.name.clone(), record))
            .collect();
        let pinned = self.db.pinned_packages()?;

        let targets: Vec<String> = if packages.is_empty() {
            installed_map
                .keys()
                .filter(|name| !pinned.contains_key(*name))
                .cloned()
                .collect()
        } else {
            packages.to_vec()
        };

        if targets.is_empty() {
            return CommandResponse::success("No packages eligible for update").pipe(Ok);
        }

        let mut changed = Vec::new();
        for name in &targets {
            let Some(installed) = installed_map.get(name) else {
                return Err(IrisError::PackageNotInstalled(name.clone()));
            };
            let Some(repo) = self.db.latest_repo_package(name)? else {
                continue;
            };
            if repo.manifest.package.version != installed.manifest.package.version
                || repo.manifest.package.revision != installed.manifest.package.revision
            {
                changed.push(name.clone());
            }
        }

        if changed.is_empty() {
            return CommandResponse::success("All target packages are already up to date").pipe(Ok);
        }

        if changed.iter().any(|name| name == SELF_PACKAGE_NAME) {
            self.ensure_self_update_uses_ordinary_path()?;
        }

        self.install(&changed, options)
    }

    pub fn remove(
        &self,
        packages: &[String],
        options: OperationOptions,
    ) -> Result<CommandResponse> {
        if packages.is_empty() {
            return Err(IrisError::InvalidInput(
                "remove requires at least one package".into(),
            ));
        }
        let current_packages = self.current_package_map()?;
        self.ensure_removal_is_safe(&current_packages, packages)?;
        let mut next_packages = current_packages.clone();
        let mut orphan_records = self.db.list_orphans(None)?;

        for name in packages {
            let installed = self
                .db
                .installed_package(name)?
                .ok_or_else(|| IrisError::PackageNotInstalled(name.clone()))?;
            self.capture_orphans_for_package(
                &installed.manifest,
                &mut orphan_records,
                options.dry_run,
            )?;
            next_packages.remove(name);
        }

        if options.dry_run {
            return CommandResponse::with_data(
                format!("Dry-run remove for {} package(s)", packages.len()),
                json!({
                    "action": "remove",
                    "packages": packages,
                    "orphan_count": orphan_records.len(),
                }),
            );
        }

        let generation_id = self.activate_generation(
            "remove",
            packages,
            &current_packages,
            &next_packages,
            &orphan_records,
        )?;

        for name in packages {
            let installed = self
                .db
                .installed_package(name)?
                .ok_or_else(|| IrisError::PackageNotInstalled(name.clone()))?;
            self.db.upsert_installed_package(
                &installed.manifest,
                PackageState::OrphanedConfig,
                Some(generation_id),
            )?;
            let records: Vec<OrphanRecord> = orphan_records
                .iter()
                .filter(|item| item.package_name == *name)
                .cloned()
                .collect();
            self.db.replace_orphans(name, &records)?;
        }

        CommandResponse::with_data(
            format!(
                "Removed {} package(s); configuration retained as orphaned state",
                packages.len()
            ),
            json!({ "generation": generation_id, "packages": packages }),
        )
    }

    pub fn purge(&self, packages: &[String], options: OperationOptions) -> Result<CommandResponse> {
        if packages.is_empty() {
            return Err(IrisError::InvalidInput(
                "purge requires at least one package".into(),
            ));
        }
        let current_packages = self.current_package_map()?;
        self.ensure_removal_is_safe(&current_packages, packages)?;
        let mut next_packages = current_packages.clone();
        let mut orphan_records = self.db.list_orphans(None)?;

        for name in packages {
            next_packages.remove(name);
            orphan_records.retain(|record| record.package_name != *name);
        }

        if options.dry_run {
            return CommandResponse::with_data(
                format!("Dry-run purge for {} package(s)", packages.len()),
                json!({ "action": "purge", "packages": packages }),
            );
        }

        let generation_id = self.activate_generation(
            "purge",
            packages,
            &current_packages,
            &next_packages,
            &orphan_records,
        )?;

        for name in packages {
            self.db.remove_installed_package(name)?;
            self.db.delete_orphans(Some(name))?;
            self.clear_orphan_files(name)?;
        }

        CommandResponse::with_data(
            format!(
                "Purged {} package(s) and associated orphaned configuration",
                packages.len()
            ),
            json!({ "generation": generation_id, "packages": packages }),
        )
    }

    pub fn verify(&self, packages: &[String], full: bool) -> Result<CommandResponse> {
        let report = self.verify_current_generation(packages, full)?;
        let summary = if report.is_clean() {
            format!(
                "Verification succeeded: checked {} file(s) in {} mode",
                report.checked_files, report.mode
            )
        } else {
            format!(
                "Verification found {} issue(s) across {} file(s) in {} mode",
                report.issues.len(),
                report.checked_files,
                report.mode
            )
        };
        CommandResponse::with_data(summary, report)
    }

    pub fn repair(
        &self,
        packages: &[String],
        options: OperationOptions,
    ) -> Result<CommandResponse> {
        let report = self.verify_current_generation(packages, true)?;
        let current_dir = self.current_generation_dir()?;
        let current_packages = self.current_package_map()?;
        let mut actions = Vec::new();

        for issue in report.issues {
            let Some(manifest) = current_packages.get(&issue.package) else {
                continue;
            };
            let Some(file) = manifest.files.iter().find(|entry| entry.path == issue.path) else {
                continue;
            };
            let target = current_dir.join(&file.path);
            let result = if options.dry_run {
                "planned".to_string()
            } else {
                self.repair_file(manifest, file, &target)?;
                "repaired".to_string()
            };
            actions.push(RepairAction {
                package: issue.package,
                path: issue.path,
                action: issue.kind,
                result,
            });
        }

        if !options.dry_run && !actions.is_empty() {
            let mut log = String::new();
            for action in &actions {
                log.push_str(&format!(
                    "{} {} {} {}\n",
                    Utc::now().to_rfc3339(),
                    action.package,
                    action.path,
                    action.result
                ));
            }
            fs::write(self.layout.repair_log_path(), log)?;
        }

        CommandResponse::with_data(
            format!(
                "Repair {} {} action(s)",
                if options.dry_run {
                    "planned"
                } else {
                    "performed"
                },
                actions.len()
            ),
            actions,
        )
    }

    pub fn audit(&self) -> Result<CommandResponse> {
        let repositories = self.db.repositories()?;
        let indexed = self.db.search_repo_packages("")?;
        let installed = self.db.list_installed_packages()?;
        let pins = self.db.pinned_packages()?;
        let orphans = self.db.list_orphans(None)?;
        let mut findings = Vec::new();
        let trusted_keys: BTreeMap<String, String> = repositories.iter().cloned().collect();

        for record in &indexed {
            match trusted_keys.get(&record.source_url) {
                Some(key) => {
                    if let Err(err) = verify_manifest_signature(&record.manifest, key) {
                        findings.push(audit_finding(
                            "repository",
                            &format!(
                                "{} {}",
                                record.manifest.package.name, record.manifest.package.version
                            ),
                            "error",
                            &err.to_string(),
                        ));
                    }
                }
                None => findings.push(audit_finding(
                    "repository",
                    &record.source_url,
                    "error",
                    "indexed package has no registered trust root",
                )),
            }
        }

        let verify = if self.db.current_generation_id()?.is_some() {
            self.verify_current_generation(&[], true)?
        } else {
            VerifyReport {
                mode: "full".into(),
                ..VerifyReport::default()
            }
        };

        for issue in &verify.issues {
            findings.push(audit_finding(
                "verify",
                &format!("{}:{}", issue.package, issue.path),
                &issue.severity,
                &issue.detail,
            ));
        }

        for orphan in orphans.iter().filter(|orphan| orphan.modified) {
            findings.push(audit_finding(
                "orphan",
                &format!("{}:{}", orphan.package_name, orphan.path),
                "warning",
                "orphaned configuration differs from packaged default",
            ));
        }

        let status = if findings.iter().any(|item| item.severity == "error") {
            "error"
        } else if findings.iter().any(|item| item.severity == "warning") {
            "warning"
        } else {
            "ok"
        };
        let report = AuditReport {
            status: status.into(),
            repositories: repositories.len(),
            indexed_packages: indexed.len(),
            installed_packages: installed.len(),
            pinned_packages: pins.len(),
            orphaned_configs: orphans.len(),
            verify,
            findings,
        };
        CommandResponse::with_data(
            format!(
                "Audit completed with status {} and {} finding(s)",
                report.status,
                report.findings.len()
            ),
            report,
        )
    }

    pub fn generation_list(&self) -> Result<CommandResponse> {
        let generations = self.db.list_generations()?;
        let mut lines = vec!["Generations:".to_string()];
        for generation in &generations {
            lines.push(format!(
                "- {}{} packages={} created={}",
                generation.id,
                if generation.current { " (current)" } else { "" },
                generation.package_count,
                generation.created_at
            ));
        }
        CommandResponse::with_data(lines.join("\n"), generations)
    }

    pub fn generation_switch(&self, generation_id: i64) -> Result<CommandResponse> {
        let dir = self.layout.generation_dir(generation_id);
        if !dir.exists() {
            return Err(IrisError::InvalidInput(format!(
                "generation {} does not exist",
                generation_id
            )));
        }
        let before = self.db.current_generation_id()?;
        self.atomic_switch_current(generation_id)?;
        if let Err(err) = self.db.set_current_generation(generation_id) {
            self.restore_current_link(before);
            return Err(err);
        }
        CommandResponse::with_data(
            format!("Switched current generation to {}", generation_id),
            json!({ "generation": generation_id }),
        )
    }

    pub fn generation_rollback(&self) -> Result<CommandResponse> {
        let generations = self.db.list_generations()?;
        let current = generations
            .iter()
            .find(|item| item.current)
            .map(|item| item.id);
        let Some(current) = current else {
            return Err(IrisError::NoCurrentGeneration);
        };
        let Some(previous) = generations.into_iter().find(|item| item.id < current) else {
            return Err(IrisError::InvalidInput(
                "no previous generation to roll back to".into(),
            ));
        };
        self.generation_switch(previous.id)
    }

    pub fn generation_diff(&self, from: i64, to: i64) -> Result<CommandResponse> {
        let left = self.db.generation_packages(from)?;
        let right = self.db.generation_packages(to)?;
        let mut diffs = Vec::new();
        let names: BTreeSet<_> = left.keys().chain(right.keys()).cloned().collect();
        for name in names {
            match (left.get(&name), right.get(&name)) {
                (None, Some(newer)) => {
                    diffs.push(format!("added {} {}", name, newer.package.version))
                }
                (Some(_), None) => diffs.push(format!("removed {}", name)),
                (Some(old), Some(new))
                    if old.package.version != new.package.version
                        || old.package.revision != new.package.revision =>
                {
                    diffs.push(format!(
                        "changed {} {} -> {}",
                        name, old.package.version, new.package.version
                    ))
                }
                _ => {}
            }
        }
        CommandResponse::with_data(
            format!("Generation diff {}..{}", from, to),
            json!({ "from": from, "to": to, "diffs": diffs }),
        )
    }

    pub fn generation_gc(&self) -> Result<CommandResponse> {
        let generations = self.db.list_generations()?;
        let keep_ids: BTreeSet<i64> = generations
            .iter()
            .take(DEFAULT_GENERATIONS_KEEP)
            .map(|item| item.id)
            .chain(
                generations
                    .iter()
                    .filter(|item| item.current)
                    .map(|item| item.id),
            )
            .collect();

        let mut deleted = Vec::new();
        for generation in generations {
            if keep_ids.contains(&generation.id) {
                continue;
            }
            let dir = self.layout.generation_dir(generation.id);
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
            }
            self.db.delete_generation(generation.id)?;
            deleted.push(generation.id);
        }

        let hashes = self.referenced_hashes(&keep_ids)?;
        let mut reclaimed = Vec::new();
        for prefix_entry in fs::read_dir(self.layout.store_dir())? {
            let prefix_entry = prefix_entry?;
            if !prefix_entry.file_type()?.is_dir() {
                continue;
            }
            for object in fs::read_dir(prefix_entry.path())? {
                let object = object?;
                if !object.file_type()?.is_file() {
                    continue;
                }
                let hash = object.file_name().to_string_lossy().to_string();
                if !hashes.contains(&hash) {
                    fs::remove_file(object.path())?;
                    reclaimed.push(hash);
                }
            }
        }

        CommandResponse::with_data(
            format!(
                "GC removed {} generation(s) and {} store object(s)",
                deleted.len(),
                reclaimed.len()
            ),
            json!({ "deleted_generations": deleted, "reclaimed_hashes": reclaimed }),
        )
    }

    pub fn orphan_list(&self) -> Result<CommandResponse> {
        let orphans = self.db.list_orphans(None)?;
        let mut lines = vec!["Orphaned configuration:".to_string()];
        for orphan in &orphans {
            lines.push(format!(
                "- {} {} modified={}",
                orphan.package_name, orphan.path, orphan.modified
            ));
        }
        if orphans.is_empty() {
            lines.push("(none)".into());
        }
        CommandResponse::with_data(lines.join("\n"), orphans)
    }

    pub fn orphan_show(&self, package: &str) -> Result<CommandResponse> {
        let orphans = self.db.list_orphans(Some(package))?;
        CommandResponse::with_data(format!("Orphans for {package}"), orphans)
    }

    pub fn orphan_purge(
        &self,
        package: Option<&str>,
        force: bool,
        options: OperationOptions,
    ) -> Result<CommandResponse> {
        let entries = self.db.list_orphans(package)?;
        if entries.iter().any(|entry| entry.modified) && !force && !options.yes {
            return Err(IrisError::InvalidInput(
                "modified orphaned configuration exists; re-run with --force or --yes".into(),
            ));
        }
        if options.dry_run {
            return CommandResponse::with_data("Dry-run orphan purge".to_string(), entries);
        }

        match package {
            Some(package) => self.clear_orphan_files(package)?,
            None => {
                if self.layout.orphans_dir().exists() {
                    fs::remove_dir_all(self.layout.orphans_dir())?;
                }
                fs::create_dir_all(self.layout.orphans_dir())?;
            }
        }
        self.db.delete_orphans(package)?;
        CommandResponse::with_data(
            "Purged orphaned configuration".to_string(),
            json!({ "purged": entries.len() }),
        )
    }

    pub fn history(&self) -> Result<CommandResponse> {
        let history = self.db.list_history()?;
        CommandResponse::with_data("Operation history".to_string(), history)
    }

    pub fn daemon_status(&self) -> Result<CommandResponse> {
        let latest = read_bounded_json_artifact(
            &self.layout.daemon_status_path(),
            MAX_DAEMON_STATUS_BYTES,
            "daemon status artifact",
        )?;
        let message = if latest.is_some() {
            "Read latest daemon verify status"
        } else {
            "No daemon verify status recorded yet"
        };
        CommandResponse::with_data(message.to_string(), DaemonStatusReadout { latest })
    }

    pub fn daemon_log(&self, lines: usize) -> Result<CommandResponse> {
        let limit = clamp_daemon_log_lines(lines);
        let (entries, truncated) =
            read_daemon_log_entries(&self.layout.daemon_verify_log_path(), limit)?;
        let message = if entries.is_empty() {
            "No daemon verify log entries recorded yet".to_string()
        } else if truncated {
            format!(
                "Read {} daemon verify log {} from bounded tail",
                entries.len(),
                daemon_log_entry_label(entries.len())
            )
        } else {
            format!(
                "Read {} daemon verify log {}",
                entries.len(),
                daemon_log_entry_label(entries.len())
            )
        };
        CommandResponse::with_data(
            message,
            DaemonLogReadout {
                entries,
                limit,
                truncated,
            },
        )
    }

    pub fn pin(&self, package: &str) -> Result<CommandResponse> {
        let installed = self
            .db
            .installed_package(package)?
            .ok_or_else(|| IrisError::PackageNotInstalled(package.into()))?;
        let constraint = format!("={}", installed.manifest.package.version);
        self.db.pin_package(package, &constraint)?;
        CommandResponse::with_data(
            format!("Pinned {} {}", package, installed.manifest.package.version),
            json!({ "package": package, "constraint": constraint }),
        )
    }

    pub fn why(&self, package: &str) -> Result<CommandResponse> {
        let current = self.current_package_map()?;
        let mut parents = Vec::new();
        for (name, manifest) in &current {
            if manifest
                .dependencies
                .runtime
                .iter()
                .any(|dep| dep.name == package)
            {
                parents.push(name.clone());
            }
        }
        let message = if parents.is_empty() {
            format!(
                "{} is explicitly installed or has no reverse dependencies",
                package
            )
        } else {
            format!("{} is required by: {}", package, parents.join(", "))
        };
        CommandResponse::with_data(
            message,
            json!({ "package": package, "required_by": parents }),
        )
    }

    fn current_package_map(&self) -> Result<BTreeMap<String, PackageManifest>> {
        match self.db.current_generation_id()? {
            Some(id) => self.db.generation_packages(id),
            None => Ok(BTreeMap::new()),
        }
    }

    fn require_managed_self_install(&self) -> Result<InstalledPackageRecord> {
        let Some(installed) = self.db.installed_package(SELF_PACKAGE_NAME)? else {
            return Err(IrisError::PackageNotInstalled(SELF_PACKAGE_NAME.into()));
        };
        if installed.state != PackageState::Installed {
            return Err(IrisError::PackageNotInstalled(SELF_PACKAGE_NAME.into()));
        }
        Ok(installed)
    }

    fn latest_self_repo_package(&self) -> Result<RepoPackageRecord> {
        self.db
            .latest_repo_package(SELF_PACKAGE_NAME)?
            .ok_or_else(|| IrisError::PackageNotFound(SELF_PACKAGE_NAME.into()))
    }

    fn ensure_self_update_uses_ordinary_path(&self) -> Result<()> {
        let Some(repo) = self.db.latest_repo_package(SELF_PACKAGE_NAME)? else {
            return Ok(());
        };
        let Some(requirement) = repo.manifest.package.self_upgrade.as_ref() else {
            return Ok(());
        };
        Err(IrisError::InvalidInput(format!(
            "repository iris {} requires staged/bootstrap self-upgrade (schema {} -> {}); run `iris self stage` then `iris self bootstrap`",
            repo.manifest.package.version,
            requirement.from_state_schema,
            requirement.target_state_schema
        )))
    }

    fn current_generation_matches_manifest(
        &self,
        manifest: &PackageManifest,
    ) -> Result<Option<i64>> {
        let Some(generation_id) = self.db.current_generation_id()? else {
            return Ok(None);
        };
        let packages = self.current_package_map()?;
        let Some(current) = packages.get(&manifest.package.name) else {
            return Ok(None);
        };
        if manifests_differ(current, manifest) {
            return Ok(None);
        }
        Ok(Some(generation_id))
    }

    fn read_self_upgrade_plan(&self) -> Result<Option<SelfUpgradePlan>> {
        read_bounded_json_artifact(
            &self.layout.bootstrap_plan_path(),
            MAX_SELF_UPGRADE_PLAN_BYTES,
            "bootstrap self-upgrade plan",
        )
    }

    fn write_self_upgrade_plan(&self, plan: &SelfUpgradePlan) -> Result<()> {
        validate_self_upgrade_plan(plan)?;
        let expected_uid = current_effective_uid()?;
        prepare_secure_private_directory(
            &self.layout.bootstrap_dir(),
            expected_uid,
            "bootstrap state directory",
        )?;
        let bytes = serde_json::to_vec_pretty(plan)?;
        write_atomic_private_artifact_file(
            &self.layout.bootstrap_plan_path(),
            &bytes,
            expected_uid,
            "bootstrap self-upgrade plan",
        )
    }

    fn remove_self_upgrade_plan(&self) -> Result<()> {
        let path = self.layout.bootstrap_plan_path();
        let expected_uid = current_effective_uid()?;
        prepare_secure_private_directory(
            &self.layout.bootstrap_dir(),
            expected_uid,
            "bootstrap state directory",
        )?;
        validate_existing_private_artifact_path(
            &path,
            expected_uid,
            "bootstrap self-upgrade plan",
        )?;
        match fs::remove_file(&path) {
            Ok(()) => sync_parent_dir(&path),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn resolve_install_plan(&self, packages: &[String]) -> Result<ResolvedInstallPlan> {
        let requested = unique_packages(packages);
        let pins = self.db.pinned_packages()?;
        let mut resolved = BTreeMap::new();
        let mut ordered = Vec::new();
        let mut visiting = BTreeSet::new();

        for package in &requested {
            self.resolve_package(
                package,
                None,
                &pins,
                &mut resolved,
                &mut ordered,
                &mut visiting,
            )?;
        }

        Ok(ResolvedInstallPlan {
            requested,
            ordered,
            packages: resolved,
        })
    }

    fn resolve_package(
        &self,
        name: &str,
        constraint: Option<&str>,
        pins: &BTreeMap<String, String>,
        resolved: &mut BTreeMap<String, RepoPackageRecord>,
        ordered: &mut Vec<String>,
        visiting: &mut BTreeSet<String>,
    ) -> Result<()> {
        if let Some(existing) = resolved.get(name) {
            if let Some(constraint) = constraint
                && !version_satisfies_constraint(&existing.manifest.package.version, constraint)
            {
                return Err(IrisError::DependencyResolution(format!(
                    "{} {} does not satisfy dependency constraint {}",
                    name, existing.manifest.package.version, constraint
                )));
            }
            if let Some(pin) = pins.get(name)
                && !version_satisfies_constraint(&existing.manifest.package.version, pin)
            {
                return Err(IrisError::DependencyResolution(format!(
                    "{} {} violates pin constraint {}",
                    name, existing.manifest.package.version, pin
                )));
            }
            return Ok(());
        }

        if !visiting.insert(name.to_string()) {
            return Err(IrisError::DependencyResolution(format!(
                "dependency cycle detected involving {}",
                name
            )));
        }

        let selected = self.select_repo_package(name, constraint, pins)?;
        for dependency in &selected.manifest.dependencies.runtime {
            self.resolve_package(
                &dependency.name,
                Some(&dependency.version),
                pins,
                resolved,
                ordered,
                visiting,
            )?;
        }

        visiting.remove(name);
        ordered.push(name.to_string());
        resolved.insert(name.to_string(), selected);
        Ok(())
    }

    fn select_repo_package(
        &self,
        name: &str,
        constraint: Option<&str>,
        pins: &BTreeMap<String, String>,
    ) -> Result<RepoPackageRecord> {
        let candidates = self.db.repo_packages_for_name(name)?;
        if candidates.is_empty() {
            return Err(IrisError::PackageNotFound(name.into()));
        }

        let pin = pins.get(name).map(String::as_str);
        candidates
            .into_iter()
            .find(|candidate| {
                constraint.is_none_or(|value| {
                    version_satisfies_constraint(&candidate.manifest.package.version, value)
                }) && pin.is_none_or(|value| {
                    version_satisfies_constraint(&candidate.manifest.package.version, value)
                })
            })
            .ok_or_else(|| {
                let mut parts = Vec::new();
                if let Some(constraint) = constraint.filter(|value| !value.trim().is_empty()) {
                    parts.push(format!("dependency {}", constraint));
                }
                if let Some(pin) = pin {
                    parts.push(format!("pin {}", pin));
                }
                let details = if parts.is_empty() {
                    "available constraints".to_string()
                } else {
                    parts.join(" and ")
                };
                IrisError::DependencyResolution(format!(
                    "no repository version of {} satisfies {}",
                    name, details
                ))
            })
    }

    fn ensure_removal_is_safe(
        &self,
        current_packages: &BTreeMap<String, PackageManifest>,
        packages: &[String],
    ) -> Result<()> {
        let removing: BTreeSet<_> = packages.iter().cloned().collect();
        for (name, manifest) in current_packages {
            if removing.contains(name) {
                continue;
            }
            for dependency in &manifest.dependencies.runtime {
                if removing.contains(&dependency.name) {
                    return Err(IrisError::DependencyResolution(format!(
                        "cannot remove {} because it is required by {}",
                        dependency.name, name
                    )));
                }
            }
        }
        Ok(())
    }

    fn stage_package_payload(&self, manifest: &PackageManifest, payload_root: &Path) -> Result<()> {
        for file in &manifest.files {
            let source = payload_root.join(&file.path);
            if !source.exists() {
                return Err(IrisError::MissingPayload {
                    package: manifest.package.name.clone(),
                    path: source,
                });
            }
            self.store.import_file(&source, Some(&file.blake3))?;
        }
        Ok(())
    }

    fn activate_generation(
        &self,
        action: &str,
        packages: &[String],
        previous_packages: &BTreeMap<String, PackageManifest>,
        next_packages: &BTreeMap<String, PackageManifest>,
        orphan_records: &[OrphanRecord],
    ) -> Result<i64> {
        let before = self.db.current_generation_id()?;
        let generation_id = self.db.next_generation_id()?;
        let txn_root =
            self.layout
                .tmp_dir()
                .join(format!("txn-{}-{}", generation_id, Utc::now().timestamp()));
        fs::create_dir_all(&txn_root)?;
        self.build_generation_tree(&txn_root, previous_packages, next_packages, orphan_records)?;

        let final_dir = self.layout.generation_dir(generation_id);
        fs::rename(&txn_root, &final_dir)?;
        if let Err(err) = self.atomic_switch_current(generation_id) {
            let _ = fs::remove_dir_all(&final_dir);
            return Err(err);
        }
        if let Err(err) =
            self.db
                .activate_generation(generation_id, before, next_packages, action, packages)
        {
            self.restore_current_link(before);
            let _ = fs::remove_dir_all(&final_dir);
            return Err(err);
        }
        Ok(generation_id)
    }

    fn build_generation_tree(
        &self,
        root: &Path,
        previous_packages: &BTreeMap<String, PackageManifest>,
        next_packages: &BTreeMap<String, PackageManifest>,
        orphan_records: &[OrphanRecord],
    ) -> Result<()> {
        let current_dir = self
            .db
            .current_generation_id()?
            .map(|id| self.layout.generation_dir(id));
        let mut claimed = HashMap::<String, String>::new();
        for (name, manifest) in next_packages {
            let previous = previous_packages.get(name);
            self.materialize_package(
                root,
                manifest,
                previous,
                current_dir.as_deref(),
                orphan_records,
                &mut claimed,
            )?;
        }
        for orphan in orphan_records {
            if next_packages.contains_key(&orphan.package_name) {
                continue;
            }
            if let Some(existing) = claimed.get(&orphan.path) {
                return Err(IrisError::PathConflict {
                    path: orphan.path.clone(),
                    first: existing.clone(),
                    second: format!("orphan:{}", orphan.package_name),
                });
            }
            let source = self
                .layout
                .orphan_file_dir(&orphan.package_name)
                .join(&orphan.path);
            let destination = root.join(&orphan.path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source, &destination)?;
            claimed.insert(
                orphan.path.clone(),
                format!("orphan:{}", orphan.package_name),
            );
        }
        Ok(())
    }

    fn materialize_package(
        &self,
        root: &Path,
        manifest: &PackageManifest,
        previous: Option<&PackageManifest>,
        current_dir: Option<&Path>,
        orphan_records: &[OrphanRecord],
        claimed: &mut HashMap<String, String>,
    ) -> Result<()> {
        for file in &manifest.files {
            if let Some(existing) = claimed.insert(file.path.clone(), manifest.package.name.clone())
            {
                return Err(IrisError::PathConflict {
                    path: file.path.clone(),
                    first: existing,
                    second: manifest.package.name.clone(),
                });
            }

            let destination = root.join(&file.path);
            match file.file_type {
                FileType::Binary | FileType::Data => {
                    self.store.symlink_object(&file.blake3, &destination)?
                }
                FileType::Config => {
                    self.materialize_config(
                        root,
                        manifest,
                        file,
                        previous,
                        current_dir,
                        orphan_records,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn materialize_config(
        &self,
        root: &Path,
        manifest: &PackageManifest,
        file: &FileEntry,
        previous: Option<&PackageManifest>,
        current_dir: Option<&Path>,
        orphan_records: &[OrphanRecord],
    ) -> Result<()> {
        let destination = root.join(&file.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }

        if let Some(orphan) = orphan_records
            .iter()
            .find(|entry| entry.package_name == manifest.package.name && entry.path == file.path)
        {
            let source = self
                .layout
                .orphan_file_dir(&orphan.package_name)
                .join(&orphan.path);
            fs::copy(source, &destination)?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(file.mode_bits()?))?;
            return Ok(());
        }

        let old_default = previous.and_then(|old| old.file_map().get(file.path.as_str()).copied());
        if let (Some(current_dir), Some(old_default)) = (current_dir, old_default) {
            let current_path = current_dir.join(&file.path);
            if current_path.exists() {
                let current_hash = ContentStore::hash_path(&current_path)?;
                if current_hash != old_default.blake3 {
                    match file.merge_strategy.unwrap_or(MergeStrategy::ThreeWay) {
                        MergeStrategy::Overwrite => {
                            self.store
                                .copy_object_to(&file.blake3, &destination, file)?;
                        }
                        MergeStrategy::ThreeWay => {
                            fs::copy(&current_path, &destination)?;
                            fs::set_permissions(
                                &destination,
                                fs::Permissions::from_mode(file.mode_bits()?),
                            )?;
                            let new_path = destination.with_extension("iris-new");
                            let orig_path = destination.with_extension("iris-orig");
                            self.store.copy_object_to(&file.blake3, &new_path, file)?;
                            self.store.copy_object_to(
                                &old_default.blake3,
                                &orig_path,
                                old_default,
                            )?;
                        }
                    }
                    return Ok(());
                }
            }
        }

        self.store
            .copy_object_to(&file.blake3, &destination, file)?;
        Ok(())
    }

    fn capture_orphans_for_package(
        &self,
        manifest: &PackageManifest,
        orphan_records: &mut Vec<OrphanRecord>,
        dry_run: bool,
    ) -> Result<()> {
        let current_dir = self.current_generation_dir()?;
        let package_orphan_dir = self.layout.orphan_file_dir(&manifest.package.name);
        if !dry_run {
            fs::create_dir_all(&package_orphan_dir)?;
        }
        orphan_records.retain(|record| record.package_name != manifest.package.name);

        for file in manifest
            .files
            .iter()
            .filter(|entry| entry.file_type == FileType::Config)
        {
            let current_path = current_dir.join(&file.path);
            if !current_path.exists() {
                continue;
            }
            let current_hash = ContentStore::hash_path(&current_path)?;
            if !dry_run {
                let orphan_path = package_orphan_dir.join(&file.path);
                if let Some(parent) = orphan_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&current_path, orphan_path)?;
            }
            orphan_records.push(OrphanRecord {
                package_name: manifest.package.name.clone(),
                path: file.path.clone(),
                default_hash: file.blake3.clone(),
                current_hash,
                modified: file.blake3 != ContentStore::hash_path(&current_path)?,
            });
        }
        Ok(())
    }

    fn current_generation_dir(&self) -> Result<PathBuf> {
        let generation_id = self
            .db
            .current_generation_id()?
            .ok_or(IrisError::NoCurrentGeneration)?;
        Ok(self.layout.generation_dir(generation_id))
    }

    fn reconcile_generation_state(&self) -> Result<()> {
        Self::remove_file_like_if_exists(&self.layout.generations_dir().join(".current-new"))?;
        self.sync_current_link_with_db()?;

        let registered: BTreeSet<_> = self
            .db
            .list_generations()?
            .into_iter()
            .map(|generation| generation.id)
            .collect();
        for entry in fs::read_dir(self.layout.generations_dir())? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name == "current" || name == ".current-new" {
                continue;
            }
            let Ok(generation_id) = name.parse::<i64>() else {
                continue;
            };
            if registered.contains(&generation_id) {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(IrisError::InvalidInput(format!(
                    "unregistered generation path is not a directory: {}",
                    path.display()
                )));
            }
            fs::remove_dir_all(path)?;
        }
        Ok(())
    }

    fn sync_current_link_with_db(&self) -> Result<()> {
        match self.db.current_generation_id()? {
            Some(generation_id) => {
                let generation_dir = self.layout.generation_dir(generation_id);
                if !generation_dir.exists() {
                    return Err(IrisError::InvalidInput(format!(
                        "current generation {} directory is missing: {}",
                        generation_id,
                        generation_dir.display()
                    )));
                }
                self.atomic_switch_current(generation_id)
            }
            None => Self::remove_file_like_if_exists(&self.layout.current_link()),
        }
    }

    fn restore_current_link(&self, generation_id: Option<i64>) {
        let _ = match generation_id {
            Some(id) => self.atomic_switch_current(id),
            None => Self::remove_file_like_if_exists(&self.layout.current_link()),
        };
    }

    fn remove_file_like_if_exists(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    return Err(IrisError::InvalidInput(format!(
                        "refusing to remove directory where file or symlink is expected: {}",
                        path.display()
                    )));
                }
                fs::remove_file(path)?;
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn atomic_switch_current(&self, generation_id: i64) -> Result<()> {
        let current_tmp = self.layout.generations_dir().join(".current-new");
        Self::remove_file_like_if_exists(&current_tmp)?;
        symlink(self.layout.generation_dir(generation_id), &current_tmp)?;
        fs::rename(current_tmp, self.layout.current_link())?;
        Ok(())
    }

    fn verify_current_generation(&self, packages: &[String], full: bool) -> Result<VerifyReport> {
        let current_dir = self.current_generation_dir()?;
        let current_packages = self.current_package_map()?;
        let filter: Option<BTreeSet<_>> =
            (!packages.is_empty()).then(|| packages.iter().cloned().collect());
        let mut report = VerifyReport {
            mode: if full { "full" } else { "fast" }.into(),
            ..VerifyReport::default()
        };

        for (name, manifest) in current_packages {
            if filter.as_ref().is_some_and(|set| !set.contains(&name)) {
                continue;
            }
            report.checked_packages += 1;
            for file in &manifest.files {
                report.checked_files += 1;
                let target = current_dir.join(&file.path);
                match file.file_type {
                    FileType::Binary | FileType::Data => {
                        let meta = match fs::symlink_metadata(&target) {
                            Ok(meta) => meta,
                            Err(_) => {
                                report.issues.push(issue(
                                    &name,
                                    &file.path,
                                    "missing",
                                    "error",
                                    "managed symlink is missing",
                                ));
                                continue;
                            }
                        };
                        if !meta.file_type().is_symlink() {
                            report.issues.push(issue(
                                &name,
                                &file.path,
                                "not-symlink",
                                "error",
                                "managed file is no longer a symlink",
                            ));
                            continue;
                        }
                        let expected = self.store.object_path(&file.blake3);
                        let link = fs::read_link(&target)?;
                        if link != expected {
                            report.issues.push(issue(
                                &name,
                                &file.path,
                                "wrong-link",
                                "error",
                                &format!("expected {}", expected.display()),
                            ));
                            continue;
                        }
                        if !expected.exists() {
                            report.issues.push(issue(
                                &name,
                                &file.path,
                                "missing-store-object",
                                "error",
                                "store object is missing",
                            ));
                            continue;
                        }
                        if full {
                            report.hashed_files += 1;
                            let hash = ContentStore::hash_path(&expected)?;
                            if hash != file.blake3 {
                                report.issues.push(issue(
                                    &name,
                                    &file.path,
                                    "hash-mismatch",
                                    "error",
                                    &format!("expected {}, got {}", file.blake3, hash),
                                ));
                            }
                        }
                    }
                    FileType::Config => {
                        if !target.exists() {
                            report.issues.push(issue(
                                &name,
                                &file.path,
                                "missing",
                                "error",
                                "config file is missing",
                            ));
                            continue;
                        }
                        if full {
                            report.hashed_files += 1;
                            let hash = ContentStore::hash_path(&target)?;
                            if hash != file.blake3 {
                                report.issues.push(issue(
                                    &name,
                                    &file.path,
                                    "modified-config",
                                    "warning",
                                    "config differs from package default",
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(report)
    }

    fn repair_file(
        &self,
        manifest: &PackageManifest,
        file: &FileEntry,
        target: &Path,
    ) -> Result<()> {
        match file.file_type {
            FileType::Binary | FileType::Data => {
                if !self.store.object_exists(&file.blake3) {
                    let repo = self.db.latest_repo_package(&manifest.package.name)?;
                    if let Some(repo) = repo {
                        let source = Path::new(&repo.payload_root).join(&file.path);
                        self.store.import_file(&source, Some(&file.blake3))?;
                    }
                }
                self.store.symlink_object(&file.blake3, target)?;
            }
            FileType::Config => {
                self.store.copy_object_to(&file.blake3, target, file)?;
            }
        }
        Ok(())
    }

    fn referenced_hashes(&self, keep_ids: &BTreeSet<i64>) -> Result<BTreeSet<String>> {
        let mut hashes = BTreeSet::new();
        for generation_id in keep_ids {
            for manifest in self.db.generation_packages(*generation_id)?.into_values() {
                for file in manifest.files {
                    hashes.insert(file.blake3);
                }
            }
        }
        for orphan in self.db.list_orphans(None)? {
            hashes.insert(orphan.default_hash);
        }
        Ok(hashes)
    }

    fn clear_orphan_files(&self, package: &str) -> Result<()> {
        let dir = self.layout.orphan_file_dir(package);
        if dir.exists() {
            fs::remove_dir_all(dir)?;
        }
        Ok(())
    }
}

fn issue(package: &str, path: &str, kind: &str, severity: &str, detail: &str) -> VerifyIssue {
    VerifyIssue {
        package: package.to_string(),
        path: path.to_string(),
        kind: kind.to_string(),
        severity: severity.to_string(),
        detail: detail.to_string(),
    }
}

fn manifest_to_json(manifest: &PackageManifest) -> Value {
    json!({
        "name": manifest.package.name,
        "version": manifest.package.version,
        "revision": manifest.package.revision,
        "summary": manifest.package.summary,
        "files": manifest.files.len(),
        "dependencies": manifest.dependencies.runtime.iter().map(|dep| dep.name.clone()).collect::<Vec<_>>(),
        "source": manifest.package.source.as_ref().map(source_to_json),
        "self_upgrade": manifest.package.self_upgrade.as_ref().map(self_upgrade_to_json)
    })
}

fn installed_to_json(installed: &InstalledPackageRecord) -> Value {
    json!({
        "state": installed.state.as_str(),
        "generation": installed.generation_id,
        "manifest": manifest_to_json(&installed.manifest)
    })
}

fn source_to_json(source: &PackageSource) -> Value {
    json!({
        "type": source.source_type,
        "origin": source.origin,
        "options": source.options,
    })
}

fn self_upgrade_to_json(self_upgrade: &PackageSelfUpgrade) -> Value {
    json!({
        "bootstrap": self_upgrade.bootstrap,
        "from_state_schema": self_upgrade.from_state_schema,
        "target_state_schema": self_upgrade.target_state_schema,
    })
}

fn self_upgrade_plan_to_json(plan: &SelfUpgradePlan) -> Value {
    json!({
        "staged_at": plan.staged_at,
        "phase": plan.phase.as_str(),
        "generation_before": plan.generation_before,
        "activated_generation": plan.activated_generation,
        "from_state_schema": plan.from_state_schema,
        "target_state_schema": plan.target_state_schema,
        "package": manifest_to_json(&plan.package),
    })
}

fn format_source(source: &PackageSource) -> String {
    let mut parts = vec![format!("type={}", source.source_type)];
    if !source.origin.trim().is_empty() {
        parts.push(format!("origin={}", source.origin));
    }
    if !source.options.is_empty() {
        parts.push(format!("options={}", source.options.join(",")));
    }
    parts.join(" ")
}

fn provenance_suffix(manifest: &PackageManifest) -> String {
    manifest
        .package
        .source
        .as_ref()
        .map(|source| format!(" [source: {}]", format_source(source)))
        .unwrap_or_default()
}

fn manifests_differ(installed: &PackageManifest, repo: &PackageManifest) -> bool {
    repo.package.version != installed.package.version
        || repo.package.revision != installed.package.revision
}

fn required_bootstrap_self_upgrade(manifest: &PackageManifest) -> Result<&PackageSelfUpgrade> {
    manifest.package.self_upgrade.as_ref().ok_or_else(|| {
        IrisError::InvalidInput(format!(
            "repository package {} {} does not declare bootstrap self-upgrade metadata",
            manifest.package.name, manifest.package.version
        ))
    })
}

fn validate_self_upgrade_plan(plan: &SelfUpgradePlan) -> Result<()> {
    plan.package.validate()?;
    if plan.package.package.name != SELF_PACKAGE_NAME {
        return Err(IrisError::InvalidInput(format!(
            "bootstrap self-upgrade plan must target {}",
            SELF_PACKAGE_NAME
        )));
    }
    let requirement = required_bootstrap_self_upgrade(&plan.package)?;
    if plan.from_state_schema != requirement.from_state_schema
        || plan.target_state_schema != requirement.target_state_schema
    {
        return Err(IrisError::InvalidInput(
            "bootstrap self-upgrade plan schema transition does not match package metadata".into(),
        ));
    }
    if plan.phase == SelfUpgradePhase::Staged && plan.activated_generation.is_some() {
        return Err(IrisError::InvalidInput(
            "bootstrap self-upgrade plan cannot record an activated generation while still staged"
                .into(),
        ));
    }
    if plan.phase == SelfUpgradePhase::GenerationActivated && plan.activated_generation.is_none() {
        return Err(IrisError::InvalidInput(
            "bootstrap self-upgrade plan is missing activated generation for generation_activated phase"
                .into(),
        ));
    }
    Ok(())
}

fn read_bounded_json_artifact<T>(
    path: &Path,
    max_bytes: u64,
    description: &str,
) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    let Some((file, metadata)) = open_read_only_artifact_file(path, description)? else {
        return Ok(None);
    };

    if metadata.len() > max_bytes {
        return Err(IrisError::InvalidInput(format!(
            "{description} exceeds safe read limit of {max_bytes} bytes"
        )));
    }

    let read_limit = usize::try_from(max_bytes).map_err(|_| {
        IrisError::InvalidInput(format!(
            "{description} exceeds platform read limit of {} bytes",
            usize::MAX
        ))
    })?;
    let (bytes, overflowed) = read_capped_bytes(file, read_limit)?;
    if overflowed {
        return Err(IrisError::InvalidInput(format!(
            "{description} exceeds safe read limit of {max_bytes} bytes"
        )));
    }
    let value = serde_json::from_slice(&bytes)
        .map_err(|err| IrisError::InvalidInput(format!("invalid {description}: {err}")))?;
    Ok(Some(value))
}

fn read_daemon_log_entries(path: &Path, limit: usize) -> Result<(Vec<DaemonVerifyStatus>, bool)> {
    let Some((file, metadata)) = open_read_only_artifact_file(path, "daemon verify log artifact")?
    else {
        return Ok((Vec::new(), false));
    };

    let (mut bytes, mut truncated) =
        read_tail_bytes(file, metadata.len(), MAX_DAEMON_LOG_TAIL_BYTES)?;
    if bytes.is_empty() {
        return Ok((Vec::new(), truncated));
    }
    if truncated {
        let Some(offset) = bytes.iter().position(|byte| *byte == b'\n') else {
            return Err(IrisError::InvalidInput(format!(
                "daemon verify log contains an entry exceeding safe read limit of {} bytes",
                MAX_DAEMON_LOG_TAIL_BYTES
            )));
        };
        bytes.drain(..=offset);
        if bytes.is_empty() {
            return Err(IrisError::InvalidInput(format!(
                "daemon verify log contains an entry exceeding safe read limit of {} bytes",
                MAX_DAEMON_LOG_TAIL_BYTES
            )));
        }
    }

    let text = String::from_utf8(bytes).map_err(|err| {
        IrisError::InvalidInput(format!("daemon verify log is not valid UTF-8: {err}"))
    })?;
    let mut parsed = Vec::new();
    for (index, line) in text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let entry = serde_json::from_str(line).map_err(|err| {
            IrisError::InvalidInput(format!(
                "invalid daemon verify log entry {}: {err}",
                index + 1
            ))
        })?;
        parsed.push(entry);
    }
    if parsed.len() > limit {
        truncated = true;
    }

    Ok((parsed.into_iter().rev().take(limit).collect(), truncated))
}

fn read_tail_bytes(mut file: File, size: u64, max_bytes: usize) -> Result<(Vec<u8>, bool)> {
    let mut truncated = size > max_bytes as u64;
    if truncated {
        file.seek(SeekFrom::Start(size - max_bytes as u64))?;
    }
    let (bytes, overflowed) = read_capped_bytes(file, max_bytes)?;
    truncated |= overflowed;
    Ok((bytes, truncated))
}

fn read_capped_bytes<R: Read>(reader: R, max_bytes: usize) -> Result<(Vec<u8>, bool)> {
    let read_limit = u64::try_from(max_bytes)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| {
            IrisError::InvalidInput(format!(
                "configured read limit is too large for this platform: {max_bytes} bytes"
            ))
        })?;

    let mut bytes = Vec::new();
    let mut limited = reader.take(read_limit);
    limited.read_to_end(&mut bytes)?;

    let overflowed = bytes.len() > max_bytes;
    if overflowed {
        bytes.truncate(max_bytes);
    }

    Ok((bytes, overflowed))
}

fn open_read_only_artifact_file(
    path: &Path,
    description: &str,
) -> Result<Option<(File, fs::Metadata)>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            return Err(IrisError::InvalidInput(format!(
                "refusing to use symlinked {description}: {}",
                path.display()
            )));
        }
        Err(err) => return Err(err.into()),
    };

    let expected_uid = current_effective_uid()?;
    if let Some(parent) = path.parent() {
        validate_observability_artifact_parent(parent, expected_uid, description)?;
    }
    let metadata = file.metadata()?;
    validate_observability_artifact_metadata(&metadata, path, expected_uid, description)?;
    Ok(Some((file, metadata)))
}

fn validate_observability_artifact_parent(
    parent: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use symlinked {description} parent directory: {}",
            parent.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(IrisError::InvalidInput(format!(
            "{description} parent directory is not a directory: {}",
            parent.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} parent directory owned by unexpected uid {}: {}",
            metadata.uid(),
            parent.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} under overly broad directory permissions: {}",
            parent.display()
        )));
    }
    Ok(())
}

fn validate_observability_artifact_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use symlinked {description}: {}",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use non-file {description}: {}",
            path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} owned by unexpected uid {}: {}",
            metadata.uid(),
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} with writable group/other permissions: {}",
            path.display()
        )));
    }
    Ok(())
}

fn prepare_secure_private_directory(
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(IrisError::InvalidInput(format!(
                    "refusing to use symlinked {description}: {}",
                    path.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(IrisError::InvalidInput(format!(
                    "{description} is not a directory: {}",
                    path.display()
                )));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
        }
        Err(err) => return Err(err.into()),
    }

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    validate_observability_artifact_parent(path, expected_uid, description)
}

fn validate_existing_private_artifact_path(
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private_artifact_metadata(&metadata, path, expected_uid, description)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn validate_private_artifact_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use symlinked {description}: {}",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use non-file {description}: {}",
            path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} owned by unexpected uid {}: {}",
            metadata.uid(),
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} with writable group/other permissions: {}",
            path.display()
        )));
    }
    Ok(())
}

fn write_atomic_private_artifact_file(
    path: &Path,
    bytes: &[u8],
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    validate_existing_private_artifact_path(path, expected_uid, description)?;
    let (tmp_path, mut file) =
        create_unique_private_temporary_artifact_file(path, expected_uid, description)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err.into());
    }

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    sync_parent_dir(path)
}

fn create_unique_private_temporary_artifact_file(
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<(PathBuf, File)> {
    let parent = path.parent().ok_or_else(|| {
        IrisError::InvalidInput(format!("path has no parent directory: {}", path.display()))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        IrisError::InvalidInput(format!("path has no file name: {}", path.display()))
    })?;
    let file_name = file_name.to_string_lossy();
    let temp_description = format!("{description} temporary artifact");

    for _ in 0..MAX_BOOTSTRAP_TEMP_FILE_ATTEMPTS {
        let counter = BOOTSTRAP_PLAN_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".{}.tmp.{}.{}",
            file_name,
            std::process::id(),
            counter
        ));

        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp_path)
        {
            Ok(file) => {
                let metadata = file.metadata()?;
                validate_private_artifact_metadata(
                    &metadata,
                    &temp_path,
                    expected_uid,
                    &temp_description,
                )?;
                return Ok((temp_path, file));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                validate_existing_private_artifact_path(
                    &temp_path,
                    expected_uid,
                    &temp_description,
                )?;
            }
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                return Err(IrisError::InvalidInput(format!(
                    "refusing to use symlinked {temp_description}: {}",
                    temp_path.display()
                )));
            }
            Err(err) => return Err(err.into()),
        }
    }

    Err(IrisError::InvalidInput(format!(
        "unable to allocate unique temporary path for {description}: {}",
        path.display()
    )))
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        IrisError::InvalidInput(format!("path has no parent directory: {}", path.display()))
    })?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn current_effective_uid() -> Result<u32> {
    Ok(unsafe { libc::geteuid() as u32 })
}

fn clamp_daemon_log_lines(lines: usize) -> usize {
    if lines == 0 {
        DEFAULT_DAEMON_LOG_LINES
    } else {
        lines.clamp(1, MAX_DAEMON_LOG_LINES)
    }
}

fn daemon_log_entry_label(count: usize) -> &'static str {
    if count == 1 { "entry" } else { "entries" }
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::read_capped_bytes;

    #[test]
    fn read_capped_bytes_reports_overflow_without_returning_extra_bytes() {
        let (bytes, overflowed) =
            read_capped_bytes(Cursor::new(b"abcdef".to_vec()), 4).expect("bounded read");

        assert!(overflowed);
        assert_eq!(bytes, b"abcd");
    }

    #[test]
    fn read_capped_bytes_returns_full_payload_within_limit() {
        let (bytes, overflowed) =
            read_capped_bytes(Cursor::new(b"abcd".to_vec()), 4).expect("bounded read");

        assert!(!overflowed);
        assert_eq!(bytes, b"abcd");
    }
}

#[derive(Debug, Clone)]
struct ResolvedInstallPlan {
    requested: Vec<String>,
    ordered: Vec<String>,
    packages: BTreeMap<String, RepoPackageRecord>,
}

fn unique_packages(packages: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for package in packages {
        if seen.insert(package.clone()) {
            unique.push(package.clone());
        }
    }
    unique
}

fn version_satisfies_constraint(version: &str, constraint: &str) -> bool {
    let trimmed = constraint.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.eq_ignore_ascii_case("latest") {
        return true;
    }

    for operator in [">=", "<=", ">", "<", "="] {
        if let Some(expected) = trimmed.strip_prefix(operator) {
            return match operator {
                ">=" => compare_versions(version, expected.trim()).is_ge(),
                "<=" => compare_versions(version, expected.trim()).is_le(),
                ">" => compare_versions(version, expected.trim()).is_gt(),
                "<" => compare_versions(version, expected.trim()).is_lt(),
                "=" => compare_versions(version, expected.trim()).is_eq(),
                _ => false,
            };
        }
    }

    compare_versions(version, trimmed).is_eq()
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left_parts: Vec<_> = left
        .split(['.', '-', '_'])
        .map(|part| part.trim())
        .collect();
    let right_parts: Vec<_> = right
        .split(['.', '-', '_'])
        .map(|part| part.trim())
        .collect();
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

    std::cmp::Ordering::Equal
}

fn audit_finding(scope: &str, subject: &str, severity: &str, detail: &str) -> AuditFinding {
    AuditFinding {
        scope: scope.into(),
        subject: subject.into(),
        severity: severity.into(),
        detail: detail.into(),
    }
}
