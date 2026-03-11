use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{IrisError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub package: PackageMetadata,
    #[serde(default)]
    pub signature: Signature,
    #[serde(default)]
    pub dependencies: Dependencies,
    #[serde(default)]
    pub files: Vec<FileEntry>,
}

impl PackageManifest {
    pub fn validate(&self) -> Result<()> {
        validate_package_name(&self.package.name)?;
        validate_package_version(&self.package.version)?;
        if self.signature.algorithm.trim().is_empty()
            || self.signature.public_key.trim().is_empty()
            || self.signature.value.trim().is_empty()
        {
            return Err(IrisError::InvalidManifest(
                "signature fields must be non-empty".into(),
            ));
        }
        if let Some(self_upgrade) = self.package.self_upgrade.as_ref() {
            if self.package.name != "iris" {
                return Err(IrisError::InvalidManifest(
                    "package.self_upgrade is only valid for package.name = \"iris\"".into(),
                ));
            }
            if !self_upgrade.bootstrap {
                return Err(IrisError::InvalidManifest(
                    "package.self_upgrade.bootstrap must be true when package.self_upgrade is present"
                        .into(),
                ));
            }
            if self_upgrade.from_state_schema == 0 || self_upgrade.target_state_schema == 0 {
                return Err(IrisError::InvalidManifest(
                    "package.self_upgrade state schema values must be greater than zero".into(),
                ));
            }
            if self_upgrade.target_state_schema <= self_upgrade.from_state_schema {
                return Err(IrisError::InvalidManifest(
                    "package.self_upgrade.target_state_schema must be greater than package.self_upgrade.from_state_schema"
                        .into(),
                ));
            }
        }

        let mut seen = BTreeSet::new();
        for file in &self.files {
            file.validate()?;
            if !seen.insert(file.path.clone()) {
                return Err(IrisError::InvalidManifest(format!(
                    "duplicate file path {}",
                    file.path
                )));
            }
        }
        Ok(())
    }

    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.value.clear();
        Ok(unsigned.to_toml()?.into_bytes())
    }

    pub fn package_id(&self) -> String {
        format!("{}-{}", self.package.name, self.package.version)
    }

    pub fn file_map(&self) -> BTreeMap<&str, &FileEntry> {
        self.files
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect()
    }
}

fn validate_package_name(value: &str) -> Result<()> {
    validate_package_field(
        value,
        "package.name",
        true,
        |ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'),
        "ASCII alphanumeric characters, '-' and '_'",
    )
}

fn validate_package_version(value: &str) -> Result<()> {
    validate_package_field(
        value,
        "package.version",
        false,
        |ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+'),
        "ASCII alphanumeric characters, '.', '-' and '+'",
    )
}

fn validate_package_field<F>(
    value: &str,
    field: &str,
    reject_dotdot: bool,
    allowed: F,
    allowed_description: &str,
) -> Result<()>
where
    F: Fn(char) -> bool,
{
    if value.is_empty() {
        return Err(IrisError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    if reject_dotdot && value.contains("..") {
        return Err(IrisError::InvalidInput(format!(
            "{field} must not contain path traversal sequence '..'"
        )));
    }
    if value.chars().any(|ch| matches!(ch, '/' | '\\')) {
        return Err(IrisError::InvalidInput(format!(
            "{field} must not contain path separators"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(IrisError::InvalidInput(format!(
            "{field} must not contain whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(IrisError::InvalidInput(format!(
            "{field} must not contain control characters"
        )));
    }
    if value.chars().any(|ch| !allowed(ch)) {
        return Err(IrisError::InvalidInput(format!(
            "{field} must contain only {allowed_description}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub revision: u32,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub abi: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub maintainer: String,
    #[serde(default)]
    pub source: Option<PackageSource>,
    #[serde(default)]
    pub self_upgrade: Option<PackageSelfUpgrade>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSelfUpgrade {
    pub bootstrap: bool,
    pub from_state_schema: u32,
    pub target_state_schema: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSource {
    #[serde(rename = "type")]
    pub source_type: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Signature {
    #[serde(default = "default_signature_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub value: String,
}

fn default_signature_algorithm() -> String {
    "ed25519".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Dependencies {
    #[serde(default)]
    pub runtime: Vec<DependencySpec>,
    #[serde(default)]
    pub build: Vec<DependencySpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencySpec {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub blake3: String,
    pub size: u64,
    pub mode: String,
    #[serde(rename = "type")]
    pub file_type: FileType,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub merge_strategy: Option<MergeStrategy>,
}

impl FileEntry {
    pub fn validate(&self) -> Result<()> {
        let relative = Path::new(&self.path);
        if relative.is_absolute() || self.path.contains('\0') {
            return Err(IrisError::InvalidManifest(format!(
                "invalid relative path {}",
                self.path
            )));
        }
        if relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(IrisError::InvalidManifest(format!(
                "parent traversal is not allowed in {}",
                self.path
            )));
        }
        if self.blake3.len() != 64
            || !self
                .blake3
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        {
            return Err(IrisError::InvalidManifest(format!(
                "invalid blake3 hash {}",
                self.blake3
            )));
        }
        if self.mode.len() != 4 || !self.mode.chars().all(|ch| ('0'..='7').contains(&ch)) {
            return Err(IrisError::InvalidManifest(format!(
                "invalid mode {}",
                self.mode
            )));
        }
        if self.file_type != FileType::Config && self.merge_strategy.is_some() {
            return Err(IrisError::InvalidManifest(format!(
                "merge_strategy is only valid for config file {}",
                self.path
            )));
        }
        Ok(())
    }

    pub fn mode_bits(&self) -> Result<u32> {
        u32::from_str_radix(&self.mode, 8)
            .map_err(|_| IrisError::InvalidManifest(format!("invalid mode {}", self.mode)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    Binary,
    Data,
    Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeStrategy {
    #[serde(rename = "3way")]
    ThreeWay,
    #[serde(rename = "overwrite")]
    Overwrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageState {
    Installed,
    OrphanedConfig,
}

impl PackageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::OrphanedConfig => "orphaned-config",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "orphaned-config" => Self::OrphanedConfig,
            _ => Self::Installed,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoPackageRecord {
    pub source_url: String,
    pub manifest_path: String,
    pub payload_root: String,
    pub manifest: PackageManifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstalledPackageRecord {
    pub state: PackageState,
    pub generation_id: Option<i64>,
    pub manifest: PackageManifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerationSummary {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub created_at: String,
    pub current: bool,
    pub package_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrphanRecord {
    pub package_name: String,
    pub path: String,
    pub default_hash: String,
    pub current_hash: String,
    pub modified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub timestamp: String,
    pub action: String,
    pub packages: Vec<String>,
    pub result: String,
    pub generation_before: Option<i64>,
    pub generation_after: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyIssue {
    pub package: String,
    pub path: String,
    pub kind: String,
    pub severity: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub mode: String,
    pub checked_packages: usize,
    pub checked_files: usize,
    pub hashed_files: usize,
    pub issues: Vec<VerifyIssue>,
}

impl Default for VerifyReport {
    fn default() -> Self {
        Self {
            mode: "fast".into(),
            checked_packages: 0,
            checked_files: 0,
            hashed_files: 0,
            issues: Vec::new(),
        }
    }
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonVerifyStatus {
    pub trigger: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
    pub mode: String,
    pub message: String,
    pub issue_count: usize,
    pub report: Option<VerifyReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatusReadout {
    pub latest: Option<DaemonVerifyStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonLogReadout {
    pub entries: Vec<DaemonVerifyStatus>,
    pub limit: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepairAction {
    pub package: String,
    pub path: String,
    pub action: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub scope: String,
    pub subject: String,
    pub severity: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub status: String,
    pub repositories: usize,
    pub indexed_packages: usize,
    pub installed_packages: usize,
    pub pinned_packages: usize,
    pub orphaned_configs: usize,
    pub verify: VerifyReport,
    pub findings: Vec<AuditFinding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str, version: &str) -> PackageManifest {
        PackageManifest {
            package: PackageMetadata {
                name: name.into(),
                version: version.into(),
                revision: 0,
                arch: "amd64".into(),
                abi: "freebsd:14:*".into(),
                summary: "test package".into(),
                maintainer: "test@example.invalid".into(),
                source: None,
                self_upgrade: None,
            },
            signature: Signature {
                algorithm: "ed25519".into(),
                public_key: "pk".into(),
                value: "sig".into(),
            },
            dependencies: Dependencies::default(),
            files: Vec::new(),
        }
    }

    fn assert_invalid_input(name: &str, version: &str, field: &str, reason: &str) {
        let err = manifest(name, version)
            .validate()
            .expect_err("manifest should be rejected");
        assert!(
            matches!(err, IrisError::InvalidInput(ref message) if message.contains(field) && message.contains(reason)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn validate_accepts_strict_name_and_version_boundaries() {
        manifest("-hello_tools-", "1.2.3-beta+meta")
            .validate()
            .expect("strictly valid package identifiers should pass");
    }

    #[test]
    fn validate_rejects_empty_name_and_version() {
        assert_invalid_input("", "1.0.0", "package.name", "empty");
        assert_invalid_input("hello", "", "package.version", "empty");
    }

    #[test]
    fn validate_rejects_path_separators_and_traversal_in_name() {
        assert_invalid_input("hello/world", "1.0.0", "package.name", "path separators");
        assert_invalid_input(r"hello\world", "1.0.0", "package.name", "path separators");
        assert_invalid_input("../hello", "1.0.0", "package.name", "path traversal");
    }

    #[test]
    fn validate_rejects_whitespace_control_and_invalid_characters_in_name() {
        assert_invalid_input("hello world", "1.0.0", "package.name", "whitespace");
        assert_invalid_input(
            "hello\u{7f}world",
            "1.0.0",
            "package.name",
            "control characters",
        );
        assert_invalid_input(
            "hello.name",
            "1.0.0",
            "package.name",
            "only ASCII alphanumeric",
        );
    }

    #[test]
    fn validate_rejects_path_separators_in_version() {
        assert_invalid_input("hello", "1/2/3", "package.version", "path separators");
        assert_invalid_input("hello", r"1\2\3", "package.version", "path separators");
    }

    #[test]
    fn validate_rejects_whitespace_control_and_invalid_characters_in_version() {
        assert_invalid_input("hello", "1.0.0 rc1", "package.version", "whitespace");
        assert_invalid_input(
            "hello",
            "1.0.0\u{7f}",
            "package.version",
            "control characters",
        );
        assert_invalid_input(
            "hello",
            "1.2.3_4,1",
            "package.version",
            "only ASCII alphanumeric",
        );
    }
}
