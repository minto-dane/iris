use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use walkdir::WalkDir;

use crate::error::{IrisError, Result};
use crate::models::PackageManifest;
use crate::state::{IrisDb, StateLayout};

#[derive(Debug, Clone, serde::Serialize)]
pub struct RepoSyncSummary {
    pub source_url: String,
    pub manifests: usize,
}

pub fn sync_repositories(layout: &StateLayout, db: &IrisDb) -> Result<Vec<RepoSyncSummary>> {
    let _ = layout;
    let repos = db.repositories()?;
    let mut summaries = Vec::new();

    for (url, key) in repos {
        let repo_root = resolve_repo_root(&url)?;
        let packages_dir = repo_root.join("packages");
        let payload_dir = repo_root.join("payload");
        if !packages_dir.exists() {
            return Err(IrisError::Unsupported(format!(
                "repository {} does not contain packages/",
                url
            )));
        }

        let mut indexed = Vec::new();
        for entry in WalkDir::new(&packages_dir)
            .into_iter()
            .filter_map(|item| item.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            let manifest_toml = fs::read_to_string(entry.path())?;
            let manifest: PackageManifest = toml::from_str(&manifest_toml)?;
            manifest.validate()?;
            verify_manifest_signature(&manifest, &key)?;

            let candidate_a = payload_dir.join(manifest.package_id());
            let candidate_b = payload_dir.join(&manifest.package.name);
            let root = if candidate_a.exists() {
                candidate_a
            } else {
                candidate_b
            };
            validate_payload_snapshot(&manifest, &root)?;
            indexed.push((manifest, entry.path().to_path_buf(), root));
        }

        db.replace_repo_packages(&url, &indexed)?;

        summaries.push(RepoSyncSummary {
            source_url: url,
            manifests: indexed.len(),
        });
    }

    Ok(summaries)
}

pub(crate) fn validate_payload_snapshot(
    manifest: &PackageManifest,
    payload_root: &Path,
) -> Result<()> {
    let root_metadata = match fs::symlink_metadata(payload_root) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(IrisError::InvalidInput(format!(
                "repository payload root missing for package {}: {}",
                manifest.package.name,
                payload_root.display()
            )));
        }
        Err(err) => return Err(err.into()),
    };

    if root_metadata.file_type().is_symlink() {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use symlinked repository payload root for package {}: {}",
            manifest.package.name,
            payload_root.display()
        )));
    }
    if !root_metadata.is_dir() {
        return Err(IrisError::InvalidInput(format!(
            "repository payload root is not a directory for package {}: {}",
            manifest.package.name,
            payload_root.display()
        )));
    }

    for file in &manifest.files {
        let source = payload_root.join(&file.path);
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(IrisError::MissingPayload {
                    package: manifest.package.name.clone(),
                    path: source,
                });
            }
            Err(err) => return Err(err.into()),
        };

        if metadata.file_type().is_symlink() {
            return Err(IrisError::InvalidInput(format!(
                "refusing to use symlinked repository payload entry for package {}: {}",
                manifest.package.name,
                source.display()
            )));
        }
        if !metadata.is_file() {
            return Err(IrisError::InvalidInput(format!(
                "repository payload entry is not a regular file for package {}: {}",
                manifest.package.name,
                source.display()
            )));
        }
    }

    Ok(())
}

pub fn validate_trusted_key(key: &str) -> Result<()> {
    parse_verifying_key(key).map(|_| ())
}

pub fn verify_manifest_signature(manifest: &PackageManifest, trusted_key: &str) -> Result<()> {
    if manifest.signature.algorithm != "ed25519" {
        return Err(IrisError::SignatureVerification(format!(
            "{} uses unsupported signature algorithm {}",
            manifest.package.name, manifest.signature.algorithm
        )));
    }
    if manifest.signature.public_key != trusted_key {
        return Err(IrisError::SignatureVerification(format!(
            "{} is signed by untrusted key {}",
            manifest.package.name, manifest.signature.public_key
        )));
    }

    let verifying_key = parse_verifying_key(trusted_key)?;
    let signature_bytes = STANDARD
        .decode(manifest.signature.value.as_bytes())
        .map_err(|err| {
            IrisError::SignatureVerification(format!(
                "{} has invalid base64 signature: {}",
                manifest.package.name, err
            ))
        })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|err| {
        IrisError::SignatureVerification(format!(
            "{} has invalid ed25519 signature bytes: {}",
            manifest.package.name, err
        ))
    })?;
    let payload = manifest.signing_payload()?;
    verifying_key.verify(&payload, &signature).map_err(|err| {
        IrisError::SignatureVerification(format!(
            "{} failed signature verification: {}",
            manifest.package.name, err
        ))
    })?;
    Ok(())
}

fn resolve_repo_root(url: &str) -> Result<PathBuf> {
    if let Some(path) = url.strip_prefix("file://") {
        return Ok(Path::new(path).to_path_buf());
    }
    let direct = Path::new(url);
    if direct.exists() {
        return Ok(direct.to_path_buf());
    }
    Err(IrisError::UnsupportedRepository(url.to_string()))
}

fn parse_verifying_key(key: &str) -> Result<VerifyingKey> {
    let decoded = STANDARD.decode(key.as_bytes()).map_err(|err| {
        IrisError::SignatureVerification(format!("invalid trusted key encoding: {}", err))
    })?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
        IrisError::SignatureVerification(
            "trusted key must decode to 32-byte ed25519 public key".into(),
        )
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|err| {
        IrisError::SignatureVerification(format!("invalid ed25519 public key: {}", err))
    })
}
