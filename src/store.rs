use std::fs;
use std::io::Read;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use crate::error::{IrisError, Result};
use crate::models::FileEntry;
use crate::state::StateLayout;

#[derive(Debug, Clone)]
pub struct ContentStore {
    layout: StateLayout,
}

impl ContentStore {
    pub fn new(layout: StateLayout) -> Self {
        Self { layout }
    }

    pub fn hash_bytes(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }

    pub fn hash_reader(mut reader: impl Read) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 128 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    pub fn hash_path(path: &Path) -> Result<String> {
        Self::hash_reader(fs::File::open(path)?)
    }

    pub fn object_path(&self, hash: &str) -> std::path::PathBuf {
        self.layout.store_dir().join(&hash[..2]).join(hash)
    }

    pub fn object_exists(&self, hash: &str) -> bool {
        self.object_path(hash).exists()
    }

    pub fn import_file(&self, path: &Path, expected_hash: Option<&str>) -> Result<String> {
        let hash = Self::hash_path(path)?;
        if let Some(expected_hash) = expected_hash
            && hash != expected_hash
        {
            return Err(IrisError::HashMismatch {
                path: path.display().to_string(),
                expected: expected_hash.to_string(),
                actual: hash,
            });
        }
        let destination = self.object_path(expected_hash.unwrap_or(&hash));
        if !destination.exists() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(path, &destination)?;
        }
        Ok(expected_hash.unwrap_or(&hash).to_string())
    }

    pub fn write_bytes(&self, bytes: &[u8]) -> Result<String> {
        let hash = Self::hash_bytes(bytes);
        let destination = self.object_path(&hash);
        if !destination.exists() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&destination, bytes)?;
        }
        Ok(hash)
    }

    pub fn copy_object_to(&self, hash: &str, destination: &Path, file: &FileEntry) -> Result<()> {
        let source = self.object_path(hash);
        if !source.exists() {
            return Err(IrisError::MissingPayload {
                package: "store".into(),
                path: source,
            });
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&source, destination)?;
        fs::set_permissions(destination, fs::Permissions::from_mode(file.mode_bits()?))?;
        Ok(())
    }

    pub fn symlink_object(&self, hash: &str, destination: &Path) -> Result<()> {
        let source = self.object_path(hash);
        if !source.exists() {
            return Err(IrisError::MissingPayload {
                package: "store".into(),
                path: source,
            });
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        if destination.exists() || fs::symlink_metadata(destination).is_ok() {
            fs::remove_file(destination)?;
        }
        symlink(source, destination)?;
        Ok(())
    }
}
