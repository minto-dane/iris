use std::fs;
use std::io::Read;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use chrono::Utc;

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

    pub fn object_path(&self, hash: &str) -> Result<PathBuf> {
        validate_store_hash(hash)?;
        Ok(self.layout.store_dir().join(&hash[..2]).join(hash))
    }

    pub fn object_exists(&self, hash: &str) -> bool {
        self.object_path(hash)
            .map(|path| path.exists())
            .unwrap_or(false)
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
        let object_hash = expected_hash.unwrap_or(&hash);
        let destination = self.object_path(object_hash)?;
        self.ensure_parent_dir(&destination)?;
        if self.object_matches_hash(&destination, object_hash)? {
            return Ok(object_hash.to_string());
        }
        self.publish_file_atomically(path, &destination)?;
        Ok(object_hash.to_string())
    }

    pub fn write_bytes(&self, bytes: &[u8]) -> Result<String> {
        let hash = Self::hash_bytes(bytes);
        let destination = self.object_path(&hash)?;
        self.ensure_parent_dir(&destination)?;
        if self.object_matches_hash(&destination, &hash)? {
            return Ok(hash);
        }
        self.publish_bytes_atomically(bytes, &destination)?;
        Ok(hash)
    }

    pub fn copy_object_to(&self, hash: &str, destination: &Path, file: &FileEntry) -> Result<()> {
        let source = self.object_path(hash)?;
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
        let source = self.object_path(hash)?;
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

    fn ensure_parent_dir(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn object_matches_hash(&self, path: &Path, expected_hash: &str) -> Result<bool> {
        match fs::metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(IrisError::InvalidInput(format!(
                        "store object is not a regular file: {}",
                        path.display()
                    )));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err.into()),
        }
        Ok(Self::hash_path(path)? == expected_hash)
    }

    fn publish_file_atomically(&self, source: &Path, destination: &Path) -> Result<()> {
        let temp_path = self.temporary_object_path(destination);
        fs::copy(source, &temp_path)?;
        self.publish_temp_file(&temp_path, destination)
    }

    fn publish_bytes_atomically(&self, bytes: &[u8], destination: &Path) -> Result<()> {
        let temp_path = self.temporary_object_path(destination);
        fs::write(&temp_path, bytes)?;
        self.publish_temp_file(&temp_path, destination)
    }

    fn publish_temp_file(&self, temp_path: &Path, destination: &Path) -> Result<()> {
        match fs::rename(temp_path, destination) {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = fs::remove_file(temp_path);
                Err(err.into())
            }
        }
    }

    fn temporary_object_path(&self, destination: &Path) -> PathBuf {
        let mut name = destination
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("object")
            .to_string();
        name.push_str(&format!(
            ".tmp-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        destination.with_file_name(name)
    }
}

fn validate_store_hash(hash: &str) -> Result<()> {
    if hash.len() != 64
        || !hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(IrisError::InvalidInput(format!(
            "invalid store hash {}",
            hash
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn object_path_rejects_invalid_hash() {
        let root = tempdir().expect("tempdir");
        let store = ContentStore::new(StateLayout::new(root.path()));

        let err = store
            .object_path("../bad")
            .expect_err("invalid hash must be rejected");

        assert!(
            matches!(err, IrisError::InvalidInput(message) if message.contains("invalid store hash"))
        );
    }

    #[test]
    fn write_bytes_replaces_corrupt_existing_object() {
        let root = tempdir().expect("tempdir");
        let layout = StateLayout::new(root.path());
        layout.ensure().expect("layout ensure");
        let store = ContentStore::new(layout);
        let bytes = b"hello object";
        let hash = ContentStore::hash_bytes(bytes);
        let object = store.object_path(&hash).expect("object path");
        fs::create_dir_all(object.parent().expect("store parent")).expect("mkdir");
        fs::write(&object, b"corrupt").expect("seed corrupt object");

        store.write_bytes(bytes).expect("write bytes");

        assert_eq!(fs::read(&object).expect("read object"), bytes);
    }
}
