use std::io;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IrisError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("toml deserialize error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("dependency resolution failed: {0}")]
    DependencyResolution(String),

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("package not found: {0}")]
    PackageNotFound(String),

    #[error("package is not installed: {0}")]
    PackageNotInstalled(String),

    #[error("repository sync is unsupported for URL: {0}")]
    UnsupportedRepository(String),

    #[error("payload file missing for package {package}: {path}")]
    MissingPayload { package: String, path: PathBuf },

    #[error("hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    #[error("path conflict at {path} between {first} and {second}")]
    PathConflict {
        path: String,
        first: String,
        second: String,
    },

    #[error("operation requires a current generation")]
    NoCurrentGeneration,

    #[error("{0}")]
    Remote(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, IrisError>;
