use std::fs;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use iris::cli::{Cli, Command, DaemonCommand, GenerationCommand, SelfCommand, Transport};
use iris::models::{
    Dependencies, DependencySpec, FileEntry, FileType, MergeStrategy, PackageManifest,
    PackageMetadata, PackageSelfUpgrade, PackageSource, Signature,
};
use iris::store::ContentStore;
use iris::{
    DaemonRequestEnvelope, DaemonResponseEnvelope, Iris, IrisError, IrisRequest, OperationOptions,
    Result,
};
use tempfile::tempdir;

fn options() -> OperationOptions {
    OperationOptions {
        dry_run: false,
        yes: true,
    }
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn trusted_key(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

fn file_entry(
    path: &str,
    bytes: &[u8],
    mode: &str,
    file_type: FileType,
    merge_strategy: Option<MergeStrategy>,
) -> FileEntry {
    FileEntry {
        path: path.into(),
        blake3: ContentStore::hash_bytes(bytes),
        size: bytes.len() as u64,
        mode: mode.into(),
        file_type,
        flags: vec![],
        merge_strategy,
    }
}

fn package_manifest(
    name: &str,
    version: &str,
    summary: &str,
    dependencies: Vec<DependencySpec>,
    files: Vec<FileEntry>,
) -> PackageManifest {
    package_manifest_with_source(name, version, summary, None, dependencies, files)
}

fn package_manifest_with_source(
    name: &str,
    version: &str,
    summary: &str,
    source: Option<PackageSource>,
    dependencies: Vec<DependencySpec>,
    files: Vec<FileEntry>,
) -> PackageManifest {
    PackageManifest {
        package: PackageMetadata {
            name: name.into(),
            version: version.into(),
            revision: 0,
            arch: "amd64".into(),
            abi: "freebsd:14:*".into(),
            summary: summary.into(),
            maintainer: "test@example.invalid".into(),
            source,
            self_upgrade: None,
        },
        signature: Signature {
            algorithm: "ed25519".into(),
            public_key: String::new(),
            value: String::new(),
        },
        dependencies: Dependencies {
            runtime: dependencies,
            ..Dependencies::default()
        },
        files,
    }
}

fn sign_manifest(mut manifest: PackageManifest, key: &SigningKey) -> Result<PackageManifest> {
    manifest.signature.public_key = trusted_key(key);
    manifest.signature.value.clear();
    let payload = manifest.signing_payload()?;
    let signature = key.sign(&payload);
    manifest.signature.value = STANDARD.encode(signature.to_bytes());
    Ok(manifest)
}

fn write_signed_package(
    repo_root: &Path,
    key: &SigningKey,
    manifest: PackageManifest,
    payload_files: &[(&str, &[u8])],
) -> Result<()> {
    let packages_dir = repo_root.join("packages");
    let payload_root = repo_root.join("payload").join(manifest.package_id());
    fs::create_dir_all(&packages_dir)?;

    for (path, bytes) in payload_files {
        let destination = payload_root.join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(destination, bytes)?;
    }

    let manifest = sign_manifest(manifest, key)?;
    manifest.validate()?;
    fs::write(
        packages_dir.join(format!("{}.toml", manifest.package_id())),
        manifest.to_toml()?,
    )?;
    Ok(())
}

fn write_hello_repo(repo_root: &Path, key: &SigningKey) -> Result<()> {
    let binary_bytes = b"#!/bin/sh\necho hello\n";
    let config_bytes = b"greeting = \"hello\"\n";
    let manifest = package_manifest(
        "hello",
        "1.0.0",
        "hello test package",
        vec![],
        vec![
            file_entry(
                "usr/bin/hello",
                binary_bytes,
                "0755",
                FileType::Binary,
                None,
            ),
            file_entry(
                "etc/hello.conf",
                config_bytes,
                "0644",
                FileType::Config,
                Some(MergeStrategy::ThreeWay),
            ),
        ],
    );
    write_signed_package(
        repo_root,
        key,
        manifest,
        &[
            ("usr/bin/hello", binary_bytes.as_slice()),
            ("etc/hello.conf", config_bytes.as_slice()),
        ],
    )
}

fn write_hello_package(
    repo_root: &Path,
    key: &SigningKey,
    version: &str,
    body: &[u8],
) -> Result<()> {
    let config_bytes = b"greeting = \"hello\"\n";
    let manifest = package_manifest(
        "hello",
        version,
        "hello test package",
        vec![],
        vec![
            file_entry("usr/bin/hello", body, "0755", FileType::Binary, None),
            file_entry(
                "etc/hello.conf",
                config_bytes,
                "0644",
                FileType::Config,
                Some(MergeStrategy::ThreeWay),
            ),
        ],
    );
    write_signed_package(
        repo_root,
        key,
        manifest,
        &[
            ("usr/bin/hello", body),
            ("etc/hello.conf", config_bytes.as_slice()),
        ],
    )
}

fn write_dependency_repo(repo_root: &Path, key: &SigningKey) -> Result<()> {
    let library_bytes = b"shared library payload\n";
    let app_bytes = b"#!/bin/sh\necho app\n";

    let library_manifest = package_manifest(
        "libgreet",
        "1.0.0",
        "dependency package",
        vec![],
        vec![file_entry(
            "usr/lib/libgreet.so",
            library_bytes,
            "0644",
            FileType::Data,
            None,
        )],
    );
    write_signed_package(
        repo_root,
        key,
        library_manifest,
        &[("usr/lib/libgreet.so", library_bytes.as_slice())],
    )?;

    let app_manifest = package_manifest(
        "greeter",
        "2.0.0",
        "application package",
        vec![DependencySpec {
            name: "libgreet".into(),
            version: ">=1.0.0".into(),
        }],
        vec![file_entry(
            "usr/bin/greeter",
            app_bytes,
            "0755",
            FileType::Binary,
            None,
        )],
    );
    write_signed_package(
        repo_root,
        key,
        app_manifest,
        &[("usr/bin/greeter", app_bytes.as_slice())],
    )
}

fn write_iris_package(
    repo_root: &Path,
    key: &SigningKey,
    version: &str,
    source: Option<PackageSource>,
    self_upgrade: Option<PackageSelfUpgrade>,
) -> Result<()> {
    let binary = format!("#!/bin/sh\necho iris {version}\n");
    let mut manifest = package_manifest_with_source(
        "iris",
        version,
        "iris package manager",
        source,
        vec![],
        vec![file_entry(
            "usr/bin/iris",
            binary.as_bytes(),
            "0755",
            FileType::Binary,
            None,
        )],
    );
    manifest.package.self_upgrade = self_upgrade;

    write_signed_package(
        repo_root,
        key,
        manifest,
        &[("usr/bin/iris", binary.as_bytes())],
    )
}

fn wait_for_socket(socket_path: &Path) {
    for _ in 0..50 {
        if socket_path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }

    panic!("daemon socket should exist: {}", socket_path.display());
}

fn connect_socket_with_retry(socket_path: &Path) -> Result<UnixStream> {
    let mut last_err = None;
    for _ in 0..50 {
        match UnixStream::connect(socket_path) {
            Ok(stream) => return Ok(stream),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                last_err = Some(err);
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.into()),
        }
    }

    Err(last_err
        .unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out connecting to daemon socket: {}",
                    socket_path.display()
                ),
            )
        })
        .into())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_private_artifact(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_private_dir(path.parent().expect("artifact parent"))?;
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn daemon_status_fixture(trigger: &str) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&serde_json::json!({
        "trigger": trigger,
        "status": "ok",
        "started_at": "2026-03-11T00:00:00Z",
        "finished_at": "2026-03-11T00:00:01Z",
        "mode": "full",
        "message": "fixture",
        "issue_count": 0,
        "report": serde_json::Value::Null,
        "error": serde_json::Value::Null,
    }))?)
}

#[test]
fn cli_parses_nested_generation_subcommand() {
    let cli = Cli::try_parse_from(["iris", "generation", "list"]).expect("cli should parse");
    assert!(matches!(
        cli.command,
        Command::Generation(GenerationCommand::List)
    ));
}

#[test]
fn cli_converts_into_frontend_request() {
    let frontend = Cli::try_parse_from([
        "iris",
        "--root",
        "/tmp/iris-test",
        "--dry-run",
        "--json",
        "install",
        "hello",
    ])
    .expect("cli should parse")
    .into_frontend_request()
    .expect("frontend conversion should succeed");

    assert_eq!(frontend.root, PathBuf::from("/tmp/iris-test"));
    assert_eq!(frontend.transport, Transport::Direct);
    assert!(frontend.socket.is_none());
    assert!(frontend.render.json);
    assert!(!frontend.render.batch);
    assert!(matches!(
        frontend.request,
        IrisRequest::Install { packages, options }
            if packages == vec!["hello".to_string()] && options.dry_run && !options.yes
    ));
}

#[test]
fn cli_parses_self_subcommands_and_frontend_requests() {
    let cli = Cli::try_parse_from(["iris", "self", "status"]).expect("cli should parse");
    assert!(matches!(cli.command, Command::SelfCmd(SelfCommand::Status)));

    let stage = Cli::try_parse_from(["iris", "--dry-run", "self", "stage"])
        .expect("cli should parse")
        .into_frontend_request()
        .expect("frontend conversion should succeed");
    assert!(matches!(
        stage.request,
        IrisRequest::SelfStage { options } if options.dry_run && !options.yes
    ));

    let bootstrap = Cli::try_parse_from(["iris", "self", "bootstrap"]).expect("cli should parse");
    assert!(matches!(
        bootstrap.command,
        Command::SelfCmd(SelfCommand::Bootstrap)
    ));

    let frontend = Cli::try_parse_from(["iris", "--dry-run", "self", "update"])
        .expect("cli should parse")
        .into_frontend_request()
        .expect("frontend conversion should succeed");

    assert!(matches!(
        frontend.request,
        IrisRequest::SelfUpdate { options } if options.dry_run && !options.yes
    ));
}

#[test]
fn cli_accepts_explicit_daemon_transport_and_socket() {
    let frontend = Cli::try_parse_from([
        "iris",
        "--transport",
        "daemon",
        "--socket",
        "/tmp/irisd.sock",
        "verify",
    ])
    .expect("cli should parse")
    .into_frontend_request()
    .expect("frontend conversion should succeed");

    assert_eq!(frontend.transport, Transport::Daemon);
    assert_eq!(frontend.socket, Some(PathBuf::from("/tmp/irisd.sock")));
    assert!(matches!(
        frontend.request,
        IrisRequest::Verify { packages, full } if packages.is_empty() && !full
    ));
}

#[test]
fn cli_rejects_socket_without_daemon_transport() {
    let err = Cli::try_parse_from(["iris", "--socket", "/tmp/irisd.sock", "history"])
        .expect("cli should parse")
        .into_frontend_request()
        .expect_err("socket without daemon transport should fail closed");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message) if message.contains("--socket requires --transport daemon")
    ));
}

#[test]
fn cli_parses_daemon_observability_subcommands() {
    let status = Cli::try_parse_from(["iris", "daemon", "status"]).expect("cli should parse");
    assert!(matches!(
        status.command,
        Command::Daemon(DaemonCommand::Status)
    ));

    let frontend = Cli::try_parse_from(["iris", "daemon", "log", "--lines", "25"])
        .expect("cli should parse")
        .into_frontend_request()
        .expect("frontend conversion should succeed");

    assert!(matches!(
        frontend.request,
        IrisRequest::DaemonLog { lines } if lines == 25
    ));
}

#[test]
fn self_status_and_package_queries_surface_provenance() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(30);
    let trusted = trusted_key(&key);
    let source = PackageSource {
        source_type: "port".into(),
        origin: "ports-mgmt/iris".into(),
        options: vec!["BLAKE3".into(), "SQLITE".into()],
    };
    write_iris_package(repo_dir.path(), &key, "1.0.0", Some(source.clone()), None)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["iris".to_string()], options())?;

    let status = app.execute(IrisRequest::SelfStatus)?;
    assert!(status.ok);
    assert_eq!(status.data["managed"].as_bool(), Some(true));
    assert_eq!(status.data["update_available"].as_bool(), Some(false));
    assert_eq!(status.data["state_schema_version"].as_u64(), Some(1));
    assert!(status.data["staged_bootstrap_plan"].is_null());
    assert!(status.data["repository_bootstrap_requirement"].is_null());
    assert_eq!(
        status.data["installed"]["manifest"]["source"]["type"].as_str(),
        Some("port")
    );
    assert_eq!(
        status.data["repository"]["source"]["origin"].as_str(),
        Some("ports-mgmt/iris")
    );
    assert!(
        status
            .message
            .contains("Repository source: type=port origin=ports-mgmt/iris options=BLAKE3,SQLITE")
    );

    let info = app.info("iris")?;
    assert_eq!(
        info.data["installed"]["manifest"]["source"]["origin"].as_str(),
        Some("ports-mgmt/iris")
    );
    assert!(
        info.message
            .contains("Installed source: type=port origin=ports-mgmt/iris options=BLAKE3,SQLITE")
    );

    let search = app.search("iris")?;
    let matches = search
        .data
        .as_array()
        .expect("search data should be an array");
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0]["manifest"]["package"]["source"]["type"].as_str(),
        Some("port")
    );
    assert!(
        search
            .message
            .contains("[source: type=port origin=ports-mgmt/iris options=BLAKE3,SQLITE]")
    );
    Ok(())
}

#[test]
fn self_update_updates_managed_iris_package() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(31);
    let trusted = trusted_key(&key);
    write_iris_package(repo_dir.path(), &key, "1.0.0", None, None)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["iris".to_string()], options())?;

    let before_generation = app
        .db
        .current_generation_id()?
        .expect("generation after initial install");

    write_iris_package(repo_dir.path(), &key, "1.1.0", None, None)?;
    app.repo_sync()?;

    let before = app.execute(IrisRequest::SelfStatus)?;
    assert_eq!(before.data["update_available"].as_bool(), Some(true));

    let response = app.execute(IrisRequest::SelfUpdate { options: options() })?;
    assert!(response.ok);

    let after_generation = app
        .db
        .current_generation_id()?
        .expect("generation after self update");
    let installed = app
        .db
        .installed_package("iris")?
        .expect("managed iris package should remain installed");

    assert!(after_generation > before_generation);
    assert_eq!(installed.manifest.package.version, "1.1.0");

    let after = app.execute(IrisRequest::SelfStatus)?;
    assert_eq!(after.data["update_available"].as_bool(), Some(false));
    Ok(())
}

#[test]
fn repo_queries_and_update_use_semantic_version_ordering() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(35);
    let trusted = trusted_key(&key);
    write_hello_package(
        repo_dir.path(),
        &key,
        "1.9.0",
        b"#!/bin/sh\necho hello v1.9.0\n",
    )?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["hello".to_string()], options())?;

    write_hello_package(
        repo_dir.path(),
        &key,
        "1.10.0",
        b"#!/bin/sh\necho hello v1.10.0\n",
    )?;
    app.repo_sync()?;

    let latest = app
        .db
        .latest_repo_package("hello")?
        .expect("latest repo package should exist");
    assert_eq!(latest.manifest.package.version, "1.10.0");

    let candidates = app.db.repo_packages_for_name("hello")?;
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].manifest.package.version, "1.10.0");
    assert_eq!(candidates[1].manifest.package.version, "1.9.0");

    let info = app.info("hello")?;
    assert_eq!(info.data["repository"]["version"].as_str(), Some("1.10.0"));

    let search = app.search("hello")?;
    let matches = search
        .data
        .as_array()
        .expect("search data should be an array");
    assert_eq!(
        matches[0]["manifest"]["package"]["version"].as_str(),
        Some("1.10.0")
    );

    app.update(&["hello".to_string()], options())?;
    let installed = app
        .db
        .installed_package("hello")?
        .expect("hello should remain installed");
    assert_eq!(installed.manifest.package.version, "1.10.0");
    Ok(())
}

#[test]
fn self_update_requires_managed_iris_package() -> Result<()> {
    let state_dir = tempdir()?;
    let app = Iris::open(state_dir.path())?;

    let err = app
        .execute(IrisRequest::SelfUpdate { options: options() })
        .expect_err("self update should require a managed iris package");

    assert!(matches!(
        err,
        IrisError::PackageNotInstalled(name) if name == "iris"
    ));
    Ok(())
}

#[test]
fn self_update_refuses_when_repo_requires_bootstrap_path() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(32);
    let trusted = trusted_key(&key);
    write_iris_package(repo_dir.path(), &key, "1.0.0", None, None)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["iris".to_string()], options())?;

    write_iris_package(
        repo_dir.path(),
        &key,
        "2.0.0",
        None,
        Some(PackageSelfUpgrade {
            bootstrap: true,
            from_state_schema: 1,
            target_state_schema: 2,
        }),
    )?;
    app.repo_sync()?;

    let err = app
        .execute(IrisRequest::SelfUpdate { options: options() })
        .expect_err("ordinary self update should fail closed when bootstrap is required");
    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("requires staged/bootstrap self-upgrade")
    ));

    let err = app
        .update(&["iris".to_string()], options())
        .expect_err("ordinary package update should also fail closed for bootstrap iris update");
    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("requires staged/bootstrap self-upgrade")
    ));
    Ok(())
}

#[test]
fn staged_bootstrap_self_upgrade_updates_generation_and_schema() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(33);
    let trusted = trusted_key(&key);
    write_iris_package(repo_dir.path(), &key, "1.0.0", None, None)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["iris".to_string()], options())?;

    let before_generation = app
        .db
        .current_generation_id()?
        .expect("generation after initial install");
    assert_eq!(app.db.state_schema_version()?, 1);

    write_iris_package(
        repo_dir.path(),
        &key,
        "2.0.0",
        None,
        Some(PackageSelfUpgrade {
            bootstrap: true,
            from_state_schema: 1,
            target_state_schema: 2,
        }),
    )?;
    app.repo_sync()?;

    let dry_run = app.execute(IrisRequest::SelfStage {
        options: OperationOptions {
            dry_run: true,
            yes: false,
        },
    })?;
    assert!(dry_run.ok);
    assert_eq!(dry_run.data["plan"]["phase"].as_str(), Some("staged"));
    assert!(
        !state_dir
            .path()
            .join("bootstrap/self-upgrade-plan.json")
            .exists()
    );

    let stage = app.execute(IrisRequest::SelfStage { options: options() })?;
    assert!(stage.ok);
    assert_eq!(
        stage.data["plan"]["package"]["version"].as_str(),
        Some("2.0.0")
    );

    let plan_path = state_dir.path().join("bootstrap/self-upgrade-plan.json");
    assert!(plan_path.exists());
    let staged_hash = ContentStore::hash_bytes(b"#!/bin/sh\necho iris 2.0.0\n");
    let staged_object = app.store.object_path(&staged_hash)?;
    assert!(staged_object.exists());

    app.generation_gc()?;
    assert!(
        staged_object.exists(),
        "generation GC must retain staged bootstrap payload objects"
    );

    let staged_status = app.execute(IrisRequest::SelfStatus)?;
    assert_eq!(
        staged_status.data["repository_bootstrap_requirement"]["target_state_schema"].as_u64(),
        Some(2)
    );
    assert_eq!(
        staged_status.data["staged_bootstrap_plan"]["phase"].as_str(),
        Some("staged")
    );

    let bootstrap = app.execute(IrisRequest::SelfBootstrap { options: options() })?;
    assert!(bootstrap.ok);
    assert_eq!(bootstrap.data["target_state_schema"].as_u64(), Some(2));

    let after_generation = app
        .db
        .current_generation_id()?
        .expect("generation after bootstrap self-upgrade");
    let installed = app
        .db
        .installed_package("iris")?
        .expect("managed iris package should remain installed");

    assert!(after_generation > before_generation);
    assert_eq!(installed.manifest.package.version, "2.0.0");
    assert_eq!(app.db.state_schema_version()?, 2);
    assert!(!plan_path.exists());

    let status = app.execute(IrisRequest::SelfStatus)?;
    assert_eq!(status.data["state_schema_version"].as_u64(), Some(2));
    assert!(status.data["staged_bootstrap_plan"].is_null());
    assert_eq!(status.data["update_available"].as_bool(), Some(false));
    Ok(())
}

#[test]
fn daemon_transport_supports_staged_bootstrap_self_upgrade() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(34);
    let trusted = trusted_key(&key);
    write_iris_package(repo_dir.path(), &key, "1.0.0", None, None)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["iris".to_string()], options())?;

    let before_generation = app
        .db
        .current_generation_id()?
        .expect("generation after initial install");
    assert_eq!(app.db.state_schema_version()?, 1);

    write_iris_package(
        repo_dir.path(),
        &key,
        "2.0.0",
        None,
        Some(PackageSelfUpgrade {
            bootstrap: true,
            from_state_schema: 1,
            target_state_schema: 2,
        }),
    )?;
    app.repo_sync()?;

    let socket_path = state_dir.path().join("run").join("self-upgrade-irisd.sock");
    let root = state_dir.path().to_path_buf();
    let server_socket = socket_path.clone();
    let config = iris::daemon::DaemonConfig {
        verify_on_start: false,
        verify_interval: None,
        max_requests: Some(5),
        max_background_verifications: None,
    };
    let handle =
        thread::spawn(move || iris::daemon::serve_with_config(root, Some(server_socket), config));
    wait_for_socket(&socket_path);

    let initial_status = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::SelfStatus,
    )?;
    assert_eq!(
        initial_status.data["repository_bootstrap_requirement"]["target_state_schema"].as_u64(),
        Some(2)
    );

    let stage = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::SelfStage { options: options() },
    )?;
    assert!(stage.ok);
    assert_eq!(
        stage.data["plan"]["package"]["version"].as_str(),
        Some("2.0.0")
    );

    let plan_path = state_dir.path().join("bootstrap/self-upgrade-plan.json");
    assert!(plan_path.exists());

    let staged_status = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::SelfStatus,
    )?;
    assert_eq!(
        staged_status.data["staged_bootstrap_plan"]["phase"].as_str(),
        Some("staged")
    );

    let bootstrap = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::SelfBootstrap { options: options() },
    )?;
    assert!(bootstrap.ok);
    assert_eq!(bootstrap.data["target_state_schema"].as_u64(), Some(2));

    let final_status = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::SelfStatus,
    )?;
    handle.join().expect("daemon thread panicked")?;

    let app = Iris::open(state_dir.path())?;
    let after_generation = app
        .db
        .current_generation_id()?
        .expect("generation after bootstrap self-upgrade");
    let installed = app
        .db
        .installed_package("iris")?
        .expect("managed iris package should remain installed");

    assert!(after_generation > before_generation);
    assert_eq!(installed.manifest.package.version, "2.0.0");
    assert_eq!(app.db.state_schema_version()?, 2);
    assert!(!plan_path.exists());
    assert_eq!(final_status.data["state_schema_version"].as_u64(), Some(2));
    assert!(final_status.data["staged_bootstrap_plan"].is_null());
    assert_eq!(final_status.data["update_available"].as_bool(), Some(false));
    assert!(!socket_path.exists(), "daemon socket should be cleaned up");
    Ok(())
}

#[test]
fn daemon_observability_returns_structured_success_without_artifacts() -> Result<()> {
    let state_dir = tempdir()?;
    let app = Iris::open(state_dir.path())?;

    let status = app.execute(IrisRequest::DaemonStatus)?;
    let log = app.execute(IrisRequest::DaemonLog { lines: 10_000 })?;

    assert!(status.ok);
    assert_eq!(status.data["latest"], serde_json::Value::Null);
    assert!(status.message.contains("No daemon verify status"));

    assert!(log.ok);
    assert_eq!(log.data["entries"].as_array().map(Vec::len), Some(0));
    assert_eq!(log.data["limit"].as_u64(), Some(200));
    assert_eq!(log.data["truncated"].as_bool(), Some(false));
    assert!(log.message.contains("No daemon verify log entries"));
    Ok(())
}

#[test]
fn daemon_status_rejects_symlinked_artifact() -> Result<()> {
    let state_dir = tempdir()?;
    let run_dir = state_dir.path().join("run");
    let target = state_dir.path().join("status-target.json");
    ensure_private_dir(&run_dir)?;
    fs::write(&target, daemon_status_fixture("startup")?)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    symlink(&target, run_dir.join("daemon-status.json"))?;

    let app = Iris::open(state_dir.path())?;
    let err = app
        .execute(IrisRequest::DaemonStatus)
        .expect_err("symlinked daemon status artifact should fail closed");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("symlinked daemon status artifact")
    ));
    Ok(())
}

#[test]
fn daemon_status_rejects_overly_broad_sensitive_parent_permissions() -> Result<()> {
    let state_dir = tempdir()?;
    let run_dir = state_dir.path().join("run");
    fs::create_dir_all(&run_dir)?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o755))?;
    let status_path = run_dir.join("daemon-status.json");
    fs::write(&status_path, daemon_status_fixture("startup")?)?;
    fs::set_permissions(&status_path, fs::Permissions::from_mode(0o600))?;

    let app = Iris::open(state_dir.path())?;
    let err = app
        .execute(IrisRequest::DaemonStatus)
        .expect_err("overly broad daemon status parent permissions should fail closed");
    let mode = fs::metadata(&run_dir)?.permissions().mode() & 0o777;

    assert_eq!(mode, 0o755);
    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("overly broad directory permissions")
    ));
    Ok(())
}

#[test]
fn daemon_status_reports_same_error_in_direct_and_daemon_modes() -> Result<()> {
    let state_dir = tempdir()?;
    let status_path = state_dir.path().join("run/daemon-status.json");
    write_private_artifact(&status_path, b"{not-json")?;

    let app = Iris::open(state_dir.path())?;
    let direct_err = app
        .execute(IrisRequest::DaemonStatus)
        .expect_err("malformed daemon status artifact should fail closed");

    let socket_path = state_dir.path().join("run").join("status-check-irisd.sock");
    let root = state_dir.path().to_path_buf();
    let server_socket = socket_path.clone();
    let config = iris::daemon::DaemonConfig {
        verify_on_start: false,
        verify_interval: None,
        max_requests: Some(1),
        max_background_verifications: None,
    };
    let handle =
        thread::spawn(move || iris::daemon::serve_with_config(root, Some(server_socket), config));

    wait_for_socket(&socket_path);
    let remote_err = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::DaemonStatus,
    )
    .expect_err("daemon transport should surface malformed status as remote error");
    handle.join().expect("daemon thread panicked")?;

    assert!(matches!(
        remote_err,
        IrisError::Remote(message) if message == direct_err.to_string()
    ));
    Ok(())
}

#[test]
fn daemon_status_rejects_oversized_artifact() -> Result<()> {
    let state_dir = tempdir()?;
    let status_path = state_dir.path().join("run/daemon-status.json");
    write_private_artifact(&status_path, &vec![b'a'; 2 * 1024 * 1024 + 1])?;

    let app = Iris::open(state_dir.path())?;
    let err = app
        .execute(IrisRequest::DaemonStatus)
        .expect_err("oversized daemon status artifact should fail closed");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("daemon status artifact exceeds safe read limit")
    ));
    Ok(())
}

#[test]
fn daemon_log_rejects_invalid_utf8_artifact() -> Result<()> {
    let state_dir = tempdir()?;
    let log_path = state_dir.path().join("log/daemon-verify.jsonl");
    write_private_artifact(&log_path, b"{\"trigger\":\"startup\"}\n\xff")?;

    let app = Iris::open(state_dir.path())?;
    let err = app
        .execute(IrisRequest::DaemonLog { lines: 1 })
        .expect_err("invalid UTF-8 daemon log should fail closed");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("daemon verify log is not valid UTF-8")
    ));
    Ok(())
}

#[test]
fn daemon_log_rejects_oversized_single_entry() -> Result<()> {
    let state_dir = tempdir()?;
    let log_path = state_dir.path().join("log/daemon-verify.jsonl");
    write_private_artifact(&log_path, &vec![b'a'; 2 * 1024 * 1024 + 1])?;

    let app = Iris::open(state_dir.path())?;
    let err = app
        .execute(IrisRequest::DaemonLog { lines: 1 })
        .expect_err("oversized daemon log entry should fail closed");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("daemon verify log contains an entry exceeding safe read limit")
    ));
    Ok(())
}

#[test]
fn daemon_verify_log_retention_compacts_large_logs() -> Result<()> {
    let state_dir = tempdir()?;
    let log_path = state_dir.path().join("log/daemon-verify.jsonl");
    let mut entry_count = 0usize;
    let line = serde_json::to_string(&serde_json::json!({
        "trigger": "historical",
        "status": "ok",
        "started_at": "2026-03-10T00:00:00Z",
        "finished_at": "2026-03-10T00:00:01Z",
        "mode": "full",
        "message": "historical entry",
        "issue_count": 0,
        "report": serde_json::Value::Null,
        "error": serde_json::Value::Null,
    }))?;
    let mut bytes = Vec::new();
    while bytes.len() <= 300_000 {
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        entry_count += 1;
    }
    write_private_artifact(&log_path, &bytes)?;

    let config = iris::daemon::DaemonConfig {
        verify_on_start: true,
        verify_interval: None,
        max_requests: None,
        max_background_verifications: Some(1),
    };
    iris::daemon::serve_with_config(state_dir.path(), None, config)?;

    let retained = fs::read_to_string(&log_path)?;
    let retained_metadata = fs::metadata(&log_path)?;
    let retained_lines: Vec<_> = retained.lines().collect();

    assert!(retained_metadata.len() <= 128 * 1024);
    assert!(retained_lines.len() < entry_count + 1);
    assert!(!retained_lines.is_empty());

    let last: serde_json::Value =
        serde_json::from_str(retained_lines.last().expect("retained log line"))?;
    assert_eq!(last["trigger"].as_str(), Some("startup"));

    for line in retained_lines {
        let _: serde_json::Value = serde_json::from_str(line)?;
    }
    Ok(())
}

#[test]
fn daemon_serves_ping_over_unix_socket() -> Result<()> {
    let state_dir = tempdir()?;
    let socket_path = state_dir.path().join("run").join("test-irisd.sock");
    let root = state_dir.path().to_path_buf();
    let server_socket = socket_path.clone();

    let handle = thread::spawn(move || iris::daemon::serve(root, Some(server_socket), Some(1)));

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    assert!(socket_path.exists(), "daemon socket should exist");

    let mut stream = connect_socket_with_retry(&socket_path)?;
    serde_json::to_writer(&mut stream, &DaemonRequestEnvelope::new(IrisRequest::Ping))?;
    stream.shutdown(Shutdown::Write)?;

    let envelope: DaemonResponseEnvelope = serde_json::from_reader(&mut stream)?;
    handle.join().expect("daemon thread panicked")?;

    assert_eq!(envelope.version, 1);
    assert!(envelope.response.ok);
    assert_eq!(envelope.response.message, "pong");
    assert!(!socket_path.exists(), "daemon socket should be cleaned up");
    Ok(())
}

#[test]
fn daemon_client_requests_ping_over_unix_socket() -> Result<()> {
    let state_dir = tempdir()?;
    let socket_path = state_dir.path().join("run").join("client-irisd.sock");
    let root = state_dir.path().to_path_buf();
    let server_socket = socket_path.clone();

    let handle = thread::spawn(move || iris::daemon::serve(root, Some(server_socket), Some(1)));

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    assert!(socket_path.exists(), "daemon socket should exist");
    let response = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::Ping,
    )?;
    handle.join().expect("daemon thread panicked")?;

    assert!(response.ok);
    assert_eq!(response.message, "pong");
    assert!(!socket_path.exists(), "daemon socket should be cleaned up");
    Ok(())
}

#[test]
fn daemon_client_fails_closed_when_socket_missing() -> Result<()> {
    let state_dir = tempdir()?;
    let missing_socket = state_dir.path().join("run").join("missing-irisd.sock");
    fs::create_dir_all(missing_socket.parent().expect("socket parent"))?;
    fs::set_permissions(
        missing_socket.parent().expect("socket parent"),
        fs::Permissions::from_mode(0o700),
    )?;

    let err = iris::daemon::request(state_dir.path(), Some(missing_socket), IrisRequest::Ping)
        .expect_err("missing daemon socket should fail without fallback");

    assert!(matches!(err, IrisError::Io(ref io_err) if io_err.kind() == io::ErrorKind::NotFound));
    Ok(())
}

#[test]
fn daemon_rejects_second_instance_when_lock_is_held() -> Result<()> {
    let state_dir = tempdir()?;
    let socket_path = state_dir.path().join("run").join("lock-irisd.sock");
    let root = state_dir.path().to_path_buf();
    let server_socket = socket_path.clone();

    let handle = thread::spawn(move || iris::daemon::serve(root, Some(server_socket), Some(1)));

    wait_for_socket(&socket_path);

    let err = iris::daemon::serve(state_dir.path(), Some(socket_path.clone()), Some(1))
        .expect_err("second daemon instance should fail closed");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("another irisd instance is already active")
    ));

    let response = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::Ping,
    )?;
    handle.join().expect("daemon thread panicked")?;

    assert!(response.ok);
    assert_eq!(response.message, "pong");
    Ok(())
}

#[test]
fn daemon_rejects_oversized_request_without_panicking() -> Result<()> {
    let state_dir = tempdir()?;
    let socket_path = state_dir.path().join("run").join("oversized-irisd.sock");
    let root = state_dir.path().to_path_buf();
    let server_socket = socket_path.clone();

    let handle = thread::spawn(move || iris::daemon::serve(root, Some(server_socket), Some(1)));

    wait_for_socket(&socket_path);

    let mut stream = connect_socket_with_retry(&socket_path)?;
    stream.write_all(&vec![b'a'; 300_000])?;
    stream.shutdown(Shutdown::Write)?;

    let envelope: DaemonResponseEnvelope = serde_json::from_reader(&mut stream)?;
    handle.join().expect("daemon thread panicked")?;

    assert!(!envelope.response.ok);
    assert!(envelope.response.message.contains("invalid daemon request"));
    assert!(envelope.response.message.contains("exceeds"));
    Ok(())
}

#[test]
fn daemon_rejects_malformed_request_without_panicking() -> Result<()> {
    let state_dir = tempdir()?;
    let socket_path = state_dir.path().join("run").join("malformed-irisd.sock");
    let root = state_dir.path().to_path_buf();
    let server_socket = socket_path.clone();

    let handle = thread::spawn(move || iris::daemon::serve(root, Some(server_socket), Some(1)));

    wait_for_socket(&socket_path);

    let mut stream = connect_socket_with_retry(&socket_path)?;
    stream.write_all(br#"{"version":1,"request""#)?;
    stream.shutdown(Shutdown::Write)?;

    let envelope: DaemonResponseEnvelope = serde_json::from_reader(&mut stream)?;
    handle.join().expect("daemon thread panicked")?;

    assert!(!envelope.response.ok);
    assert!(envelope.response.message.contains("invalid daemon request"));
    Ok(())
}

#[test]
fn daemon_client_rejects_overly_broad_socket_parent_permissions() -> Result<()> {
    let state_dir = tempdir()?;
    let run_dir = state_dir.path().join("run");
    fs::create_dir_all(&run_dir)?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o777))?;

    let err = iris::daemon::request(
        state_dir.path(),
        Some(run_dir.join("irisd.sock")),
        IrisRequest::Ping,
    )
    .expect_err("client should reject overly broad socket parent permissions");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("overly broad directory permissions")
    ));
    Ok(())
}

#[test]
fn daemon_rejects_symlinked_lock_path() -> Result<()> {
    let state_dir = tempdir()?;
    let run_dir = state_dir.path().join("run");
    let lock_target = state_dir.path().join("lock-target");
    fs::create_dir_all(&run_dir)?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))?;
    fs::write(&lock_target, b"lock")?;
    symlink(&lock_target, run_dir.join("irisd.lock"))?;

    let config = iris::daemon::DaemonConfig {
        verify_on_start: false,
        verify_interval: None,
        max_requests: Some(1),
        max_background_verifications: None,
    };
    let err = iris::daemon::serve_with_config(state_dir.path(), None, config)
        .expect_err("symlinked daemon lock path should fail closed");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("symlinked daemon lock path")
    ));
    Ok(())
}

#[test]
fn daemon_rejects_symlinked_verify_log_path() -> Result<()> {
    let state_dir = tempdir()?;
    let log_dir = state_dir.path().join("log");
    let log_target = state_dir.path().join("verify-log-target.jsonl");
    fs::create_dir_all(&log_dir)?;
    fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700))?;
    fs::write(&log_target, b"{}\n")?;
    symlink(&log_target, log_dir.join("daemon-verify.jsonl"))?;

    let config = iris::daemon::DaemonConfig {
        verify_on_start: true,
        verify_interval: None,
        max_requests: None,
        max_background_verifications: Some(1),
    };
    let err = iris::daemon::serve_with_config(state_dir.path(), None, config)
        .expect_err("symlinked daemon verify log should fail closed");

    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("symlinked daemon verify log artifact")
    ));
    Ok(())
}

#[test]
fn daemon_startup_verify_writes_skipped_status_without_generation() -> Result<()> {
    let state_dir = tempdir()?;
    let config = iris::daemon::DaemonConfig {
        verify_on_start: true,
        verify_interval: None,
        max_requests: None,
        max_background_verifications: Some(1),
    };

    iris::daemon::serve_with_config(state_dir.path(), None, config)?;

    let status_path = state_dir.path().join("run/daemon-status.json");
    let log_path = state_dir.path().join("log/daemon-verify.jsonl");
    let status: serde_json::Value = serde_json::from_slice(&fs::read(&status_path)?)?;
    let log = fs::read_to_string(log_path)?;

    assert_eq!(status["trigger"].as_str(), Some("startup"));
    assert_eq!(status["status"].as_str(), Some("skipped"));
    assert!(
        status["message"]
            .as_str()
            .is_some_and(|message| message.contains("no current generation"))
    );
    assert_eq!(log.lines().count(), 1);
    Ok(())
}

#[test]
fn daemon_startup_verify_records_warning_report() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(11);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["hello".to_string()], options())?;

    let generation_id = app
        .db
        .current_generation_id()?
        .expect("generation after install");
    fs::write(
        app.layout
            .generation_dir(generation_id)
            .join("etc/hello.conf"),
        b"greeting = \"changed\"\n",
    )?;

    let config = iris::daemon::DaemonConfig {
        verify_on_start: true,
        verify_interval: None,
        max_requests: None,
        max_background_verifications: Some(1),
    };
    iris::daemon::serve_with_config(state_dir.path(), None, config)?;

    let status: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.path().join("run/daemon-status.json"))?)?;

    assert_eq!(status["trigger"].as_str(), Some("startup"));
    assert_eq!(status["status"].as_str(), Some("warning"));
    assert_eq!(status["issue_count"].as_u64(), Some(1));
    assert_eq!(status["report"]["mode"].as_str(), Some("full"));
    assert_eq!(
        status["report"]["issues"][0]["kind"].as_str(),
        Some("modified-config")
    );
    Ok(())
}

#[test]
fn daemon_interval_verify_runs_without_startup_verify() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(12);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["hello".to_string()], options())?;

    let config = iris::daemon::DaemonConfig {
        verify_on_start: false,
        verify_interval: Some(Duration::from_millis(50)),
        max_requests: None,
        max_background_verifications: Some(1),
    };
    iris::daemon::serve_with_config(state_dir.path(), None, config)?;

    let status: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.path().join("run/daemon-status.json"))?)?;
    let log = fs::read_to_string(state_dir.path().join("log/daemon-verify.jsonl"))?;

    assert_eq!(status["trigger"].as_str(), Some("interval"));
    assert_eq!(status["status"].as_str(), Some("ok"));
    assert_eq!(status["issue_count"].as_u64(), Some(0));
    assert_eq!(log.lines().count(), 1);
    Ok(())
}

#[test]
fn daemon_observability_matches_between_direct_and_daemon_transports() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(13);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["hello".to_string()], options())?;

    let verify_config = iris::daemon::DaemonConfig {
        verify_on_start: true,
        verify_interval: None,
        max_requests: None,
        max_background_verifications: Some(1),
    };
    iris::daemon::serve_with_config(state_dir.path(), None, verify_config)?;

    let direct_status = app.execute(IrisRequest::DaemonStatus)?;
    let direct_log = app.execute(IrisRequest::DaemonLog { lines: 1 })?;

    assert_eq!(direct_status.data["latest"]["status"].as_str(), Some("ok"));
    assert_eq!(direct_log.data["entries"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        direct_log.data["entries"][0]["trigger"].as_str(),
        Some("startup")
    );

    let socket_path = state_dir
        .path()
        .join("run")
        .join("observability-irisd.sock");
    let root = state_dir.path().to_path_buf();
    let server_socket = socket_path.clone();
    let serve_config = iris::daemon::DaemonConfig {
        verify_on_start: false,
        verify_interval: None,
        max_requests: Some(2),
        max_background_verifications: None,
    };

    let handle = thread::spawn(move || {
        iris::daemon::serve_with_config(root, Some(server_socket), serve_config)
    });
    wait_for_socket(&socket_path);

    let daemon_status = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::DaemonStatus,
    )?;
    let daemon_log = iris::daemon::request(
        state_dir.path(),
        Some(socket_path.clone()),
        IrisRequest::DaemonLog { lines: 1 },
    )?;
    handle.join().expect("daemon thread panicked")?;

    assert_eq!(daemon_status.data, direct_status.data);
    assert_eq!(daemon_log.data, direct_log.data);
    assert_eq!(daemon_status.message, direct_status.message);
    assert_eq!(daemon_log.message, direct_log.message);
    Ok(())
}

#[test]
fn lifecycle_install_verify_remove_and_purge() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(7);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;

    app.install(&["hello".to_string()], options())?;
    let history_after_install = app.db.list_history()?;
    assert_eq!(history_after_install.len(), 1);
    assert_eq!(history_after_install[0].action, "install");

    let generation_id = app
        .db
        .current_generation_id()?
        .expect("generation after install");
    let generation_dir = app.layout.generation_dir(generation_id);

    assert!(
        fs::symlink_metadata(generation_dir.join("usr/bin/hello"))?
            .file_type()
            .is_symlink()
    );
    assert!(generation_dir.join("etc/hello.conf").is_file());

    let verify_fast = app.verify(&[], false)?;
    assert_eq!(verify_fast.data["mode"].as_str(), Some("fast"));
    assert_eq!(verify_fast.data["checked_packages"].as_u64(), Some(1));
    assert_eq!(verify_fast.data["hashed_files"].as_u64(), Some(0));
    assert_eq!(verify_fast.data["issues"].as_array().map(Vec::len), Some(0));

    fs::write(
        generation_dir.join("etc/hello.conf"),
        b"greeting = \"custom\"\n",
    )?;
    let verify_fast_modified = app.verify(&[], false)?;
    assert_eq!(
        verify_fast_modified.data["issues"].as_array().map(Vec::len),
        Some(0)
    );

    let verify_modified = app.verify(&[], true)?;
    assert_eq!(verify_modified.data["mode"].as_str(), Some("full"));
    assert_eq!(verify_modified.data["hashed_files"].as_u64(), Some(2));
    assert_eq!(
        verify_modified.data["issues"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        verify_modified.data["issues"][0]["kind"].as_str(),
        Some("modified-config")
    );

    let audit = app.audit()?;
    assert_eq!(audit.data["status"].as_str(), Some("warning"));
    assert_eq!(audit.data["verify"]["mode"].as_str(), Some("full"));
    assert!(
        audit.data["findings"]
            .as_array()
            .expect("audit findings array")
            .iter()
            .any(|finding| {
                finding["scope"].as_str() == Some("verify")
                    && finding["subject"].as_str() == Some("hello:etc/hello.conf")
            })
    );

    app.remove(&["hello".to_string()], options())?;
    let history_after_remove = app.db.list_history()?;
    assert_eq!(history_after_remove.len(), 2);
    assert_eq!(history_after_remove[0].action, "remove");

    let installed = app
        .db
        .installed_package("hello")?
        .expect("installed state retained");
    assert_eq!(installed.state.as_str(), "orphaned-config");

    let orphans = app.db.list_orphans(Some("hello"))?;
    assert_eq!(orphans.len(), 1);
    assert!(orphans[0].modified);
    assert!(
        app.layout
            .orphan_file_dir("hello")
            .join("etc/hello.conf")
            .exists()
    );

    let removed_generation = app
        .db
        .current_generation_id()?
        .expect("generation after remove");
    let removed_dir = app.layout.generation_dir(removed_generation);
    assert!(!removed_dir.join("usr/bin/hello").exists());
    assert!(removed_dir.join("etc/hello.conf").exists());

    app.purge(&["hello".to_string()], options())?;
    let history_after_purge = app.db.list_history()?;
    assert_eq!(history_after_purge.len(), 3);
    assert_eq!(history_after_purge[0].action, "purge");

    assert!(app.db.installed_package("hello")?.is_none());
    assert!(app.db.list_orphans(Some("hello"))?.is_empty());
    assert!(!app.layout.orphan_file_dir("hello").exists());

    let purged_generation = app
        .db
        .current_generation_id()?
        .expect("generation after purge");
    let purged_dir = app.layout.generation_dir(purged_generation);
    assert!(!purged_dir.join("usr/bin/hello").exists());
    assert!(!purged_dir.join("etc/hello.conf").exists());
    Ok(())
}

#[test]
fn install_resolves_dependencies_and_blocks_required_removal() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(9);
    let trusted = trusted_key(&key);
    write_dependency_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;

    let install = app.install(&["greeter".to_string()], options())?;
    assert_eq!(
        install.data["requested_packages"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        install.data["resolved_packages"].as_array().map(Vec::len),
        Some(2)
    );

    let installed = app.db.list_installed_packages()?;
    assert_eq!(installed.len(), 2);
    assert!(
        installed
            .iter()
            .any(|record| record.manifest.package.name == "libgreet")
    );
    assert!(
        installed
            .iter()
            .any(|record| record.manifest.package.name == "greeter")
    );

    let why = app.why("libgreet")?;
    assert!(
        why.data["required_by"]
            .as_array()
            .expect("required_by array")
            .iter()
            .any(|item| item.as_str() == Some("greeter"))
    );

    let err = app
        .remove(&["libgreet".to_string()], options())
        .expect_err("dependency removal should be blocked");
    assert!(matches!(
        err,
        IrisError::DependencyResolution(message) if message.contains("required by greeter")
    ));
    Ok(())
}

#[test]
fn install_dry_run_does_not_stage_store_objects() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(14);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;

    let response = app.install(
        &["hello".to_string()],
        OperationOptions {
            dry_run: true,
            yes: false,
        },
    )?;

    assert!(response.ok);
    assert_eq!(app.db.current_generation_id()?, None);
    assert!(app.db.installed_package("hello")?.is_none());
    assert!(fs::read_dir(app.layout.store_dir())?.next().is_none());
    Ok(())
}

#[test]
fn generation_switch_and_rollback_reconcile_installed_state() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(15);
    let trusted = trusted_key(&key);
    write_hello_package(
        repo_dir.path(),
        &key,
        "1.0.0",
        b"#!/bin/sh\necho hello v1\n",
    )?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["hello".to_string()], options())?;

    let generation_v1 = app
        .db
        .current_generation_id()?
        .expect("generation after initial install");
    assert_eq!(
        app.db
            .installed_package("hello")?
            .expect("hello installed")
            .manifest
            .package
            .version,
        "1.0.0"
    );

    write_hello_package(
        repo_dir.path(),
        &key,
        "2.0.0",
        b"#!/bin/sh\necho hello v2\n",
    )?;
    app.repo_sync()?;
    app.update(&["hello".to_string()], options())?;

    let generation_v2 = app
        .db
        .current_generation_id()?
        .expect("generation after update");
    assert!(generation_v2 > generation_v1);
    assert_eq!(
        app.db
            .installed_package("hello")?
            .expect("hello installed after update")
            .manifest
            .package
            .version,
        "2.0.0"
    );

    app.generation_rollback()?;
    let rolled_back = app
        .db
        .installed_package("hello")?
        .expect("hello installed after rollback");
    assert_eq!(rolled_back.manifest.package.version, "1.0.0");
    assert_eq!(rolled_back.generation_id, Some(generation_v1));

    app.generation_switch(generation_v2)?;
    let switched = app
        .db
        .installed_package("hello")?
        .expect("hello installed after switch");
    assert_eq!(switched.manifest.package.version, "2.0.0");
    assert_eq!(switched.generation_id, Some(generation_v2));
    Ok(())
}

#[test]
fn repo_sync_rejects_untrusted_signatures() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let signing = signing_key(11);
    let trusted = signing_key(12);
    write_hello_repo(repo_dir.path(), &signing)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(
        repo_dir.path().to_str().expect("utf8 path"),
        &trusted_key(&trusted),
    )?;

    let err = app
        .repo_sync()
        .expect_err("repo sync should reject manifest signed by another key");
    assert!(matches!(
        err,
        IrisError::SignatureVerification(message) if message.contains("untrusted key")
    ));
    Ok(())
}

#[test]
fn repo_sync_rejects_missing_payload_files() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(36);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let missing_payload = repo_dir.path().join("payload/hello-1.0.0/usr/bin/hello");
    fs::remove_file(&missing_payload)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;

    let err = app
        .repo_sync()
        .expect_err("repo sync should reject missing payload files");
    assert!(matches!(
        err,
        IrisError::MissingPayload { package, path }
            if package == "hello" && path == missing_payload
    ));
    Ok(())
}

#[test]
fn repo_sync_keeps_previous_index_when_replacement_fails() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(21);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    assert_eq!(app.db.repo_packages_for_name("hello")?.len(), 1);

    fs::copy(
        repo_dir.path().join("packages/hello-1.0.0.toml"),
        repo_dir.path().join("packages/hello-duplicate.toml"),
    )?;

    app.repo_sync()
        .expect_err("duplicate package snapshot should fail atomically");
    let indexed = app.db.repo_packages_for_name("hello")?;
    assert_eq!(indexed.len(), 1);
    assert_eq!(indexed[0].manifest.package.version, "1.0.0");
    Ok(())
}

#[test]
fn install_rejects_symlinked_repo_payload_entries_after_sync() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(37);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;

    let payload_file = repo_dir.path().join("payload/hello-1.0.0/usr/bin/hello");
    let payload_target = repo_dir.path().join("payload/symlink-target");
    fs::write(&payload_target, b"#!/bin/sh\necho hijacked\n")?;
    fs::remove_file(&payload_file)?;
    symlink(&payload_target, &payload_file)?;

    let err = app
        .install(&["hello".to_string()], options())
        .expect_err("install should reject symlinked repository payload entries");
    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("symlinked repository payload entry")
    ));
    Ok(())
}

#[test]
fn repair_uses_exact_repository_snapshot() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(38);
    let trusted = trusted_key(&key);
    let version_one = b"#!/bin/sh\necho hello v1\n";
    let version_two = b"#!/bin/sh\necho hello v2\n";
    write_hello_package(repo_dir.path(), &key, "1.0.0", version_one)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["hello".to_string()], options())?;

    let installed = app
        .db
        .installed_package("hello")?
        .expect("hello should be installed");
    let binary = installed
        .manifest
        .files
        .iter()
        .find(|file| file.path == "usr/bin/hello")
        .expect("hello binary entry should exist");
    let object_path = app.store.object_path(&binary.blake3)?;
    fs::remove_file(&object_path)?;
    assert!(!object_path.exists());

    write_hello_package(repo_dir.path(), &key, "2.0.0", version_two)?;
    app.repo_sync()?;

    app.repair(&["hello".to_string()], options())?;
    assert_eq!(fs::read(&object_path)?, version_one);
    Ok(())
}

#[test]
fn orphan_purge_rejects_missing_package_target() -> Result<()> {
    let state_dir = tempdir()?;
    let app = Iris::open(state_dir.path())?;

    let err = app
        .orphan_purge(Some("hello"), false, options())
        .expect_err("orphan purge should fail when the requested package has no orphan entries");
    assert!(matches!(
        err,
        IrisError::InvalidInput(message)
            if message.contains("package has no orphaned configuration: hello")
    ));
    Ok(())
}

#[test]
fn open_reconciles_current_link_and_cleans_unregistered_generation_dir() -> Result<()> {
    let state_dir = tempdir()?;
    let repo_dir = tempdir()?;
    let key = signing_key(22);
    let trusted = trusted_key(&key);
    write_hello_repo(repo_dir.path(), &key)?;

    let app = Iris::open(state_dir.path())?;
    app.repo_add(repo_dir.path().to_str().expect("utf8 path"), &trusted)?;
    app.repo_sync()?;
    app.install(&["hello".to_string()], options())?;

    let current_generation = app
        .db
        .current_generation_id()?
        .expect("generation after install");
    let stale_generation = current_generation + 1;
    let stale_dir = app.layout.generation_dir(stale_generation);
    fs::create_dir_all(&stale_dir)?;
    fs::write(stale_dir.join("stale.txt"), b"stale")?;

    let current_link = app.layout.current_link();
    fs::remove_file(&current_link)?;
    symlink(&stale_dir, &current_link)?;
    symlink(
        &stale_dir,
        app.layout.generations_dir().join(".current-new"),
    )?;

    let reopened = Iris::open(state_dir.path())?;

    assert_eq!(
        reopened.db.current_generation_id()?,
        Some(current_generation)
    );
    assert_eq!(
        fs::read_link(reopened.layout.current_link())?,
        reopened.layout.generation_dir(current_generation)
    );
    assert!(!stale_dir.exists());
    assert!(
        !reopened
            .layout
            .generations_dir()
            .join(".current-new")
            .exists()
    );
    Ok(())
}
