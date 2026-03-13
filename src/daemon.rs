use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::api::{
    DaemonRequestEnvelope, DaemonResponseEnvelope, IrisRequest, IrisResponse, PROTOCOL_VERSION,
};
use crate::error::{IrisError, Result};
use crate::models::{DaemonVerifyStatus, VerifyReport};
use crate::ops::Iris;
use crate::state::StateLayout;

const DEFAULT_DAEMON_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DAEMON_REQUEST_BYTES: usize = 256 * 1024;
const MAX_DAEMON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DAEMON_VERIFY_LOG_BYTES: u64 = 256 * 1024;
const RETAINED_DAEMON_VERIFY_LOG_BYTES: usize = 128 * 1024;
const MAX_ARTIFACT_TEMP_FILE_ATTEMPTS: u64 = 1024;

static ARTIFACT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct DaemonConfig {
    pub verify_on_start: bool,
    pub verify_interval: Option<Duration>,
    pub max_requests: Option<usize>,
    pub max_background_verifications: Option<usize>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            verify_on_start: true,
            verify_interval: Some(Duration::from_secs(300)),
            max_requests: None,
            max_background_verifications: None,
        }
    }
}

struct InstanceLockGuard {
    _file: File,
}

struct SocketGuard {
    path: PathBuf,
}

impl SocketGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct SchedulerState {
    config: DaemonConfig,
    next_verify_at: Option<Instant>,
    background_runs: usize,
}

impl SchedulerState {
    fn new(config: DaemonConfig) -> Self {
        Self {
            config,
            next_verify_at: config
                .verify_interval
                .map(|interval| Instant::now() + interval),
            background_runs: 0,
        }
    }

    fn interval_due(&self) -> bool {
        self.next_verify_at
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn record_run(&mut self) {
        self.background_runs += 1;
        self.next_verify_at = self
            .config
            .verify_interval
            .map(|interval| Instant::now() + interval);
    }

    fn limit_reached(&self) -> bool {
        self.config
            .max_background_verifications
            .is_some_and(|limit| self.background_runs >= limit)
    }
}

pub fn serve(
    root: impl Into<PathBuf>,
    socket_path: Option<PathBuf>,
    max_requests: Option<usize>,
) -> Result<()> {
    let config = DaemonConfig {
        max_requests,
        ..DaemonConfig::default()
    };
    serve_with_config(root, socket_path, config)
}

pub fn serve_with_config(
    root: impl Into<PathBuf>,
    socket_path: Option<PathBuf>,
    config: DaemonConfig,
) -> Result<()> {
    let layout = StateLayout::new(root);
    layout.ensure()?;
    let daemon_owner_uid = current_effective_uid()?;
    let _instance_lock = acquire_instance_lock(&layout, daemon_owner_uid)?;
    let socket_path = socket_path.unwrap_or_else(|| layout.daemon_socket_path());
    let listener = bind_listener(&socket_path, daemon_owner_uid)?;
    listener.set_nonblocking(true)?;
    let _guard = SocketGuard::new(socket_path);
    let mut scheduler = SchedulerState::new(config);

    if config.verify_on_start {
        run_and_record_background_verify(&layout, "startup")?;
        scheduler.record_run();
        if scheduler.limit_reached() {
            return Ok(());
        }
    }

    let mut handled = 0usize;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                handle_stream(&layout.root, daemon_owner_uid, stream);
                handled += 1;
                if config.max_requests.is_some_and(|limit| handled >= limit) {
                    break;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err.into()),
        }

        if scheduler.interval_due() {
            run_and_record_background_verify(&layout, "interval")?;
            scheduler.record_run();
            if scheduler.limit_reached() {
                break;
            }
        }

        thread::sleep(Duration::from_millis(25));
    }

    Ok(())
}

pub fn background_verify_once(root: impl Into<PathBuf>, trigger: &str) -> Result<()> {
    let layout = StateLayout::new(root);
    layout.ensure()?;
    run_and_record_background_verify(&layout, trigger)
}

pub fn request(
    root: impl Into<PathBuf>,
    socket_path: Option<PathBuf>,
    request: IrisRequest,
) -> Result<IrisResponse> {
    let layout = StateLayout::new(root);
    let socket_path = socket_path.unwrap_or_else(|| layout.daemon_socket_path());
    validate_client_socket_path(&socket_path)?;

    let mut stream = UnixStream::connect(&socket_path)?;
    configure_stream(&stream)?;
    serde_json::to_writer(&mut stream, &DaemonRequestEnvelope::new(request))?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;

    let envelope = read_response(&stream)?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(IrisError::Unsupported(format!(
            "unsupported daemon protocol version: {}",
            envelope.version
        )));
    }

    if !envelope.response.ok {
        return Err(IrisError::Remote(envelope.response.message));
    }

    Ok(envelope.response)
}

fn run_and_record_background_verify(layout: &StateLayout, trigger: &str) -> Result<()> {
    let status = collect_verify_status(layout, trigger);
    write_daemon_verify_status(layout, &status)
}

fn collect_verify_status(layout: &StateLayout, trigger: &str) -> DaemonVerifyStatus {
    let started_at = Utc::now();
    let started_at_text = started_at.to_rfc3339();

    let result = Iris::open(&layout.root).and_then(|app| match app.db.current_generation_id()? {
        Some(_) => app.verify(&[], true),
        None => Err(IrisError::NoCurrentGeneration),
    });

    match result {
        Ok(response) => match serde_json::from_value::<VerifyReport>(response.data.clone()) {
            Ok(report) => DaemonVerifyStatus {
                trigger: trigger.into(),
                status: classify_report_status(&report).into(),
                started_at: started_at_text,
                finished_at: Utc::now().to_rfc3339(),
                mode: report.mode.clone(),
                message: response.message,
                issue_count: report.issues.len(),
                report: Some(report),
                error: None,
            },
            Err(err) => error_verify_status(
                trigger,
                started_at_text,
                format!("failed to decode verify report: {err}"),
            ),
        },
        Err(IrisError::NoCurrentGeneration) => skipped_verify_status(
            trigger,
            "no current generation available for daemon verification",
        ),
        Err(err) => error_verify_status(trigger, started_at_text, err.to_string()),
    }
}

fn classify_report_status(report: &VerifyReport) -> &'static str {
    if report.issues.iter().any(|issue| issue.severity == "error") {
        "error"
    } else if report
        .issues
        .iter()
        .any(|issue| issue.severity == "warning")
    {
        "warning"
    } else {
        "ok"
    }
}

fn skipped_verify_status(trigger: &str, message: &str) -> DaemonVerifyStatus {
    let now = Utc::now().to_rfc3339();
    DaemonVerifyStatus {
        trigger: trigger.into(),
        status: "skipped".into(),
        started_at: now.clone(),
        finished_at: now,
        mode: "full".into(),
        message: message.into(),
        issue_count: 0,
        report: None,
        error: None,
    }
}

fn error_verify_status(trigger: &str, started_at: String, error: String) -> DaemonVerifyStatus {
    DaemonVerifyStatus {
        trigger: trigger.into(),
        status: "error".into(),
        started_at,
        finished_at: Utc::now().to_rfc3339(),
        mode: "full".into(),
        message: format!("daemon verification failed: {error}"),
        issue_count: 0,
        report: None,
        error: Some(error),
    }
}

fn write_daemon_verify_status(layout: &StateLayout, status: &DaemonVerifyStatus) -> Result<()> {
    write_status_file(layout, status)?;
    append_verify_log(layout, status)?;
    Ok(())
}

fn write_status_file(layout: &StateLayout, status: &DaemonVerifyStatus) -> Result<()> {
    let path = layout.daemon_status_path();
    let owner_uid = current_effective_uid()?;
    if let Some(parent) = path.parent() {
        prepare_secure_directory(parent, owner_uid, "daemon status directory")?;
    }
    let bytes = serde_json::to_vec_pretty(status)?;
    write_atomic_artifact_file(&path, &bytes, owner_uid, "daemon status artifact")
}

fn append_verify_log(layout: &StateLayout, status: &DaemonVerifyStatus) -> Result<()> {
    let path = layout.daemon_verify_log_path();
    let owner_uid = current_effective_uid()?;
    if let Some(parent) = path.parent() {
        prepare_secure_directory(parent, owner_uid, "daemon log directory")?;
    }
    let mut file = open_append_only_artifact_file(&path, owner_uid, "daemon verify log artifact")?;
    writeln!(file, "{}", serde_json::to_string(status)?)?;
    file.flush()?;
    file.sync_data()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    enforce_verify_log_retention(&path, owner_uid)?;
    sync_parent_dir(&path)?;
    Ok(())
}

fn bind_listener(socket_path: &Path, expected_uid: u32) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        prepare_secure_directory(parent, expected_uid, "daemon socket parent")?;
    }

    match fs::symlink_metadata(socket_path) {
        Ok(metadata) => {
            if metadata.file_type().is_socket() {
                fs::remove_file(socket_path)?;
            } else {
                return Err(IrisError::InvalidInput(format!(
                    "refusing to replace non-socket daemon path: {}",
                    socket_path.display()
                )));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let listener = UnixListener::bind(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    validate_socket_file(socket_path, expected_uid, "daemon socket")?;
    Ok(listener)
}

fn handle_stream(root: &Path, expected_uid: u32, mut stream: UnixStream) {
    let response = match configure_stream(&stream)
        .and_then(|_| validate_peer_credentials(&stream, expected_uid))
    {
        Ok(()) => match read_request(&stream) {
            Ok(envelope) if envelope.version == PROTOCOL_VERSION => {
                match Iris::open(root).and_then(|app| app.execute(envelope.request)) {
                    Ok(response) => response,
                    Err(err) => IrisResponse::error(err.to_string()),
                }
            }
            Ok(envelope) => IrisResponse::error(format!(
                "unsupported protocol version: {}",
                envelope.version
            )),
            Err(err) => IrisResponse::error(format!("invalid daemon request: {err}")),
        },
        Err(err) => IrisResponse::error(err.to_string()),
    };

    let _ = serde_json::to_writer(&mut stream, &DaemonResponseEnvelope::new(response));
    let _ = stream.write_all(b"\n");
    let _ = stream.flush();
}

fn read_request(stream: &UnixStream) -> Result<DaemonRequestEnvelope> {
    read_json_bounded(stream, MAX_DAEMON_REQUEST_BYTES, "daemon request")
}

fn read_response(stream: &UnixStream) -> Result<DaemonResponseEnvelope> {
    read_json_bounded(stream, MAX_DAEMON_RESPONSE_BYTES, "daemon response")
}

fn validate_client_socket_path(socket_path: &Path) -> Result<()> {
    let expected_uid = current_effective_uid()?;
    if let Some(parent) = socket_path.parent() {
        validate_socket_parent(parent, expected_uid, "daemon socket parent")?;
    }
    validate_socket_file(socket_path, expected_uid, "daemon socket")
}

fn acquire_instance_lock(layout: &StateLayout, expected_uid: u32) -> Result<InstanceLockGuard> {
    let run_dir = layout.run_dir();
    prepare_secure_directory(&run_dir, expected_uid, "daemon run directory")?;
    let lock_path = layout.daemon_lock_path();
    let mut file = open_lock_file(&lock_path, expected_uid)?;
    lock_file_nonblocking(&file, &lock_path)?;
    write_lock_metadata(&mut file, expected_uid)?;
    sync_parent_dir(&lock_path)?;
    Ok(InstanceLockGuard { _file: file })
}

fn configure_stream(stream: &UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(DEFAULT_DAEMON_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(DEFAULT_DAEMON_IO_TIMEOUT))?;
    Ok(())
}

fn validate_peer_credentials(stream: &UnixStream, expected_uid: u32) -> Result<()> {
    let credentials = socket_peer_credentials(stream)?;
    if credentials.uid != expected_uid {
        return Err(IrisError::InvalidInput(format!(
            "refusing daemon request from uid {} (expected {})",
            credentials.uid, expected_uid
        )));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct PeerCredentials {
    uid: u32,
    #[allow(dead_code)]
    gid: u32,
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
fn socket_peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut uid = 0 as libc::uid_t;
    let mut gid = 0 as libc::gid_t;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };

    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(PeerCredentials {
        uid: uid as u32,
        gid: gid as u32,
    })
}

#[cfg(target_os = "linux")]
fn socket_peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
    let mut credentials_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut credentials_len,
        )
    };

    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }

    if credentials_len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(IrisError::InvalidInput(format!(
            "unexpected SO_PEERCRED payload size: {}",
            credentials_len
        )));
    }

    let credentials = unsafe { credentials.assume_init() };
    Ok(PeerCredentials {
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
)))]
fn socket_peer_credentials(_stream: &UnixStream) -> Result<PeerCredentials> {
    Err(IrisError::Unsupported(
        "peer credential validation is not implemented on this target".into(),
    ))
}

fn read_json_bounded<T>(stream: &UnixStream, max_bytes: usize, label: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut bytes = Vec::new();

    loop {
        let mut chunk = [0u8; 8192];
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        let remaining = max_bytes.saturating_add(1).saturating_sub(bytes.len());
        if remaining > 0 {
            bytes.extend_from_slice(&chunk[..read.min(remaining)]);
        }

        if bytes.len() > max_bytes {
            drain_reader(&mut reader)?;
            return Err(IrisError::InvalidInput(format!(
                "{label} exceeds {} bytes",
                max_bytes
            )));
        }
    }

    if bytes.is_empty() {
        return Err(IrisError::InvalidInput(format!("empty {label}")));
    }

    Ok(serde_json::from_slice(&bytes)?)
}

fn drain_reader<R: Read>(reader: &mut R) -> Result<()> {
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn open_lock_file(lock_path: &Path, expected_uid: u32) -> Result<File> {
    match fs::symlink_metadata(lock_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(IrisError::InvalidInput(format!(
                    "refusing to use symlinked daemon lock path: {}",
                    lock_path.display()
                )));
            }
            if !metadata.is_file() {
                return Err(IrisError::InvalidInput(format!(
                    "refusing to use non-file daemon lock path: {}",
                    lock_path.display()
                )));
            }
            if metadata.uid() != expected_uid {
                return Err(IrisError::InvalidInput(format!(
                    "refusing to use daemon lock owned by unexpected uid {}: {}",
                    metadata.uid(),
                    lock_path.display()
                )));
            }
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(IrisError::InvalidInput(format!(
                    "refusing to use daemon lock with writable group/other permissions: {}",
                    lock_path.display()
                )));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)
        .map_err(|err| match err.raw_os_error() {
            Some(libc::ELOOP) => IrisError::InvalidInput(format!(
                "refusing to use symlinked daemon lock path: {}",
                lock_path.display()
            )),
            _ => err.into(),
        })?;
    fs::set_permissions(lock_path, fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn open_append_only_artifact_file(
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<File> {
    validate_existing_artifact_path(path, expected_uid, description)?;

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| match err.raw_os_error() {
            Some(libc::ELOOP) => IrisError::InvalidInput(format!(
                "refusing to use symlinked {description}: {}",
                path.display()
            )),
            _ => err.into(),
        })?;

    validate_open_artifact_file(&file, path, expected_uid, description)?;
    Ok(file)
}

fn open_read_only_artifact_file(
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<Option<(File, fs::Metadata)>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            return Err(IrisError::InvalidInput(format!(
                "refusing to use symlinked {description}: {}",
                path.display()
            )));
        }
        Err(err) => return Err(err.into()),
    };

    if let Some(parent) = path.parent() {
        validate_socket_parent(
            parent,
            expected_uid,
            &format!("{description} parent directory"),
        )?;
    }
    let metadata = file.metadata()?;
    validate_artifact_metadata(&metadata, path, expected_uid, description, true)?;
    Ok(Some((file, metadata)))
}

fn enforce_verify_log_retention(path: &Path, expected_uid: u32) -> Result<()> {
    let Some((file, metadata)) =
        open_read_only_artifact_file(path, expected_uid, "daemon verify log artifact")?
    else {
        return Ok(());
    };

    if metadata.len() <= MAX_DAEMON_VERIFY_LOG_BYTES {
        return Ok(());
    }

    let (retained, truncated) =
        read_tail_bytes(file, metadata.len(), RETAINED_DAEMON_VERIFY_LOG_BYTES)?;
    let retained = retain_complete_jsonl_tail(
        retained,
        truncated,
        RETAINED_DAEMON_VERIFY_LOG_BYTES,
        "daemon verify log artifact",
        "retention",
    )?;
    write_atomic_artifact_file(path, &retained, expected_uid, "daemon verify log artifact")
}

fn validate_existing_artifact_path(
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_artifact_metadata(&metadata, path, expected_uid, description, true)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn validate_open_artifact_file(
    file: &File,
    path: &Path,
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    let metadata = file.metadata()?;
    validate_artifact_metadata(&metadata, path, expected_uid, description, false)
}

fn validate_artifact_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    expected_uid: u32,
    description: &str,
    require_private_permissions: bool,
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

    if require_private_permissions && metadata.permissions().mode() & 0o022 != 0 {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} with writable group/other permissions: {}",
            path.display()
        )));
    }

    Ok(())
}

fn write_atomic_artifact_file(
    path: &Path,
    bytes: &[u8],
    expected_uid: u32,
    description: &str,
) -> Result<()> {
    validate_existing_artifact_path(path, expected_uid, description)?;

    let (tmp_path, mut file) =
        create_unique_temporary_artifact_file(path, expected_uid, description)?;
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

fn create_unique_temporary_artifact_file(
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

    for _ in 0..MAX_ARTIFACT_TEMP_FILE_ATTEMPTS {
        let counter = ARTIFACT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
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
                validate_artifact_metadata(
                    &metadata,
                    &temp_path,
                    expected_uid,
                    &temp_description,
                    true,
                )?;
                return Ok((temp_path, file));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                validate_existing_artifact_path(&temp_path, expected_uid, &temp_description)?;
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

fn retain_complete_jsonl_tail(
    mut bytes: Vec<u8>,
    truncated: bool,
    max_bytes: usize,
    description: &str,
    purpose: &str,
) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        return Ok(bytes);
    }

    if truncated {
        let Some(offset) = bytes.iter().position(|byte| *byte == b'\n') else {
            return Err(IrisError::InvalidInput(format!(
                "{description} contains an entry exceeding safe {purpose} limit of {max_bytes} bytes"
            )));
        };
        bytes.drain(..=offset);
        if bytes.is_empty() {
            return Err(IrisError::InvalidInput(format!(
                "{description} contains an entry exceeding safe {purpose} limit of {max_bytes} bytes"
            )));
        }
    }

    Ok(bytes)
}

fn lock_file_nonblocking(file: &File, lock_path: &Path) -> Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if is_lock_contention_error(&err) {
        return Err(IrisError::InvalidInput(format!(
            "another irisd instance is already active: {}",
            lock_path.display()
        )));
    }

    Err(err.into())
}

#[cfg(target_os = "linux")]
fn is_lock_contention_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EWOULDBLOCK))
}

#[cfg(not(target_os = "linux"))]
fn is_lock_contention_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EWOULDBLOCK) | Some(libc::EAGAIN)
    )
}

fn write_lock_metadata(file: &mut File, expected_uid: u32) -> Result<()> {
    let content = format!("pid={}\nuid={}\n", std::process::id(), expected_uid);
    file.set_len(0)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

fn prepare_secure_directory(path: &Path, expected_uid: u32, description: &str) -> Result<()> {
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
    validate_socket_parent(path, expected_uid, description)
}

fn validate_socket_parent(parent: &Path, expected_uid: u32, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use symlinked {description}: {}",
            parent.display()
        )));
    }

    if !metadata.is_dir() {
        return Err(IrisError::InvalidInput(format!(
            "{description} is not a directory: {}",
            parent.display()
        )));
    }

    if metadata.uid() != expected_uid {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} owned by unexpected uid {}: {}",
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

fn validate_socket_file(socket_path: &Path, expected_uid: u32, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(socket_path)?;
    if !metadata.file_type().is_socket() {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use non-socket {description}: {}",
            socket_path.display()
        )));
    }

    if metadata.uid() != expected_uid {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} owned by unexpected uid {}: {}",
            metadata.uid(),
            socket_path.display()
        )));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(IrisError::InvalidInput(format!(
            "refusing to use {description} with writable group/other permissions: {}",
            socket_path.display()
        )));
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::retain_complete_jsonl_tail;

    #[test]
    fn retain_complete_jsonl_tail_keeps_recent_complete_entries() {
        let retained = retain_complete_jsonl_tail(
            b"partial\nsecond\nthird\n".to_vec(),
            true,
            32,
            "daemon verify log artifact",
            "retention",
        )
        .expect("retention should keep complete entries");

        assert_eq!(retained, b"second\nthird\n");
    }

    #[test]
    fn retain_complete_jsonl_tail_rejects_oversized_single_entry() {
        let err = retain_complete_jsonl_tail(
            b"oversized-entry-without-boundary".to_vec(),
            true,
            8,
            "daemon verify log artifact",
            "retention",
        )
        .expect_err("oversized single entry should fail closed");

        assert!(err.to_string().contains(
            "daemon verify log artifact contains an entry exceeding safe retention limit"
        ));
    }
}
