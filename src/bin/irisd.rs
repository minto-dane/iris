use std::ffi::CString;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::ptr;
use std::time::Duration;

use clap::{ArgAction, Parser};
use iris::{IrisError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessIdentity {
    euid: u32,
    egid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedUser {
    uid: u32,
    primary_gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivilegeDropTarget {
    uid: u32,
    gid: u32,
}

const NSS_LOOKUP_BUFFER_FALLBACK: usize = 16 * 1024;

#[derive(Debug, Clone, Parser)]
#[command(name = "irisd", version, about = "Iris daemon")]
struct DaemonCli {
    #[arg(long, default_value = "/var/iris")]
    root: PathBuf,
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    group: Option<String>,
    #[arg(long = "no-verify-on-start", action = ArgAction::SetFalse, default_value_t = true)]
    verify_on_start: bool,
    #[arg(long, default_value_t = 300)]
    verify_interval_secs: u64,
}

fn main() {
    let cli = DaemonCli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: DaemonCli) -> Result<()> {
    maybe_drop_privileges(&cli)?;
    let config = iris::daemon::DaemonConfig {
        verify_on_start: cli.verify_on_start,
        verify_interval: (cli.verify_interval_secs > 0)
            .then(|| Duration::from_secs(cli.verify_interval_secs)),
        max_requests: None,
        max_background_verifications: None,
    };
    iris::daemon::serve_with_config(cli.root, cli.socket, config)
}

fn maybe_drop_privileges(cli: &DaemonCli) -> Result<()> {
    let current = current_process_identity();
    let target =
        resolve_privilege_drop_target(&current, cli.user.as_deref(), cli.group.as_deref())?;
    if let Some(target) = target {
        apply_privilege_drop(target)?;
    }

    Ok(())
}

fn resolve_privilege_drop_target(
    current: &ProcessIdentity,
    user: Option<&str>,
    group: Option<&str>,
) -> Result<Option<PrivilegeDropTarget>> {
    if user.is_none() && group.is_some() {
        return Err(IrisError::InvalidInput(
            "--group requires --user for irisd privilege drop".into(),
        ));
    }

    if current.euid != 0 {
        if user.is_some() || group.is_some() {
            return Err(IrisError::InvalidInput(
                "irisd privilege drop options require root execution".into(),
            ));
        }
        return Ok(None);
    }

    let user = user.ok_or_else(|| {
        IrisError::InvalidInput("refusing to run irisd as root without --user".into())
    })?;
    let resolved_user = resolve_user_spec(user)?;
    let gid = match group {
        Some(group) => resolve_group_spec(group)?,
        None => resolved_user.primary_gid,
    };

    if resolved_user.uid == 0 {
        return Err(IrisError::InvalidInput(
            "refusing to keep irisd running as uid 0 after privilege drop".into(),
        ));
    }
    if gid == 0 {
        return Err(IrisError::InvalidInput(
            "refusing to keep irisd running as gid 0 after privilege drop".into(),
        ));
    }

    Ok(Some(PrivilegeDropTarget {
        uid: resolved_user.uid,
        gid,
    }))
}

fn apply_privilege_drop(target: PrivilegeDropTarget) -> Result<()> {
    clear_supplementary_groups()?;
    set_group_id(target.gid)?;
    set_user_id(target.uid)?;

    let current = current_process_identity();
    if current.egid != target.gid {
        return Err(IrisError::InvalidInput(format!(
            "irisd privilege drop left unexpected gid {} (expected {})",
            current.egid, target.gid
        )));
    }
    if current.euid != target.uid {
        return Err(IrisError::InvalidInput(format!(
            "irisd privilege drop left unexpected uid {} (expected {})",
            current.euid, target.uid
        )));
    }
    if current.euid == 0 || current.egid == 0 {
        return Err(IrisError::InvalidInput(
            "irisd privilege drop must not retain uid/gid 0".into(),
        ));
    }

    Ok(())
}

fn clear_supplementary_groups() -> Result<()> {
    let result = unsafe { libc::setgroups(0, ptr::null()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_group_id(gid: u32) -> Result<()> {
    let result = unsafe { libc::setgid(gid as libc::gid_t) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_user_id(uid: u32) -> Result<()> {
    let result = unsafe { libc::setuid(uid as libc::uid_t) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn current_process_identity() -> ProcessIdentity {
    ProcessIdentity {
        euid: unsafe { libc::geteuid() as u32 },
        egid: unsafe { libc::getegid() as u32 },
    }
}

fn resolve_user_spec(spec: &str) -> Result<ResolvedUser> {
    if let Ok(uid) = spec.parse::<u32>() {
        return lookup_user_by_uid(uid);
    }

    let spec = CString::new(spec)
        .map_err(|_| IrisError::InvalidInput("daemon user contains interior NUL byte".into()))?;
    lookup_user_by_name(&spec)
}

fn lookup_user_by_uid(uid: u32) -> Result<ResolvedUser> {
    let mut buffer_len = passwd_lookup_buffer_len();
    loop {
        let mut passwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result = ptr::null_mut();
        let mut buffer = vec![0u8; buffer_len];
        let status = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_len = buffer_len.saturating_mul(2);
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status).into());
        }
        if result.is_null() {
            return Err(IrisError::InvalidInput(format!(
                "unknown daemon uid: {}",
                uid
            )));
        }

        let passwd = unsafe { passwd.assume_init() };
        return Ok(ResolvedUser {
            uid: passwd.pw_uid,
            primary_gid: passwd.pw_gid,
        });
    }
}

fn resolve_group_spec(spec: &str) -> Result<u32> {
    if let Ok(gid) = spec.parse::<u32>() {
        return lookup_group_by_gid(gid);
    }

    let spec = CString::new(spec)
        .map_err(|_| IrisError::InvalidInput("daemon group contains interior NUL byte".into()))?;
    lookup_group_by_name(&spec)
}

fn lookup_group_by_gid(gid: u32) -> Result<u32> {
    let mut buffer_len = group_lookup_buffer_len();
    loop {
        let mut group = MaybeUninit::<libc::group>::uninit();
        let mut result = ptr::null_mut();
        let mut buffer = vec![0u8; buffer_len];
        let status = unsafe {
            libc::getgrgid_r(
                gid as libc::gid_t,
                group.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_len = buffer_len.saturating_mul(2);
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status).into());
        }
        if result.is_null() {
            return Err(IrisError::InvalidInput(format!(
                "unknown daemon gid: {}",
                gid
            )));
        }

        let group = unsafe { group.assume_init() };
        return Ok(group.gr_gid);
    }
}

fn lookup_user_by_name(spec: &CString) -> Result<ResolvedUser> {
    let mut buffer_len = passwd_lookup_buffer_len();
    loop {
        let mut passwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result = ptr::null_mut();
        let mut buffer = vec![0u8; buffer_len];
        let status = unsafe {
            libc::getpwnam_r(
                spec.as_ptr(),
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_len = buffer_len.saturating_mul(2);
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status).into());
        }
        if result.is_null() {
            return Err(IrisError::InvalidInput(format!(
                "unknown daemon user: {}",
                spec.to_string_lossy()
            )));
        }

        let passwd = unsafe { passwd.assume_init() };
        return Ok(ResolvedUser {
            uid: passwd.pw_uid,
            primary_gid: passwd.pw_gid,
        });
    }
}

fn lookup_group_by_name(spec: &CString) -> Result<u32> {
    let mut buffer_len = group_lookup_buffer_len();
    loop {
        let mut group = MaybeUninit::<libc::group>::uninit();
        let mut result = ptr::null_mut();
        let mut buffer = vec![0u8; buffer_len];
        let status = unsafe {
            libc::getgrnam_r(
                spec.as_ptr(),
                group.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_len = buffer_len.saturating_mul(2);
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status).into());
        }
        if result.is_null() {
            return Err(IrisError::InvalidInput(format!(
                "unknown daemon group: {}",
                spec.to_string_lossy()
            )));
        }

        let group = unsafe { group.assume_init() };
        return Ok(group.gr_gid);
    }
}

fn passwd_lookup_buffer_len() -> usize {
    lookup_buffer_len(libc::_SC_GETPW_R_SIZE_MAX)
}

fn group_lookup_buffer_len() -> usize {
    lookup_buffer_len(libc::_SC_GETGR_R_SIZE_MAX)
}

fn lookup_buffer_len(sysconf_name: libc::c_int) -> usize {
    let size = unsafe { libc::sysconf(sysconf_name) };
    if size <= 0 {
        NSS_LOOKUP_BUFFER_FALLBACK
    } else {
        size as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parses_privilege_drop_flags() {
        let cli = DaemonCli::try_parse_from([
            "irisd",
            "--user",
            "1000",
            "--group",
            "1000",
            "--verify-interval-secs",
            "0",
        ])
        .expect("daemon cli should parse");

        assert_eq!(cli.user.as_deref(), Some("1000"));
        assert_eq!(cli.group.as_deref(), Some("1000"));
        assert_eq!(cli.verify_interval_secs, 0);
    }

    #[test]
    fn privilege_drop_rejects_group_without_user() {
        let err = resolve_privilege_drop_target(
            &ProcessIdentity { euid: 0, egid: 0 },
            None,
            Some("1000"),
        )
        .expect_err("group without user should fail closed");

        assert!(matches!(
            err,
            IrisError::InvalidInput(message) if message.contains("--group requires --user")
        ));
    }

    #[test]
    fn privilege_drop_rejects_non_root_override_request() {
        let err = resolve_privilege_drop_target(
            &ProcessIdentity {
                euid: 1000,
                egid: 1000,
            },
            Some("1001"),
            None,
        )
        .expect_err("non-root override request should fail closed");

        assert!(matches!(
            err,
            IrisError::InvalidInput(message) if message.contains("require root execution")
        ));
    }

    #[test]
    fn privilege_drop_rejects_root_without_user() {
        let err = resolve_privilege_drop_target(&ProcessIdentity { euid: 0, egid: 0 }, None, None)
            .expect_err("root without user should fail closed");

        assert!(matches!(
            err,
            IrisError::InvalidInput(message)
                if message.contains("refusing to run irisd as root without --user")
        ));
    }

    #[test]
    fn privilege_drop_rejects_uid_zero_target() {
        let err =
            resolve_privilege_drop_target(&ProcessIdentity { euid: 0, egid: 0 }, Some("0"), None)
                .expect_err("uid 0 target should fail closed");

        assert!(matches!(
            err,
            IrisError::InvalidInput(message) if message.contains("uid 0")
        ));
    }

    #[test]
    fn privilege_drop_rejects_gid_zero_target() {
        let current = current_process_identity();
        if current.euid == 0 {
            return;
        }

        let err = resolve_privilege_drop_target(
            &ProcessIdentity { euid: 0, egid: 0 },
            Some(&current.euid.to_string()),
            Some("0"),
        )
        .expect_err("gid 0 target should fail closed");

        assert!(matches!(
            err,
            IrisError::InvalidInput(message) if message.contains("gid 0")
        ));
    }

    #[test]
    fn privilege_drop_resolves_numeric_user_and_group() {
        let current = current_process_identity();
        if current.euid == 0 || current.egid == 0 {
            return;
        }

        let target = resolve_privilege_drop_target(
            &ProcessIdentity { euid: 0, egid: 0 },
            Some(&current.euid.to_string()),
            Some(&current.egid.to_string()),
        )
        .expect("numeric drop target should resolve")
        .expect("root execution should require a target");

        assert_eq!(target.uid, current.euid);
        assert_eq!(target.gid, current.egid);
    }
}
