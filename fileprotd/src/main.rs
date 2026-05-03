#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("fileprotd only supports Linux");

use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use fileprot_common::{DEFAULT_CONFIG_PATH, config::Config};
use fuser::{Config as FuserConfig, MountOption, SessionACL, spawn_mount2};
use nix::{
    fcntl::{AtFlags, OFlag, open, openat},
    mount::{MntFlags, umount2},
    sys::{
        prctl,
        stat::{FileStat, Mode, fstatat},
    },
};
use std::{
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    signal::{
        ctrl_c,
        unix::{SignalKind, signal as unix_signal},
    },
    sync::mpsc,
};

mod access_control;
mod dbus_service;
mod filesystem;

/// Open `path` with `O_PATH | O_CLOEXEC`.
fn open_o_path(path: &Path) -> ah::Result<OwnedFd> {
    open(path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
        .map_err(|e| err!("Failed to open '{}' with O_PATH: {}", path.display(), e))
}

/// Return `(st_dev, st_ino)` for the directory referenced by `fd`.
fn fd_id(fd: impl AsFd) -> ah::Result<(u64, u64)> {
    let st: FileStat =
        fstatat(fd, ".", AtFlags::empty()).map_err(|e| err!("fstatat failed: {}", e))?;
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Return `true` if the directory referred to by `child_fd` is the same as,
/// or is a descendant of, the directory identified by `ancestor_id`.
fn is_fd_inside(child_fd: OwnedFd, ancestor_id: (u64, u64)) -> ah::Result<bool> {
    let mut current = child_fd;
    loop {
        let cur_id = fd_id(current.as_fd())?;
        if cur_id == ancestor_id {
            return Ok(true);
        }
        let parent = openat(
            current.as_fd(),
            "..",
            OFlag::O_PATH | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| err!("openat(\"..\") failed: {}", e))?;
        let par_id = fd_id(parent.as_fd())?;
        if par_id == cur_id {
            // Reached VFS root: ".." resolves to the same inode as ".".
            return Ok(false);
        }
        current = parent;
    }
}

/// Detach a FUSE mountpoint from the kernel's VFS using a lazy unmount.
/// On success the mountpoint is immediately invisible to new callers;
/// the FUSE session thread will clean up its file descriptor on its own.
fn try_detach_mount(mountpoint: &Path) -> ah::Result<()> {
    umount2(mountpoint, MntFlags::MNT_DETACH)
        .map_err(|e| err!("Failed to unmount '{}': {}", mountpoint.display(), e))
}

/// Command-line arguments for fileprotd.
#[derive(Debug, Parser)]
#[command(author, version, about = "fileprotd - fileprot daemon")]
struct Args {
    /// Path to configuration file
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Disable GUI peer verification via exe inode check (for testing only)
    #[arg(long = "no-verify-peer-exe")]
    no_verify_peer_exe: bool,

    /// Disable GUI peer verification via UID check (for testing only)
    #[arg(long = "no-verify-peer-uid")]
    no_verify_peer_uid: bool,
}

async fn async_main(args: Args) -> ah::Result<()> {
    // Determine config path from command-line argument or default.
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

    log::info!("Loading configuration from {}", config_path.display());
    let config = Config::load(&config_path)?;
    log::info!(
        "Configuration loaded: {} mount(s), gui_binary={}",
        config.mounts().len(),
        config.gui_binary_path().display()
    );

    // Verify that the backing base directory is owned by root and not
    // accessible to group or other. This is done once at startup so that
    // misconfigured host permissions are caught before any FUSE mount is
    // attempted.
    {
        let base = config.backing_base_dir();
        let meta = std::fs::metadata(base).map_err(|e| {
            err!(
                "Failed to stat backing base directory '{}': {}",
                base.display(),
                e
            )
        })?;
        use std::os::unix::fs::MetadataExt as _;
        if meta.uid() != 0 {
            return Err(err!(
                "Backing base directory '{}' must be owned by root (uid 0), but uid is {}",
                base.display(),
                meta.uid()
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(err!(
                "Backing base directory '{}' has unsafe permissions (mode {:04o}); \
                 expected 0700 or stricter (no group/other bits)",
                base.display(),
                meta.mode() & 0o777
            ));
        }
    }

    // Create the request channel (FUSE threads -> D-Bus service).
    let (request_tx, request_rx) = mpsc::channel(256);

    // Start the D-Bus service.
    let peer_verification = dbus_service::PeerVerification {
        verify_exe: !args.no_verify_peer_exe,
        verify_uid: !args.no_verify_peer_uid,
    };
    let _connection = dbus_service::start_dbus_service(
        request_rx,
        config.gui_binary_path().to_path_buf(),
        peer_verification,
    )
    .await?;
    log::info!("D-Bus service started on system bus");

    // Create the shared access controller.
    let coupling = if config.couple_approval_to_process() {
        access_control::ApprovalCoupling::CoupledToProcess
    } else {
        access_control::ApprovalCoupling::Uncoupled
    };
    let renewal = if config.renew_approval_on_access() {
        access_control::ApprovalRenewal::RenewOnAccess
    } else {
        access_control::ApprovalRenewal::NoRenewal
    };
    let access_controller = Arc::new(access_control::AccessController::new(
        request_tx,
        config.request_timeout(),
        config.approval_ttl(),
        coupling,
        renewal,
    ));

    // Mount FUSE filesystems.
    let mut sessions = Vec::with_capacity(config.mounts().len());
    for mount_cfg in config.mounts() {
        if mount_cfg.disabled() {
            log::info!("Mount '{}' is disabled, skipping", mount_cfg.name());
            continue;
        }

        // Validate that the backing directory exists and is accessible.
        if !mount_cfg.backing_dir().exists() {
            return Err(err!(
                "Backing directory does not exist: {}",
                mount_cfg.backing_dir().display()
            ));
        }
        if !mount_cfg.backing_dir().is_dir() {
            return Err(err!(
                "Backing path is not a directory: {}",
                mount_cfg.backing_dir().display()
            ));
        }

        // Validate that the mount point exists.
        match mount_cfg.mountpoint().try_exists() {
            Ok(true) => {}
            Ok(false) => {
                return Err(err!(
                    "Mount point does not exist: {}",
                    mount_cfg.mountpoint().display()
                ));
            }
            Err(e) => {
                // ENOTCONN means there is a stale FUSE mount left over from a
                // previous daemon run (e.g. after a crash or SIGKILL). The
                // kernel still has the mountpoint in the VFS table but the
                // FUSE endpoint is gone, so every stat() returns ENOTCONN.
                // Try to detach it so we can mount cleanly.
                if e.raw_os_error() == Some(nix::errno::Errno::ENOTCONN as i32) {
                    log::warn!(
                        "Stale FUSE mount detected at '{}' (ENOTCONN), attempting cleanup.",
                        mount_cfg.mountpoint().display()
                    );
                    try_detach_mount(mount_cfg.mountpoint())?;
                } else {
                    return Err(err!(
                        "Mount point is not accessible: {} ({})",
                        mount_cfg.mountpoint().display(),
                        e
                    ));
                }
            }
        }
        if !mount_cfg.mountpoint().is_dir() {
            return Err(err!(
                "Mount point is not a directory: {}",
                mount_cfg.mountpoint().display()
            ));
        }

        // Guard against misconfiguration where the mountpoint overlaps with the
        // backing directory - this would recursively obscure files or cause
        // undefined FUSE behaviour.
        //
        // Open both paths with O_PATH so that subsequent fstat and openat(..)
        // calls operate on the actual inodes rather than on string paths.
        // This eliminates the TOCTOU window that exists between
        // canonicalize() and spawn_mount2().
        {
            let mp_id = fd_id(open_o_path(mount_cfg.mountpoint())?)?;
            let bd_id = fd_id(open_o_path(&mount_cfg.backing_dir())?)?;

            if mp_id == bd_id {
                return Err(err!(
                    "Mount point '{}' and backing directory '{}' are the same inode - refusing to mount",
                    mount_cfg.mountpoint().display(),
                    mount_cfg.backing_dir().display(),
                ));
            }
            if is_fd_inside(open_o_path(mount_cfg.mountpoint())?, bd_id)? {
                return Err(err!(
                    "Mount point '{}' is inside backing directory '{}' - refusing to mount",
                    mount_cfg.mountpoint().display(),
                    mount_cfg.backing_dir().display(),
                ));
            }
            if is_fd_inside(open_o_path(&mount_cfg.backing_dir())?, mp_id)? {
                return Err(err!(
                    "Backing directory '{}' is inside mount point '{}' - refusing to mount",
                    mount_cfg.backing_dir().display(),
                    mount_cfg.mountpoint().display(),
                ));
            }
        }

        log::info!(
            "Mounting '{}': {} -> {}",
            mount_cfg.name(),
            mount_cfg.mountpoint().display(),
            mount_cfg.backing_dir().display()
        );

        let fs = filesystem::ProtectedFilesystem::new(
            mount_cfg.name().to_string(),
            mount_cfg.backing_dir().to_path_buf(),
            mount_cfg.uid(),
            mount_cfg.gid(),
            Arc::clone(&access_controller),
        )
        .map_err(|e| {
            err!(
                "Failed to open backing dir for '{}': {}",
                mount_cfg.name(),
                e
            )
        })?;

        let mut fuser_config = FuserConfig::default();
        fuser_config.mount_options = vec![
            MountOption::FSName(format!("fileprot:{}", mount_cfg.name())),
            MountOption::AutoUnmount,
            // Let the kernel enforce permission checks based on the uid/gid/perm
            // attributes we return from getattr/lookup. This avoids having to
            // re-implement permission checking in the access() callback.
            MountOption::DefaultPermissions,
        ];
        fuser_config.acl = SessionACL::All;

        match spawn_mount2(fs, mount_cfg.mountpoint(), &fuser_config) {
            Ok(session) => {
                sessions.push((
                    mount_cfg.name().to_string(),
                    mount_cfg.mountpoint().to_path_buf(),
                    session,
                ));
                log::info!("Mount '{}' active and registered", mount_cfg.name());
            }
            Err(e) => {
                log::error!("Failed to mount '{}': {}", mount_cfg.name(), e);
                return Err(err!("Failed to mount '{}': {}", mount_cfg.name(), e));
            }
        }
    }

    log::info!("fileprotd running with {} active mount(s)", sessions.len());

    // Wait for shutdown signal (SIGTERM from systemd or Ctrl+C).
    let mut sigterm = unix_signal(SignalKind::terminate())?;
    tokio::select! {
        _ = ctrl_c() => {
            log::info!("Received SIGINT, shutting down...");
        }
        _ = sigterm.recv() => {
            log::info!("Received SIGTERM, shutting down...");
        }
    }

    // Unmount FUSE filesystems.
    for (name, mountpoint, session) in sessions {
        log::info!("Unmounting '{}'...", name);
        match try_detach_mount(&mountpoint) {
            Ok(()) => log::info!("Unmounted '{}'", name),
            Err(e) => log::warn!("Failed to unmount '{}': {}", name, e),
        }
        // Drop the session handle to join the FUSE background thread.
        drop(session);
    }

    Ok(())
}

fn main() -> ah::Result<()> {
    // Prevent ptrace and core dumps.
    prctl::set_dumpable(false).context("Failed to set PR_SET_DUMPABLE")?;
    // Disable performance counters.
    prctl::task_perf_events_disable().context("Failed to set PR_TASK_PERF_EVENTS_DISABLE")?;
    // Disable privilege escalation via execve.
    prctl::set_no_new_privs().context("Failed to set PR_SET_NO_NEW_PRIVS")?;

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command-line arguments.
    let args = Args::parse();

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?
        .block_on(async_main(args))
        .context("Tokio runtime init error")
}
