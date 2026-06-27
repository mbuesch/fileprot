#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("fileprotd only supports Linux");

use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use fileprot_common::fileops::{fd_id, is_fd_inside, open_dir_components, open_o_path};
use fileprot_common::{DEFAULT_CONFIG_PATH, config::Config};
use fuser::{Config as FuserConfig, MountOption, SessionACL, spawn_mount2};
use nix::{
    errno::Errno::ENOTCONN,
    mount::{MntFlags, umount2},
    sys::prctl,
};
use std::{
    fs,
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

    // Per-mount access controllers are created inside the mount loop below.

    // Mount FUSE filesystems.
    let mut sessions = Vec::with_capacity(config.mounts().len());
    for mount_cfg in config.mounts() {
        if mount_cfg.disabled() {
            log::info!("Mount '{}' is disabled, skipping", mount_cfg.name());
            continue;
        }

        // Ensure the backing directory exists and is accessible.
        let backing_dir = mount_cfg.backing_dir();
        match backing_dir.try_exists() {
            Ok(true) => {
                if !backing_dir.is_dir() {
                    return Err(err!(
                        "Backing path is not a directory: {}",
                        backing_dir.display()
                    ));
                }
            }
            Ok(false) => {
                log::info!("Creating backing directory {}", backing_dir.display());
                fs::create_dir_all(&backing_dir).with_context(|| {
                    format!(
                        "Failed to create backing directory {}",
                        backing_dir.display()
                    )
                })?;
            }
            Err(e) => {
                return Err(err!(
                    "Backing directory is not accessible: {} ({})",
                    backing_dir.display(),
                    e
                ));
            }
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
                if e.raw_os_error() == Some(ENOTCONN as i32) {
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

        let coupling = if mount_cfg.couple_approval_to_process(&config) {
            access_control::ApprovalCoupling::CoupledToProcess
        } else {
            access_control::ApprovalCoupling::Uncoupled
        };
        let renewal = if mount_cfg.renew_approval_on_access(&config) {
            access_control::ApprovalRenewal::RenewOnAccess
        } else {
            access_control::ApprovalRenewal::NoRenewal
        };
        let access_controller = Arc::new(access_control::AccessController::new(
            request_tx.clone(),
            config.request_timeout(),
            mount_cfg.approval_ttl(&config),
            coupling,
            renewal,
        ));
        let backing_fd = open_dir_components(&mount_cfg.backing_dir()).map_err(|e| {
            err!(
                "Failed to open backing directory '{}' for mount '{}': {}",
                mount_cfg.backing_dir().display(),
                mount_cfg.name(),
                e
            )
        })?;

        let fs = filesystem::ProtectedFilesystem::new(
            mount_cfg.name().to_string(),
            mount_cfg.backing_dir().to_path_buf(),
            backing_fd,
            mount_cfg.uid(),
            mount_cfg.gid(),
            Arc::clone(&access_controller),
        )
        .map_err(|e| {
            err!(
                "Failed to initialise filesystem for '{}': {}",
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
            // Disallow setuid binaries and device nodes on the FUSE mount.
            MountOption::NoSuid,
            // Disallow device nodes on the FUSE mount.
            MountOption::NoDev,
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
