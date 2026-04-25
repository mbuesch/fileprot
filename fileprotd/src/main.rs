#![forbid(unsafe_code)]

use anyhow::{self as ah, format_err as err};
use clap::Parser;
use fileprot_common::{DEFAULT_CONFIG_PATH, config::Config};
use fuser::{Config as FuserConfig, MountOption, SessionACL, spawn_mount2};
use nix::mount::{MntFlags, umount2};
use std::{os::unix::fs::MetadataExt as _, path::Path, path::PathBuf, sync::Arc};
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

#[tokio::main]
async fn main() -> ah::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command-line arguments.
    let args = Args::parse();
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
        {
            let mp_meta = std::fs::metadata(mount_cfg.mountpoint()).map_err(|e| {
                err!(
                    "Failed to stat mount point '{}': {}",
                    mount_cfg.mountpoint().display(),
                    e
                )
            })?;
            let bd_meta = std::fs::metadata(mount_cfg.backing_dir()).map_err(|e| {
                err!(
                    "Failed to stat backing dir '{}': {}",
                    mount_cfg.backing_dir().display(),
                    e
                )
            })?;
            if mp_meta.dev() == bd_meta.dev() && mp_meta.ino() == bd_meta.ino() {
                return Err(err!(
                    "Mount point '{}' and backing directory '{}' are the same inode - refusing to mount",
                    mount_cfg.mountpoint().display(),
                    mount_cfg.backing_dir().display(),
                ));
            }
            // Use canonicalized paths to catch one being a subdirectory of the other.
            let canonical_mp = std::fs::canonicalize(mount_cfg.mountpoint()).map_err(|e| {
                err!(
                    "Failed to canonicalize mount point '{}': {}",
                    mount_cfg.mountpoint().display(),
                    e
                )
            })?;
            let canonical_bd = std::fs::canonicalize(mount_cfg.backing_dir()).map_err(|e| {
                err!(
                    "Failed to canonicalize backing dir '{}': {}",
                    mount_cfg.backing_dir().display(),
                    e
                )
            })?;
            if canonical_mp.starts_with(&canonical_bd) {
                return Err(err!(
                    "Mount point '{}' is inside backing directory '{}' - refusing to mount",
                    mount_cfg.mountpoint().display(),
                    mount_cfg.backing_dir().display(),
                ));
            }
            if canonical_bd.starts_with(&canonical_mp) {
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
