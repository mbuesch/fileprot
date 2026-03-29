use crate::dbus_service::PeerVerification;
use anyhow::{self as ah, format_err as err};
use clap::Parser;
use fileprot_common::{DEFAULT_CONFIG_PATH, config::Config};
use fuser::{Config as FuserConfig, MountOption, SessionACL, spawn_mount2};
use std::{path::PathBuf, sync::Arc};
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

/// Command-line arguments for fileprotd.
#[derive(Debug, Parser)]
#[command(author, version, about = "fileprotd - fileprot daemon")]
struct Args {
    /// Path to configuration file
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Disable GUI peer verification (for testing only)
    #[arg(long = "no-verify-peer")]
    no_verify_peer: bool,
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
    let peer_verification = if args.no_verify_peer {
        PeerVerification::Disabled
    } else {
        PeerVerification::Enabled
    };
    let _connection = dbus_service::start_dbus_service(
        request_rx,
        config.gui_binary_path().to_path_buf(),
        peer_verification,
    )
    .await?;
    log::info!("D-Bus service started on system bus");

    // Create the shared access controller.
    let access_controller = Arc::new(access_control::AccessController::new(
        request_tx,
        config.request_timeout(),
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
        if !mount_cfg.mountpoint().exists() {
            return Err(err!(
                "Mount point does not exist: {}",
                mount_cfg.mountpoint().display()
            ));
        }
        if !mount_cfg.mountpoint().is_dir() {
            return Err(err!(
                "Mount point is not a directory: {}",
                mount_cfg.mountpoint().display()
            ));
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
            access_controller.clone(),
        );

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
                sessions.push((mount_cfg.name().to_string(), session));
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

    // Drop sessions to unmount FUSE filesystems.
    for (name, session) in sessions {
        log::info!("Unmounting '{}'", name);
        drop(session);
    }

    Ok(())
}
