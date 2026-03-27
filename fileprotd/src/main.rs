use anyhow as ah;
use clap::Parser;
use fileprot_common::{DEFAULT_CONFIG_PATH, config::Config};
use fuser::{Config as FuserConfig, MountOption, SessionACL, spawn_mount2};
use std::{path::PathBuf, sync::Arc, time::Duration};
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
        config.mounts.len(),
        config.gui_binary_path.display()
    );

    // Create the request channel (FUSE threads -> D-Bus service).
    let (request_tx, request_rx) = mpsc::channel(256);

    // Start the D-Bus service.
    let _connection =
        dbus_service::start_dbus_service(request_rx, config.gui_binary_path.clone()).await?;
    log::info!("D-Bus service started on system bus");

    // Create the shared access controller.
    let access_controller = Arc::new(access_control::AccessController::new(
        request_tx,
        Duration::from_secs(config.request_timeout_secs),
    ));

    // Mount FUSE filesystems.
    let mut sessions = Vec::with_capacity(config.mounts.len());
    for mount_cfg in &config.mounts {
        if mount_cfg.disabled() {
            log::info!("Mount '{}' is disabled, skipping", mount_cfg.name);
            continue;
        }
        let backing_dir = mount_cfg
            .backing_dir
            .as_ref()
            .expect("backing_dir not resolved");
        log::info!(
            "Mounting '{}': {} -> {}",
            mount_cfg.name,
            mount_cfg.mountpoint.display(),
            backing_dir.display()
        );

        let fs = filesystem::ProtectedFilesystem::new(
            mount_cfg.name.clone(),
            backing_dir.clone(),
            access_controller.clone(),
        );

        let mut config = FuserConfig::default();
        config.mount_options = vec![
            MountOption::FSName(format!("fileprot:{}", mount_cfg.name)),
            MountOption::AutoUnmount,
        ];
        config.acl = SessionACL::All;

        let session = spawn_mount2(fs, &mount_cfg.mountpoint, &config)?;
        sessions.push((mount_cfg.name.clone(), session));
        log::info!("Mount '{}' active", mount_cfg.name);
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
