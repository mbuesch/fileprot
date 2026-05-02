#![forbid(unsafe_code)]

use anyhow::{self as ah, Context as _};
use clap::Parser;
use dioxus::desktop::{
    Config as DesktopConfig, LogicalSize, WindowBuilder, WindowCloseBehaviour, tao,
};
use image::GenericImageView;
use nix::sys::prctl;

mod dbus_client;
mod ui;

const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");

/// Command-line arguments for fileprot.
#[derive(Debug, Parser)]
#[command(author, version, about = "fileprot - File Protection Tray")]
struct Args {
    /// Start with the window visible instead of hidden
    #[arg(long)]
    visible: bool,
}

fn load_window_icon() -> Option<tao::window::Icon> {
    let img = image::load_from_memory(ICON_PNG)
        .map_err(|e| log::warn!("Failed to load window icon: {}", e))
        .ok()?;
    let (width, height) = img.dimensions();
    let rgba = img.into_rgba8().into_raw();
    tao::window::Icon::from_rgba(rgba, width, height)
        .map_err(|e| log::warn!("Failed to create window icon: {}", e))
        .ok()
}

async fn async_main(args: Args) -> ah::Result<()> {
    // Spawn the tray icon via the StatusNotifierItem D-Bus protocol.
    ui::spawn_tray();

    #[cfg(target_os = "android")]
    let builder = dioxus::LaunchBuilder::mobile();
    #[cfg(not(target_os = "android"))]
    let builder = dioxus::LaunchBuilder::desktop();

    let config = DesktopConfig::new()
        .with_window(
            WindowBuilder::new()
                .with_title("fileprot - Access Requests")
                .with_always_on_top(false)
                .with_inner_size(LogicalSize::new(700.0, 500.0))
                .with_window_icon(load_window_icon())
                .with_visible(args.visible),
        )
        .with_close_behaviour(WindowCloseBehaviour::WindowHides)
        .with_menu(None);

    tokio::task::unconstrained(async move {
        builder.with_cfg(config).launch(ui::App);
    })
    .await;

    Ok(())
}

fn main() -> ah::Result<()> {
    // Prevent ptrace and core dumps.
    prctl::set_dumpable(false).context("Failed to set PR_SET_DUMPABLE")?;

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
