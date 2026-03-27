use dioxus::{
    LaunchBuilder,
    desktop::{Config as DesktopConfig, LogicalSize, WindowBuilder, WindowCloseBehaviour, tao},
};
use image::GenericImageView;
use std::{process, sync::atomic::Ordering};
use tray_icon::{
    TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};

mod dbus_client;
mod ui;

const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");

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

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // GTK must be initialized before creating tray icon on Linux.
    gtk::init().expect("Failed to initialize GTK");

    // Build tray menu.
    let menu = Menu::new();
    let show_item = MenuItem::new("Show", true, None);
    let quit_item = MenuItem::new("Quit", true, None);
    let show_item_id = show_item.id().clone();
    let quit_item_id = quit_item.id().clone();
    menu.append(&show_item).unwrap();
    menu.append(&quit_item).unwrap();

    // Create tray icon with a simple colored icon.
    let icon = ui::create_icon();
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("fileprot - File Protection")
        .with_icon(icon)
        .build()
        .expect("failed to create tray icon");

    // Handle tray menu events via set_event_handler so they run directly in the
    // GTK activate-signal callback context, bypassing the crossbeam channel.
    // This is the recommended pattern for tao/winit users per tray-icon docs.
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if event.id() == &show_item_id {
            ui::SHOW_REQUESTED.store(true, Ordering::Relaxed);
        } else if event.id() == &quit_item_id {
            process::exit(0);
        }
    }));

    // Launch Dioxus desktop app.
    LaunchBuilder::desktop()
        .with_cfg(
            DesktopConfig::new()
                .with_window(
                    WindowBuilder::new()
                        .with_title("fileprot - Access Requests")
                        .with_inner_size(LogicalSize::new(700.0, 500.0))
                        .with_window_icon(load_window_icon()),
                )
                .with_close_behaviour(WindowCloseBehaviour::WindowHides),
        )
        .launch(ui::app);
}
