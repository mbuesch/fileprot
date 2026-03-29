use image::GenericImageView;
use std::sync::atomic::AtomicBool;
use tray_icon::Icon;

const ICON_PNG: &[u8] = include_bytes!("../../../assets/icon.png");

/// Shared state: set by the tray "Show" handler, polled by the Dioxus coroutine.
pub static SHOW_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Load the tray icon from the embedded PNG asset.
pub fn create_icon() -> Icon {
    let img = image::load_from_memory(ICON_PNG).expect("failed to load icon PNG");
    let (width, height) = img.dimensions();
    let rgba = img.into_rgba8().into_raw();
    Icon::from_rgba(rgba, width, height).expect("failed to create tray icon")
}
