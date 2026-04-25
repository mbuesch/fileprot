use image::GenericImageView;
use ksni::{MenuItem, Tray, TrayMethods};
use std::{
    process,
    sync::atomic::{AtomicBool, Ordering},
};

const ICON_PNG: &[u8] = include_bytes!("../../../assets/icon.png");

/// Shared state: set by the tray activate handler, polled by the Dioxus coroutine.
pub static SHOW_REQUESTED: AtomicBool = AtomicBool::new(false);

fn load_icon_pixmap() -> Vec<ksni::Icon> {
    let img = image::load_from_memory(ICON_PNG).expect("failed to load icon PNG");
    let (width, height) = img.dimensions();
    let rgba = img.into_rgba8().into_raw();
    // Convert from RGBA8 to ARGB32 big-endian (StatusNotifierItem spec).
    let argb: Vec<u8> = rgba
        .chunks(4)
        .flat_map(|p| [p[3], p[0], p[1], p[2]])
        .collect();
    vec![ksni::Icon {
        width: width as i32,
        height: height as i32,
        data: argb,
    }]
}

struct FileprotTray;

impl Tray for FileprotTray {
    fn id(&self) -> String {
        env!("CARGO_PKG_NAME").into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        load_icon_pixmap()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "fileprot - File Protection".into(),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        SHOW_REQUESTED.store(true, Ordering::Relaxed);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        use ksni::menu::*;
        vec![
            StandardItem {
                label: "Show".into(),
                activate: Box::new(|_| {
                    SHOW_REQUESTED.store(true, Ordering::Relaxed);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| process::exit(0)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// Spawn the tray icon in a background thread with its own tokio runtime.
pub fn spawn_tray() {
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tray tokio runtime")
            .block_on(async {
                FileprotTray.spawn().await.expect("failed to spawn tray");
                std::future::pending::<()>().await
            });
    });
}
