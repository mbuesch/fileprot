use crate::{
    dbus_client::connect,
    ui::{components::RequestListEntry, tray::SHOW_REQUESTED},
};
use base64::Engine;
use dioxus::desktop::{tao, window};
use dioxus::prelude::*;
use fileprot_common::dbus_interface::AccessControlRequest;
use std::sync::Arc;
use std::{pin::pin, sync::LazyLock, time::Duration};
use tokio_stream::StreamExt;
use x11rb::{connection::Connection as _, protocol::xproto::ConnectionExt as _};

const CSS: &str = include_str!("style.css");
const ICON_RAW_2_PNG: &[u8] = include_bytes!("../../../assets/icon_raw_2.png");

static ICON_RAW_2_DATA_URI: LazyLock<String> = LazyLock::new(|| {
    let encoded = base64::engine::general_purpose::STANDARD.encode(ICON_RAW_2_PNG);
    format!("data:image/png;base64,{}", encoded)
});

/// Message type for the D-Bus coroutine communication.
#[derive(Debug)]
pub(crate) enum DbusAction {
    Respond { request_id: String, approved: bool },
}

/// Query the global cursor position from the X11 server.
/// Returns `None` if the connection fails or the query fails.
fn get_cursor_position() -> Option<(i32, i32)> {
    let (conn, screen_num) = x11rb::connect(None).ok()?;
    let root = conn.setup().roots[screen_num].root;
    let reply = conn.query_pointer(root).ok()?.reply().ok()?;
    Some((reply.root_x as i32, reply.root_y as i32))
}

fn raise_window(w: &tao::window::Window) {
    w.set_visible(true);
    w.set_minimized(false);

    let cursor_pos = get_cursor_position();

    // Find the monitor that contains the cursor, falling back to the window's current monitor.
    let monitor = cursor_pos
        .and_then(|(cx, cy)| {
            w.available_monitors().find(|m| {
                let pos = m.position();
                let size = m.size();
                cx >= pos.x
                    && cx < pos.x + size.width as i32
                    && cy >= pos.y
                    && cy < pos.y + size.height as i32
            })
        })
        .or_else(|| w.current_monitor());

    if let Some(monitor) = monitor {
        let m_size = monitor.size();
        let m_pos = monitor.position();
        let w_size = w.outer_size();

        let (x, y) = if let Some((cx, cy)) = cursor_pos {
            // Center the window on the cursor, clamped to stay fully within the monitor.
            let wx = cx - w_size.width as i32 / 2;
            let wy = cy - w_size.height as i32 / 2;
            let wx = wx
                .max(m_pos.x)
                .min(m_pos.x + m_size.width as i32 - w_size.width as i32);
            let wy = wy
                .max(m_pos.y)
                .min(m_pos.y + m_size.height as i32 - w_size.height as i32);
            (wx, wy)
        } else {
            // Fall back to centering on the monitor.
            (
                m_pos.x + (m_size.width as i32 - w_size.width as i32) / 2,
                m_pos.y + (m_size.height as i32 - w_size.height as i32) / 2,
            )
        };

        w.set_outer_position(tao::dpi::PhysicalPosition::new(x, y));
    }
    w.set_focus();
}

/// Coroutine that polls for show signals from the tray icon.
fn use_tray_watcher(win: Arc<tao::window::Window>) {
    use_coroutine(move |_: UnboundedReceiver<()>| {
        let win = Arc::clone(&win);
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if SHOW_REQUESTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
                    win.set_visible(true);
                }
            }
        }
    });
}

/// Coroutine that handles all D-Bus communication with the daemon.
fn use_dbus_handler(
    win: Arc<tao::window::Window>,
    mut requests: Signal<Vec<AccessControlRequest>>,
    mut error: Signal<Option<String>>,
) -> Coroutine<DbusAction> {
    use_coroutine(move |mut rx: UnboundedReceiver<DbusAction>| {
        let win = Arc::clone(&win);
        async move {
            // Connect to daemon D-Bus service.
            let proxy = match connect().await {
                Ok(p) => {
                    error.set(None);
                    p
                }
                Err(e) => {
                    log::error!("Failed to connect to daemon: {e}");
                    error.set(Some("Failed to connect to daemon".to_string()));
                    return;
                }
            };

            // Load any already-pending requests.
            match proxy.get_pending_requests().await {
                Ok(pending) => {
                    if !pending.is_empty() {
                        log::info!("Loaded {} pending request(s)", pending.len());
                        raise_window(&win);
                        // Push-merge by id: avoid overwriting entries already pushed
                        // by signals that may have arrived before this fetch completed.
                        let mut list = requests.write();
                        for item in pending {
                            if !list.iter().any(|r| r.id == item.id) {
                                list.push(item);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to get pending requests: {e}");
                    error.set(Some("Failed to load pending requests".to_string()));
                }
            }

            // Listen for NewRequest signals.
            let signal_stream = match proxy.receive_new_request().await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to subscribe to signals: {e}");
                    error.set(Some("Signal subscription failed".to_string()));
                    return;
                }
            };
            let mut signal_stream = pin!(signal_stream);

            // Process both incoming signals and outgoing responses using select-style loop.
            loop {
                tokio::select! {
                    item = signal_stream.next() => {
                        match item {
                            Some(signal) => match signal.args() {
                                Ok(args) => {
                                    log::debug!("NewRequest signal: id={}", args.request_id);
                                    // Fetch the UID-filtered list from the daemon rather than
                                    // trusting the broadcast signal payload, so User B's GUI
                                    // never sees User A's requests (N1).
                                    match proxy.get_pending_requests().await {
                                        Ok(pending) => {
                                            error.set(None);
                                            if !pending.is_empty() {
                                                raise_window(&win);
                                            }
                                            requests.set(pending);
                                        }
                                        Err(e) => {
                                            log::error!("Failed to get pending requests: {e}");
                                            error.set(Some("Failed to load pending requests".to_string()));
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("Failed to parse signal args: {e}");
                                    error.set(Some("Failed to parse signal args".to_string()));
                                    break;
                                }
                            },
                            None => {
                                log::warn!("D-Bus signal stream ended");
                                error.set(Some("Lost connection to daemon".to_string()));
                                break;
                            }
                        }
                    }
                    action = rx.next() => {
                        match action {
                            Some(DbusAction::Respond { request_id, approved }) => {
                                match proxy.respond_to_request(&request_id, approved).await {
                                    Ok(found) => {
                                        if !found {
                                            log::warn!(
                                                "Request {request_id} not found (may have timed out)"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("Failed to respond to {request_id}: {e}");
                                        error.set(Some("Failed to respond to request".to_string()));
                                    }
                                }
                                requests.write().retain(|r| r.id != request_id);
                                if requests.read().is_empty() {
                                    win.set_visible(false);
                                }
                            }
                            None => {
                                log::info!("Action channel closed");
                                error.set(Some("Action channel closed".to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }
    })
}

#[component]
pub fn App() -> Element {
    let requests = use_signal(Vec::<AccessControlRequest>::new);
    let error_sig = use_signal(|| None::<String>);

    let tao_window = Arc::clone(&window().window);
    use_tray_watcher(Arc::clone(&tao_window));
    let dbus_coroutine = use_dbus_handler(tao_window, requests, error_sig);

    let error = error_sig.read().clone();
    let request_list = requests.read().clone();

    rsx! {
        style { {CSS} }
        div { class: "container",
            div { class: "header",
                img {
                    class: "header-icon",
                    src: ICON_RAW_2_DATA_URI.as_str(),
                    alt: "fileprot",
                }
                h1 { "fileprot" }
                if let Some(ref msg) = error {
                    span { class: "status", "{msg}" }
                } else {
                    span { class: "status ok", "" }
                }
            }
            if request_list.is_empty() {
                div { class: "empty",
                    p { "No pending access requests." }
                    p { class: "hint",
                        "Requests will appear here when applications try to access protected files."
                    }
                }
            } else {
                div { class: "request-list",
                    for req in request_list.iter() {
                        RequestListEntry { req: req.clone(), dbus_tx: dbus_coroutine }
                    }
                }
            }
        }
    }
}
