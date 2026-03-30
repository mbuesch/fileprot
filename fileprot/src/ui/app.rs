use crate::dbus_client::connect;
use base64::Engine;
use dioxus::desktop::{tao, window};
use dioxus::prelude::*;
use fileprot_common::dbus_interface::AccessControlRequest;
use futures_lite::StreamExt;
use std::{pin::pin, sync::LazyLock, time::Duration};

use super::components::render_request;
use super::tray::SHOW_REQUESTED;

const CSS: &str = include_str!("../style.css");
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

#[component]
pub fn App() -> Element {
    let mut requests = use_signal(Vec::<AccessControlRequest>::new);
    let mut connection_status = use_signal(|| "Connecting...".to_string());

    // Coroutine that polls for show/quit signals from the tray icon.
    let tao_window = window().window.clone();
    let tao_window_for_dbus = tao_window.clone();
    use_coroutine(move |_: UnboundedReceiver<()>| {
        let win = tao_window.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if SHOW_REQUESTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
                    win.set_visible(true);
                }
            }
        }
    });

    // Coroutine that handles D-Bus communication.
    let dbus_coroutine = use_coroutine(move |mut rx: UnboundedReceiver<DbusAction>| {
        let win = tao_window_for_dbus.clone();
        async move {
            let raise_window = |w: &tao::window::Window| {
                w.set_visible(true);
                w.set_minimized(false);
                if let Some(monitor) = w.current_monitor() {
                    let m_size = monitor.size();
                    let m_pos = monitor.position();
                    let w_size = w.outer_size();
                    let x = m_pos.x + (m_size.width as i32 - w_size.width as i32) / 2;
                    let y = m_pos.y + (m_size.height as i32 - w_size.height as i32) / 2;
                    w.set_outer_position(tao::dpi::PhysicalPosition::new(x, y));
                }
                w.set_focus();
            };
            // Connect to daemon D-Bus service.
            let proxy = match connect().await {
                Ok(p) => {
                    connection_status.set("Connected".to_string());
                    p
                }
                Err(e) => {
                    let msg = format!("Failed to connect to daemon: {}", e);
                    log::error!("{}", msg);
                    connection_status.set(msg);
                    return;
                }
            };

            // Load any already-pending requests.
            match proxy.get_pending_requests().await {
                Ok(pending) => {
                    if !pending.is_empty() {
                        log::info!("Loaded {} pending request(s)", pending.len());
                        raise_window(&win);
                        requests.set(pending);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to get pending requests: {}", e);
                }
            }

            // Listen for NewRequest signals.
            let signal_stream = match proxy.receive_new_request().await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to subscribe to signals: {}", e);
                    connection_status.set(format!("Signal subscription failed: {}", e));
                    return;
                }
            };

            let mut signal_stream = pin!(signal_stream);

            // Process both incoming signals and outgoing responses using select-style loop.
            loop {
                enum Event {
                    Signal(AccessControlRequest),
                    Action(DbusAction),
                    SignalStreamEnded,
                    ActionStreamEnded,
                }

                let event = futures_lite::future::or(
                    async {
                        match signal_stream.next().await {
                            Some(signal) => match signal.args() {
                                Ok(args) => Event::Signal(args.request),
                                Err(e) => {
                                    log::error!("Failed to parse signal args: {}", e);
                                    // Return a dummy that we'll skip
                                    Event::SignalStreamEnded
                                }
                            },
                            None => Event::SignalStreamEnded,
                        }
                    },
                    async {
                        match rx.next().await {
                            Some(action) => Event::Action(action),
                            None => Event::ActionStreamEnded,
                        }
                    },
                )
                .await;

                match event {
                    Event::Signal(info) => {
                        log::info!("New request: {:?}", info);
                        raise_window(&win);
                        requests.write().push(info);
                    }
                    Event::Action(DbusAction::Respond {
                        request_id,
                        approved,
                    }) => {
                        match proxy.respond_to_request(&request_id, approved).await {
                            Ok(found) => {
                                if !found {
                                    log::warn!(
                                        "Request {} not found (may have timed out)",
                                        request_id
                                    );
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to respond to {}: {}", request_id, e);
                            }
                        }
                        requests.write().retain(|r| r.id != request_id);
                        if requests.read().is_empty() {
                            win.set_visible(false);
                        }
                    }
                    Event::SignalStreamEnded => {
                        log::warn!("D-Bus signal stream ended");
                        break;
                    }
                    Event::ActionStreamEnded => {
                        log::info!("Action channel closed");
                        break;
                    }
                }
            }
        }
    });

    let status = connection_status.read().clone();
    let request_list = requests.read().clone();
    let has_requests = !request_list.is_empty();

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
                span { class: if status == "Connected" { "status connected" } else { "status" },
                    "{status}"
                }
            }
            if has_requests {
                div { class: "request-list",
                    for req in request_list.iter() {
                        render_request { req: req.clone(), dbus_tx: dbus_coroutine }
                    }
                }
            } else {
                div { class: "empty",
                    p { "No pending access requests." }
                    p { class: "hint",
                        "Requests will appear here when applications try to access protected files."
                    }
                }
            }
        }
    }
}
