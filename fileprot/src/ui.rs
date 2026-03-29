use crate::dbus_client::connect;
use base64::Engine;
use dioxus::desktop::window;
use dioxus::prelude::*;
use fileprot_common::dbus_interface::AccessControlRequest;
use futures_lite::StreamExt;
use image::GenericImageView;
use std::{
    pin::pin,
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tray_icon::Icon;

const CSS: &str = include_str!("style.css");
const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");
const ICON_RAW_2_PNG: &[u8] = include_bytes!("../../assets/icon_raw_2.png");

static ICON_RAW_2_DATA_URI: LazyLock<String> = LazyLock::new(|| {
    let encoded = base64::engine::general_purpose::STANDARD.encode(ICON_RAW_2_PNG);
    format!("data:image/png;base64,{}", encoded)
});

/// Shared state: set by the tray "Show" handler, polled by the Dioxus coroutine.
pub static SHOW_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Message type for the D-Bus coroutine communication.
#[derive(Debug)]
enum DbusAction {
    Respond { request_id: String, approved: bool },
}

pub fn app() -> Element {
    let mut requests = use_signal(Vec::<AccessControlRequest>::new);
    let mut connection_status = use_signal(|| "Connecting...".to_string());

    // Coroutine that polls for show/quit signals from the tray icon.
    let tao_window = window().window.clone();
    use_coroutine(move |_: UnboundedReceiver<()>| {
        let win = tao_window.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if SHOW_REQUESTED.swap(false, Ordering::Relaxed) {
                    win.set_visible(true);
                }
            }
        }
    });

    // Coroutine that handles D-Bus communication.
    let dbus_coroutine = use_coroutine(move |mut rx: UnboundedReceiver<DbusAction>| async move {
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
                    requests.write().push(info);
                }
                Event::Action(DbusAction::Respond {
                    request_id,
                    approved,
                }) => {
                    match proxy.respond_to_request(&request_id, approved).await {
                        Ok(found) => {
                            if !found {
                                log::warn!("Request {} not found (may have timed out)", request_id);
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to respond to {}: {}", request_id, e);
                        }
                    }
                    requests.write().retain(|r| r.id != request_id);
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
                        {render_request(req.clone(), dbus_coroutine)}
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

fn render_request(req: AccessControlRequest, dbus_tx: Coroutine<DbusAction>) -> Element {
    let req_id_approve = req.id.clone();
    let req_id_deny = req.id.clone();
    let dbus_tx_approve = dbus_tx;
    let dbus_tx_deny = dbus_tx;

    let op_class = match req.operation.as_str() {
        "read" => "op-read",
        "write" => "op-write",
        "create" => "op-create",
        "delete" => "op-delete",
        _ => "op-unknown",
    };

    rsx! {
        div { class: "request-card",
            div { class: "request-info",
                div { class: "request-field",
                    span { class: "label", "Operation:" }
                    span { class: "value {op_class}", "{req.operation}" }
                }
                div { class: "request-field",
                    span { class: "label", "File:" }
                    span { class: "value path", "{req.path}" }
                }
                div { class: "request-field",
                    span { class: "label", "Application:" }
                    span { class: "value", "{req.app_name}" }
                }
                div { class: "request-field",
                    span { class: "label", "PID:" }
                    span { class: "value", "{req.pid}" }
                }
            }
            div { class: "request-actions",
                button {
                    class: "btn btn-approve",
                    onclick: move |_| {
                        dbus_tx_approve
                            .send(DbusAction::Respond {
                                request_id: req_id_approve.clone(),
                                approved: true,
                            });
                    },
                    "Approve"
                }
                button {
                    class: "btn btn-deny",
                    onclick: move |_| {
                        dbus_tx_deny
                            .send(DbusAction::Respond {
                                request_id: req_id_deny.clone(),
                                approved: false,
                            });
                    },
                    "Deny"
                }
            }
        }
    }
}

/// Load the tray icon from the embedded PNG asset.
pub fn create_icon() -> Icon {
    let img = image::load_from_memory(ICON_PNG).expect("failed to load icon PNG");
    let (width, height) = img.dimensions();
    let rgba = img.into_rgba8().into_raw();
    Icon::from_rgba(rgba, width, height).expect("failed to create tray icon")
}
