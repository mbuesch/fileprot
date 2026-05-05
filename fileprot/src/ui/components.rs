use super::app::DbusAction;
use dioxus::prelude::*;
use fileprot_common::dbus_interface::AccessControlRequest;

#[component]
pub fn RequestListEntry(req: AccessControlRequest, dbus_tx: Coroutine<DbusAction>) -> Element {
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

    // Symbol prefix gives a non-color cue for colorblind users.
    let op_label = match req.operation.as_str() {
        "read" => "\u{2193} read",
        "write" => "\u{2191} write",
        "create" => "+ create",
        "delete" => "\u{2715} delete",
        _ => req.operation.as_str(),
    };

    rsx! {
        div { class: "request-card {op_class}",
            div { class: "request-body",
                // Primary: app name + operation badge
                div { class: "app-row",
                    span { class: "app-name", "{req.app_name}" }
                    span { class: "op-badge {op_class}", "{op_label}" }
                }
                // Secondary: file path
                div { class: "file-path", "{req.path}" }
                // Tertiary: PID
                div { class: "meta-row",
                    span { class: "meta-label", "PID" }
                    span { "{req.pid}" }
                }
            }
            // Actions: Approve left, Deny right
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
                    "\u{2713} Approve"
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
                    "\u{2715} Deny"
                }
            }
        }
    }
}
