use dioxus::prelude::*;
use fileprot_common::dbus_interface::AccessControlRequest;

use super::app::DbusAction;

pub fn render_request(req: AccessControlRequest, dbus_tx: Coroutine<DbusAction>) -> Element {
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
                div { class: "request-field primary",
                    span { class: "label", "File:" }
                    span { class: "value path", "{req.path}" }
                }
                div { class: "request-field secondary",
                    span { class: "label", "Application:" }
                    span { class: "value", "{req.app_name}" }
                }
                div { class: "request-field tertiary",
                    span { class: "label", "Operation:" }
                    span { class: "value {op_class}", "{req.operation}" }
                }
                div { class: "request-field tertiary",
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
