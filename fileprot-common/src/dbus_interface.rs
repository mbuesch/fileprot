//! D-Bus interface definitions shared between daemon and GUI.
//!
//! The daemon exposes the `ch.bues.fileprot.AccessControl` interface on
//! `ch.bues.fileprot.Daemon` at `/ch/bues/fileprot/Daemon`.
//!
//! Methods:
//!   GetPendingRequests() -> Vec<(id, pid, path, app_name, operation)>
//!   RespondToRequest(request_id, approved) -> bool
//!
//! Signals:
//!   NewRequest(id, pid, path, app_name, operation)

use serde::{Deserialize, Serialize};
use zbus::{proxy, zvariant::Type};

#[derive(Debug, Clone, PartialEq, Eq, Type, Serialize, Deserialize)]
pub struct AccessControlRequest {
    pub id: String,
    pub pid: u32,
    pub uid: u32,
    pub path: String,
    pub app_name: String,
    pub operation: String,
}

/// D-Bus proxy for the GUI to communicate with the daemon.
#[proxy(
    interface = "ch.bues.fileprot.AccessControl",
    default_service = "ch.bues.fileprot.Daemon",
    default_path = "/ch/bues/fileprot/Daemon"
)]
pub trait AccessControl {
    /// Get all currently pending access requests.
    /// Returns a list of (id, pid, path, app_name, operation) tuples.
    fn get_pending_requests(&self) -> zbus::Result<Vec<AccessControlRequest>>;

    /// Respond to an access request.
    /// Returns true if the request was found and the response was recorded.
    fn respond_to_request(&self, request_id: &str, approved: bool) -> zbus::Result<bool>;

    /// Signal emitted when a new access request arrives.
    #[zbus(signal)]
    fn new_request(&self, request: AccessControlRequest) -> zbus::Result<()>;
}
