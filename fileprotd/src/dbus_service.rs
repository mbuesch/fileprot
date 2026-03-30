use crate::access_control::AccessRequest;
use anyhow::{self as ah, Context, format_err as err};
use fileprot_common::{DBUS_BUS_NAME, DBUS_OBJECT_PATH, dbus_interface::AccessControlRequest};
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, mpsc, oneshot};
use zbus::{Connection, connection, interface, object_server::SignalEmitter};

/// Whether to verify the identity of the GUI peer on D-Bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerVerification {
    /// Verify that the calling binary matches the configured GUI path.
    Enabled,
    /// Skip peer verification (for testing only).
    Disabled,
}

/// A pending request waiting for user response.
struct PendingEntry {
    request: AccessControlRequest,
    response_tx: Option<oneshot::Sender<bool>>,
}

/// D-Bus service exposed by the daemon for the GUI to interact with.
pub struct AccessControlService {
    pending: Arc<Mutex<HashMap<String, PendingEntry>>>,
    gui_binary_path: PathBuf,
    peer_verification: PeerVerification,
}

#[interface(name = "ch.bues.fileprot.AccessControl")]
impl AccessControlService {
    /// Get all currently pending access requests.
    async fn get_pending_requests(&self) -> Vec<AccessControlRequest> {
        let pending = self.pending.lock().await;
        pending.values().map(|r| r.request.clone()).collect()
    }

    /// Respond to an access request. Returns true if the request was found.
    async fn respond_to_request(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &Connection,
        request_id: &str,
        approved: bool,
    ) -> zbus::fdo::Result<bool> {
        // Verify the caller is a legitimate fileprot GUI.
        if self.peer_verification == PeerVerification::Enabled
            && let Err(e) = self.verify_peer(&header, connection).await
        {
            log::warn!("Peer verification failed: {}", e);
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "Peer verification failed: {}",
                e
            )));
        }

        let mut pending = self.pending.lock().await;
        if let Some(mut req) = pending.remove(request_id) {
            log::info!(
                "Request {} {} by user",
                request_id,
                if approved { "approved" } else { "denied" }
            );
            if let Some(tx) = req.response_tx.take() {
                let _ = tx.send(approved);
            }
            Ok(true)
        } else {
            log::warn!("Request {} not found", request_id);
            Ok(false)
        }
    }

    /// Signal emitted when a new access request arrives.
    #[zbus(signal)]
    async fn new_request(
        emitter: &SignalEmitter<'_>,
        request: AccessControlRequest,
    ) -> zbus::Result<()>;
}

impl AccessControlService {
    fn new(gui_binary_path: PathBuf, peer_verification: PeerVerification) -> Self {
        AccessControlService {
            pending: Arc::new(Mutex::new(HashMap::new())),
            gui_binary_path,
            peer_verification,
        }
    }

    /// Verify that the D-Bus caller is the legitimate fileprot GUI binary.
    async fn verify_peer(
        &self,
        header: &zbus::message::Header<'_>,
        connection: &Connection,
    ) -> ah::Result<()> {
        let sender = header
            .sender()
            .ok_or_else(|| err!("no sender bus name in header"))?;

        // Use the D-Bus daemon to get the caller's PID.
        let dbus_proxy = zbus::fdo::DBusProxy::new(connection)
            .await
            .context("failed to create DBus proxy")?;

        let pid = dbus_proxy
            .get_connection_unix_process_id(sender.clone().into())
            .await
            .context("failed to get peer PID")?;

        // Read the caller's executable path from /proc.
        let exe_path = fs::read_link(format!("/proc/{}/exe", pid))
            .with_context(|| format!("failed to read /proc/{}/exe", pid))?;

        if exe_path != self.gui_binary_path {
            return Err(err!(
                "peer binary '{}' does not match expected '{}'",
                exe_path.display(),
                self.gui_binary_path.display()
            ));
        }

        log::debug!("Peer verified: PID {} exe {:?}", pid, exe_path);
        Ok(())
    }
}

/// Start the D-Bus service and a background task that processes incoming access requests.
/// Returns the D-Bus connection.
pub async fn start_dbus_service(
    mut request_rx: mpsc::Receiver<AccessRequest>,
    gui_binary_path: PathBuf,
    peer_verification: PeerVerification,
) -> ah::Result<Connection> {
    let service = AccessControlService::new(gui_binary_path, peer_verification);
    let pending = Arc::clone(&service.pending);

    let connection = connection::Builder::system()
        .context("failed to connect to system bus")?
        .name(DBUS_BUS_NAME)
        .context("failed to request bus name")?
        .serve_at(DBUS_OBJECT_PATH, service)
        .context("failed to serve at object path")?
        .build()
        .await
        .context("failed to build D-Bus connection")?;

    let conn_clone = connection.clone();

    // Spawn a task that receives access requests from FUSE threads
    // and adds them to the pending list, emitting D-Bus signals.
    tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            let info = request.request;

            // Add to pending list.
            {
                let mut pending_map = pending.lock().await;
                pending_map.insert(
                    info.id.clone(),
                    PendingEntry {
                        request: info.clone(),
                        response_tx: Some(request.response_tx),
                    },
                );
            }

            // Emit D-Bus signal.
            let object_server = conn_clone.object_server();
            let iface_ref = match object_server
                .interface::<_, AccessControlService>(DBUS_OBJECT_PATH)
                .await
            {
                Ok(iface) => iface,
                Err(e) => {
                    log::error!("Failed to get interface reference: {}", e);
                    continue;
                }
            };

            if let Err(e) =
                AccessControlService::new_request(iface_ref.signal_emitter(), info.clone()).await
            {
                log::error!("Failed to emit NewRequest signal: {}", e);
            }

            log::info!(
                "Pending request {}: pid={} path='{}' app='{}' op={}",
                info.id,
                info.pid,
                info.path,
                info.app_name,
                info.operation
            );
        }
        log::info!("Request channel closed, D-Bus service shutting down");
    });

    Ok(connection)
}
