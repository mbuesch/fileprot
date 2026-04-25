use crate::access_control::AccessRequest;
use anyhow::{self as ah, Context, format_err as err};
use fileprot_common::{DBUS_BUS_NAME, DBUS_OBJECT_PATH, dbus_interface::AccessControlRequest};
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{Arc, mpsc as std_mpsc},
};
use tokio::sync::{Mutex, mpsc};
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
    response_tx: Option<std_mpsc::SyncSender<bool>>,
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
            if let Some(tx) = req.response_tx.take()
                && tx.send(approved).is_err()
            {
                log::warn!(
                    "Request {}: response channel closed before send (FUSE thread already gone)",
                    request_id
                );
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

        // Verify the peer's executable against the configured GUI binary by
        // comparing (device, inode).
        let proc_exe = format!("/proc/{}/exe", pid);
        let proc_meta =
            fs::metadata(&proc_exe).with_context(|| format!("failed to stat {}", proc_exe))?;
        let gui_meta = fs::metadata(&self.gui_binary_path).with_context(|| {
            format!(
                "failed to stat GUI binary '{}'",
                self.gui_binary_path.display()
            )
        })?;

        if proc_meta.dev() != gui_meta.dev() || proc_meta.ino() != gui_meta.ino() {
            return Err(err!(
                "peer binary (dev={}, ino={}) does not match GUI binary '{}' (dev={}, ino={})",
                proc_meta.dev(),
                proc_meta.ino(),
                self.gui_binary_path.display(),
                gui_meta.dev(),
                gui_meta.ino(),
            ));
        }

        log::debug!(
            "Peer verified: PID {} matches GUI binary '{}'",
            pid,
            self.gui_binary_path.display()
        );
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
            let cancel_rx = request.cancel_rx;

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

            // Spawn a lightweight task that removes the pending entry once the
            // FUSE thread drops its cancel_tx (i.e. request_access returned,
            // whether by timeout, response, or error). This prevents stale
            // entries from accumulating in the pending map when requests time
            // out without a user response.
            let pending_clone = Arc::clone(&pending);
            let id_clone = info.id.clone();
            tokio::spawn(async move {
                // Completes when cancel_tx is dropped (any return path).
                let _ = cancel_rx.await;
                let mut map = pending_clone.lock().await;
                if map.remove(&id_clone).is_some() {
                    log::info!(
                        "Request {} removed from pending after FUSE thread returned",
                        id_clone
                    );
                }
            });
        }
        log::info!("Request channel closed, D-Bus service shutting down");
    });

    Ok(connection)
}
