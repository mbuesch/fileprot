use crate::access_control::AccessRequest;
use anyhow::{self as ah, Context, format_err as err};
use fileprot_common::{DBUS_BUS_NAME, DBUS_OBJECT_PATH, dbus_interface::AccessControlRequest};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::{Arc, mpsc as std_mpsc},
};
use tokio::sync::{Mutex, mpsc};
use zbus::{Connection, connection, interface, object_server::SignalEmitter};

/// D-Bus peer-verification options (for testing only).
/// In production both checks should remain enabled.
#[derive(Debug, Clone, Copy)]
pub struct PeerVerification {
    /// Verify that the calling binary's (dev, ino) matches the configured GUI path.
    pub verify_exe: bool,
    /// Verify that the caller's Unix UID matches the UID of the requested file's owner.
    pub verify_uid: bool,
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
    /// (dev, ino) of the GUI binary
    gui_exe_identity: (u64, u64),
    peer_verification: PeerVerification,
}

#[interface(name = "ch.bues.fileprot.AccessControl")]
impl AccessControlService {
    /// Get all currently pending access requests.
    /// Only requests whose FUSE-reported UID matches the caller's D-Bus UID
    /// are returned, preventing cross-user information disclosure.
    /// The caller's binary is also verified against the configured GUI path.
    async fn get_pending_requests(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Vec<AccessControlRequest> {
        // Verify binary identity first.
        if self.peer_verification.verify_exe
            && let Err(e) = self.verify_peer(&header, connection).await
        {
            log::warn!("Peer verification failed for GetPendingRequests: {}", e);
            return vec![];
        }
        // Then filter by UID to prevent cross-user information disclosure.
        let caller_uid = match Self::caller_uid(&header, connection).await {
            Ok(u) => u,
            Err(e) => {
                log::warn!("Failed to get caller UID for GetPendingRequests: {}", e);
                return vec![];
            }
        };
        let pending = self.pending.lock().await;
        pending
            .values()
            .filter(|e| !self.peer_verification.verify_uid || e.request.uid == caller_uid)
            .map(|e| e.request.clone())
            .collect()
    }

    /// Respond to an access request. Returns true if the request was found.
    /// The caller's binary is verified against the configured GUI path, and
    /// the caller's D-Bus UID must match the UID of the requesting process;
    /// this prevents User B from approving or denying User A's requests.
    async fn respond_to_request(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &Connection,
        request_id: &str,
        approved: bool,
    ) -> zbus::fdo::Result<bool> {
        // Verify binary identity first.
        if self.peer_verification.verify_exe
            && let Err(e) = self.verify_peer(&header, connection).await
        {
            log::warn!("Peer verification failed: {}", e);
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "Peer verification failed: {}",
                e
            )));
        }
        // Then verify UID to prevent cross-user approval bypass.
        let caller_uid = match Self::caller_uid(&header, connection).await {
            Ok(u) => u,
            Err(e) => {
                log::warn!("UID check failed: {}", e);
                return Err(zbus::fdo::Error::AccessDenied(format!(
                    "UID check failed: {}",
                    e
                )));
            }
        };

        let mut pending = self.pending.lock().await;

        // Verify UID match before acting.
        if self.peer_verification.verify_uid
            && let Some(entry) = pending.get(request_id)
            && entry.request.uid != caller_uid
        {
            log::warn!(
                "RespondToRequest: caller UID {} does not match request UID {} (id={})",
                caller_uid,
                entry.request.uid,
                request_id
            );
            return Err(zbus::fdo::Error::AccessDenied(
                "UID mismatch: you can only respond to requests from your own user".to_string(),
            ));
        }

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
    /// Carries only the request ID; the GUI calls GetPendingRequests for the
    /// UID-filtered payload, preventing cross-user information disclosure.
    #[zbus(signal)]
    async fn new_request(emitter: &SignalEmitter<'_>, request_id: &str) -> zbus::Result<()>;
}

impl AccessControlService {
    fn new(
        gui_binary_path: PathBuf,
        gui_exe_identity: (u64, u64),
        peer_verification: PeerVerification,
    ) -> Self {
        AccessControlService {
            pending: Arc::new(Mutex::new(HashMap::new())),
            gui_binary_path,
            gui_exe_identity,
            peer_verification,
        }
    }

    /// Get the real UID of the D-Bus caller via GetConnectionUnixUser.
    async fn caller_uid(
        header: &zbus::message::Header<'_>,
        connection: &Connection,
    ) -> ah::Result<u32> {
        let sender = header
            .sender()
            .ok_or_else(|| err!("no sender bus name in header"))?;
        let dbus_proxy = zbus::fdo::DBusProxy::new(connection)
            .await
            .context("failed to create DBus proxy")?;
        dbus_proxy
            .get_connection_unix_user(sender.clone().into())
            .await
            .context("failed to get caller UID")
    }

    /// Verify that the D-Bus caller is the legitimate fileprot GUI binary
    /// by comparing (device, inode) of the caller's /proc/<pid>/exe against
    /// the identity cached at daemon startup.
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

        // Open /proc/<pid>/exe with O_PATH so the kernel resolves the magic
        // symlink to the actual executable inode directly.  fstat on the
        // resulting fd gives (dev, ino) of that inode without any additional
        // userspace symlink traversal on the resolved path string.
        let proc_exe = format!("/proc/{}/exe", pid);
        let (proc_dev, proc_ino) = stat_o_path(&proc_exe)
            .with_context(|| format!("failed to stat {} via O_PATH", proc_exe))?;

        // Compare against the identity captured once at startup.
        let (expected_dev, expected_ino) = self.gui_exe_identity;
        if proc_dev != expected_dev || proc_ino != expected_ino {
            return Err(err!(
                "peer binary (dev={}, ino={}) does not match GUI binary '{}' (dev={}, ino={})",
                proc_dev,
                proc_ino,
                self.gui_binary_path.display(),
                expected_dev,
                expected_ino,
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

/// Open `path` with `O_PATH | O_CLOEXEC` and return its `(dev, ino)` via `fstat`.
///
/// `O_PATH` has the kernel resolve the path (including magic symlinks such as
/// `/proc/<pid>/exe`) to a file-descriptor that refers directly to the target
/// inode.  `fstat` on that fd returns the inode's identity without a second
/// round of userspace symlink resolution on the resolved path string, which
/// `fs::metadata` would otherwise perform.
fn stat_o_path(path: &str) -> ah::Result<(u64, u64)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("O_PATH open failed: {}", path))?;
    let meta = file
        .metadata()
        .with_context(|| format!("fstat failed: {}", path))?;
    Ok((meta.dev(), meta.ino()))
}

/// Start the D-Bus service and a background task that processes incoming access requests.
/// Returns the D-Bus connection.
pub async fn start_dbus_service(
    mut request_rx: mpsc::Receiver<AccessRequest>,
    gui_binary_path: PathBuf,
    peer_verification: PeerVerification,
) -> ah::Result<Connection> {
    // Capture the GUI binary's (dev, ino) once at startup using O_PATH + fstat.
    // This avoids re-following symlinks on every request and gives a stable
    // identity for the lifetime of this daemon session.
    let gui_exe_identity = if peer_verification.verify_exe {
        let path_str = gui_binary_path
            .to_str()
            .ok_or_else(|| err!("GUI binary path is not valid UTF-8"))?;
        let identity = stat_o_path(path_str).with_context(|| {
            format!(
                "failed to identify GUI binary '{}'",
                gui_binary_path.display()
            )
        })?;
        log::info!(
            "GUI binary '{}' identity cached: dev={}, ino={}",
            gui_binary_path.display(),
            identity.0,
            identity.1
        );
        identity
    } else {
        (0, 0)
    };

    let service = AccessControlService::new(gui_binary_path, gui_exe_identity, peer_verification);
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
                AccessControlService::new_request(iface_ref.signal_emitter(), &info.id).await
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
