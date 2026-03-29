use anyhow::{self as ah, Context};
use fileprot_common::{Operation, dbus_interface::AccessControlRequest};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

/// A request from the FUSE filesystem to the D-Bus service,
/// asking the user for approval.
pub struct AccessRequest {
    pub request: AccessControlRequest,
    pub response_tx: oneshot::Sender<bool>,
}

/// Handle held by the FUSE filesystem to send access requests.
/// Bridges synchronous FUSE threads to the async D-Bus service.
pub struct AccessController {
    request_tx: mpsc::Sender<AccessRequest>,
    timeout: Duration,
    next_id: AtomicU64,
}

impl AccessController {
    pub fn new(request_tx: mpsc::Sender<AccessRequest>, timeout: Duration) -> Self {
        AccessController {
            request_tx,
            timeout,
            next_id: AtomicU64::new(1),
        }
    }

    /// Send an access request and block until the user responds or timeout expires.
    /// Called from FUSE threads (synchronous context).
    pub fn request_access(
        &self,
        pid: u32,
        path: String,
        app_name: String,
        operation: Operation,
    ) -> ah::Result<bool> {
        let id = format!("req-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let (response_tx, mut response_rx) = oneshot::channel();

        let request = AccessRequest {
            request: AccessControlRequest {
                id: id.clone(),
                pid,
                path,
                app_name,
                operation: operation.to_string(),
            },
            response_tx,
        };

        // Send request to D-Bus service (blocking_send is safe from non-tokio threads).
        self.request_tx
            .blocking_send(request)
            .context("D-Bus service channel closed")?;

        // Block waiting for response with timeout.
        // Instead of spawning a thread, use a blocking_recv with a manual timeout check.
        let timeout = self.timeout;
        let start = std::time::Instant::now();

        loop {
            let _ = match timeout.checked_sub(start.elapsed()) {
                Some(r) => r,
                None => {
                    log::warn!("Access request {} timed out after {:?}", id, timeout);
                    return Ok(false);
                }
            };

            match response_rx.try_recv() {
                Ok(approved) => return Ok(approved),
                Err(oneshot::error::TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    log::error!("Access request {} channel closed", id);
                    return Ok(false);
                }
            }
        }
    }
}
