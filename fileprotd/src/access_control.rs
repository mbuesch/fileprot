use anyhow::{self as ah};
use fileprot_common::{Operation, dbus_interface::AccessControlRequest};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc as std_mpsc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

/// Maximum number of entries in the per-process approval cache.
/// When the cache is full and all entries are still live, new approvals are
/// not cached (the process will simply be prompted again on its next access).
const APPROVAL_CACHE_MAX_ENTRIES: usize = 1024;

/// Returned when the access-request queue is at capacity.
#[derive(Debug)]
pub struct QueueFullError;

impl std::fmt::Display for QueueFullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "access request queue full")
    }
}

impl std::error::Error for QueueFullError {}

/// A request from the FUSE filesystem to the D-Bus service,
/// asking the user for approval.
pub struct AccessRequest {
    pub request: AccessControlRequest,
    /// Sender half of the response channel. The D-Bus handler calls
    /// `send(approved)` on this; it is a std (non-async) Sender so it is safe
    /// to call from async code without blocking the executor.
    pub response_tx: std_mpsc::SyncSender<bool>,
    /// Receiver half of a cancellation pair. The FUSE thread holds the sender
    /// side alive for the entire duration of `request_access`. When the
    /// function returns (timeout, response received, or error), the sender is
    /// dropped, completing this receiver. The D-Bus service watches this to
    /// evict the corresponding pending-map entry.
    pub cancel_rx: oneshot::Receiver<()>,
}

/// Composite identity of a process, used as the approval cache key.
///
/// Using multiple attributes guards against PID reuse: a new process that
/// happens to receive the same PID as a previously approved one will differ in
/// at least one of exe_path or start_time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    /// Kernel process ID.
    pid: u32,
    /// UID of the requesting process (from the FUSE request credential).
    uid: u32,
    /// Resolved absolute path of the process executable.
    exe_path: PathBuf,
    /// Process start time read from `/proc/<pid>/stat` (field 22, jiffies
    /// since boot). Distinguishes processes that share a PID over time.
    start_time: u64,
}

impl ProcessIdentity {
    /// Snapshot a process's identity and derive its app name from the
    /// executable path, using a single coherent set of `/proc/<pid>/` reads to
    /// minimise the PID-reuse race window. Returns `None` if the process has
    /// already exited or any required `/proc` entry is unreadable.
    pub fn snapshot(pid: u32, uid: u32) -> Option<(Self, String)> {
        let exe_path = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
        let start_time = Self::read_start_time(pid)?;
        let app_name = exe_path.file_name()?.to_str()?.to_owned();
        let identity = ProcessIdentity {
            pid,
            uid,
            exe_path,
            start_time,
        };
        Some((identity, app_name))
    }

    /// Read the process start time from `/proc/<pid>/stat` (field 22).
    ///
    /// The `comm` field (field 2) may contain spaces and parentheses, so we
    /// locate it by finding the last `)` in the line and counting fields from
    /// there.
    fn read_start_time(pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
        // Skip past the closing ')' of comm, then a single space.
        let after_comm = stat.rfind(')')?.checked_add(2)?;
        let rest = &stat[after_comm..];
        // Fields after comm (0-indexed from here):
        //   0: state, 1: ppid, 2: pgrp, 3: session, 4: tty_nr,
        //   5: tpgid, 6: flags, 7: minflt, 8: cminflt, 9: majflt,
        //  10: cmajflt, 11: utime, 12: stime, 13: cutime, 14: cstime,
        //  15: priority, 16: nice, 17: num_threads, 18: itrealvalue,
        //  19: starttime  <-- field 22 in the kernel docs (1-indexed)
        rest.split_whitespace().nth(19)?.parse().ok()
    }
}

/// Controls whether a cache hit resets the approval TTL timer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ApprovalRenewal {
    /// Each cache hit resets the TTL timer, keeping the approval alive as long
    /// as the process keeps accessing files.
    RenewOnAccess,
    /// The TTL is fixed from the time the user originally granted approval.
    /// It will expire even if the process is actively accessing files.
    NoRenewal,
}

/// Controls whether a cached approval is tied to the specific process that
/// obtained it or is reusable by any process.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ApprovalCoupling {
    /// The cached approval is locked to the exact process (PID, UID, exe path,
    /// start time). No other process can benefit from it.
    CoupledToProcess,
    /// Any process may reuse a recently-granted approval within the TTL window.
    Uncoupled,
}

/// Storage for the approval cache, keyed on whether process-identity coupling
/// is enabled.
#[derive(Debug, Clone)]
enum CacheState {
    /// Each approved process is tracked individually by its full identity.
    /// Only that exact process can reuse the cached approval.
    Coupled(HashMap<ProcessIdentity, Instant>),
    /// A single global "last approved" timestamp.
    /// Any process benefits from a recently-granted approval.
    Uncoupled(Option<Instant>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CachedApproval {
    Approved,
    NotApproved,
}

/// Handle held by the FUSE filesystem to send access requests.
/// Bridges synchronous FUSE threads to the async D-Bus service.
#[derive(Debug)]
pub struct AccessController {
    request_tx: mpsc::Sender<AccessRequest>,
    timeout: Duration,
    next_id: AtomicU64,
    /// How long to remember an approval.
    /// A value of `Duration::ZERO` disables caching entirely.
    approval_ttl: Duration,
    /// Whether cache hits reset the TTL timer.
    renewal: ApprovalRenewal,
    /// Approval cache, mode determined at construction time.
    approval_cache: Mutex<CacheState>,
}

impl AccessController {
    pub fn new(
        request_tx: mpsc::Sender<AccessRequest>,
        timeout: Duration,
        approval_ttl: Duration,
        coupling: ApprovalCoupling,
        renewal: ApprovalRenewal,
    ) -> Self {
        let cache = match coupling {
            ApprovalCoupling::CoupledToProcess => CacheState::Coupled(HashMap::new()),
            ApprovalCoupling::Uncoupled => CacheState::Uncoupled(None),
        };
        AccessController {
            request_tx,
            timeout,
            next_id: AtomicU64::new(1),
            approval_ttl,
            renewal,
            approval_cache: Mutex::new(cache),
        }
    }

    /// Return `true` if a non-expired approval is cached.
    /// `identity` is only consulted in coupled mode.
    fn check_cache(&self, identity: Option<&ProcessIdentity>) -> CachedApproval {
        if self.approval_ttl.is_zero() {
            return CachedApproval::NotApproved;
        }
        let mut cache = self.approval_cache.lock().expect("Lock poisoned");
        match &mut *cache {
            CacheState::Coupled(map) => {
                // Evict expired entries from the cache.
                map.retain(|_, approved_at| approved_at.elapsed() < self.approval_ttl);

                // Check if the given identity has a valid cached approval.
                let approved = identity.is_some_and(|id| {
                    map.get(id)
                        .is_some_and(|approved_at| approved_at.elapsed() < self.approval_ttl)
                });
                if approved {
                    // Renew the TTL on each access if the option is set.
                    if self.renewal == ApprovalRenewal::RenewOnAccess
                        && let Some(id) = identity
                        && let Some(approved_at) = map.get_mut(id)
                    {
                        *approved_at = Instant::now();
                    }
                    CachedApproval::Approved
                } else {
                    CachedApproval::NotApproved
                }
            }
            CacheState::Uncoupled(last) => {
                // Check if the global approval is still valid.
                let approved =
                    last.is_some_and(|approved_at| approved_at.elapsed() < self.approval_ttl);
                if approved {
                    // Renew the TTL on each access if the option is set.
                    if self.renewal == ApprovalRenewal::RenewOnAccess {
                        *last = Some(Instant::now());
                    }
                    CachedApproval::Approved
                } else {
                    CachedApproval::NotApproved
                }
            }
        }
    }

    /// Insert or refresh an approval entry.
    /// `identity` is only used in coupled mode.
    fn cache_approval(&self, identity: Option<ProcessIdentity>) {
        if self.approval_ttl.is_zero() {
            return;
        }
        let mut cache = self.approval_cache.lock().expect("Lock poisoned");
        match &mut *cache {
            CacheState::Coupled(map) => {
                if let Some(id) = identity {
                    // Enforce a size cap to prevent unbounded growth from many
                    // short-lived processes that each get approved once.
                    if map.len() >= APPROVAL_CACHE_MAX_ENTRIES {
                        // Evict all expired entries first.
                        map.retain(|_, approved_at| approved_at.elapsed() < self.approval_ttl);
                        // If still at capacity, skip caching; the process will
                        // simply be prompted again on its next access.
                        if map.len() >= APPROVAL_CACHE_MAX_ENTRIES {
                            log::warn!(
                                "Approval cache at capacity ({}), not caching approval for pid={}",
                                APPROVAL_CACHE_MAX_ENTRIES,
                                id.pid,
                            );
                            return;
                        }
                    }
                    map.insert(id, Instant::now());
                }
            }
            CacheState::Uncoupled(last) => {
                *last = Some(Instant::now());
            }
        }
    }

    /// Send an access request and block until the user responds or timeout expires.
    /// Called from FUSE threads (synchronous context).
    pub fn request_access(
        &self,
        identity: ProcessIdentity,
        path: String,
        app_name: String,
        operation: Operation,
    ) -> ah::Result<bool> {
        let pid = identity.pid;

        // Return early if a valid approval is cached.
        if self.check_cache(Some(&identity)) == CachedApproval::Approved {
            log::debug!("Approval cache hit: pid={} op={}", pid, operation);
            return Ok(true);
        }

        let req_id = format!("req-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        // Use a std (non-async) sync_channel with a bound of 1.
        // Sender::send is non-blocking for a bound-1 channel that has not been
        // sent to yet, and it is safe to call from async code without touching
        // the tokio executor. The FUSE thread blocks on recv_timeout, which is
        // a plain OS-level block that needs no tokio runtime context.
        let (response_tx, response_rx) = std_mpsc::sync_channel(1);
        // The sender side is held alive for the entire wait loop. When this
        // function returns (for any reason), `_cancel_tx` is dropped, which
        // wakes the D-Bus cleanup task to evict the pending-map entry.
        let (_cancel_tx, cancel_rx) = oneshot::channel::<()>();

        let request = AccessRequest {
            request: AccessControlRequest {
                id: req_id.clone(),
                pid: identity.pid,
                uid: identity.uid,
                path,
                app_name,
                operation: operation.to_string(),
            },
            response_tx,
            cancel_rx,
        };

        // Send the request to the D-Bus service. Use try_send so that a full
        // queue never blocks FUSE worker threads (which could deadlock all
        // protected mounts).
        match self.request_tx.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::warn!(
                    "Access request queue full, temporarily rejecting pid={}",
                    pid
                );
                return Err(ah::anyhow!(QueueFullError));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(ah::anyhow!("D-Bus service channel closed"));
            }
        }

        // Block the FUSE thread waiting for a response. recv_timeout is a
        // plain OS-level blocking call that works from any thread without
        // requiring a tokio runtime context.
        match response_rx.recv_timeout(self.timeout) {
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                log::warn!(
                    "Access request {} timed out after {:?}",
                    req_id,
                    self.timeout
                );
                Ok(false)
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                log::error!("Access request {} channel closed", req_id);
                Ok(false)
            }
            Ok(approved) => {
                if approved {
                    self.cache_approval(Some(identity));
                }
                Ok(approved)
            }
        }
    }
}
