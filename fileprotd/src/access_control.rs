use anyhow::{self as ah, Context};
use fileprot_common::{Operation, dbus_interface::AccessControlRequest};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

/// A request from the FUSE filesystem to the D-Bus service,
/// asking the user for approval.
pub struct AccessRequest {
    pub request: AccessControlRequest,
    pub response_tx: oneshot::Sender<bool>,
}

/// Composite identity of a process, used as the approval cache key.
///
/// Using multiple attributes guards against PID reuse: a new process that
/// happens to receive the same PID as a previously approved one will differ in
/// at least one of exe_path or start_time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessIdentity {
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
    /// Build a `ProcessIdentity` by reading `/proc/<pid>/` entries.
    /// Returns `None` if the process has already exited or the files are
    /// unreadable.
    fn read(pid: u32, uid: u32) -> Option<Self> {
        let exe_path = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
        let start_time = Self::read_start_time(pid)?;
        Some(ProcessIdentity {
            pid,
            uid,
            exe_path,
            start_time,
        })
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

/// Controls whether a cached approval is tied to the specific process that
/// obtained it or is reusable by any process.
pub enum ApprovalCoupling {
    /// The cached approval is locked to the exact process (PID, UID, exe path,
    /// start time). No other process can benefit from it.
    CoupledToProcess,
    /// Any process may reuse a recently-granted approval within the TTL window.
    Uncoupled,
}

/// Storage for the approval cache, keyed on whether process-identity coupling
/// is enabled.
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
pub struct AccessController {
    request_tx: mpsc::Sender<AccessRequest>,
    timeout: Duration,
    next_id: AtomicU64,
    /// How long to remember an approval.
    /// A value of `Duration::ZERO` disables caching entirely.
    approval_ttl: Duration,
    /// Approval cache, mode determined at construction time.
    approval_cache: Mutex<CacheState>,
}

impl AccessController {
    pub fn new(
        request_tx: mpsc::Sender<AccessRequest>,
        timeout: Duration,
        approval_ttl: Duration,
        coupling: ApprovalCoupling,
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
                if identity.is_some_and(|id| {
                    map.get(id)
                        .is_some_and(|approved_at| approved_at.elapsed() < self.approval_ttl)
                }) {
                    CachedApproval::Approved
                } else {
                    CachedApproval::NotApproved
                }
            }
            CacheState::Uncoupled(last) => {
                // Check if the global approval is still valid.
                if last.is_some_and(|approved_at| approved_at.elapsed() < self.approval_ttl) {
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
        pid: u32,
        uid: u32,
        path: String,
        app_name: String,
        operation: Operation,
    ) -> ah::Result<bool> {
        // Build the process identity for cache operations.
        let identity = ProcessIdentity::read(pid, uid);

        // Return early if a valid approval is cached.
        if self.check_cache(identity.as_ref()) == CachedApproval::Approved {
            log::debug!("Approval cache hit: pid={} op={}", pid, operation);
            return Ok(true);
        }

        let req_id = format!("req-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let (response_tx, mut response_rx) = oneshot::channel();

        let request = AccessRequest {
            request: AccessControlRequest {
                id: req_id.clone(),
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
        let timeout = self.timeout;
        let start = Instant::now();

        loop {
            if timeout.checked_sub(start.elapsed()).is_none() {
                log::warn!("Access request {} timed out after {:?}", req_id, timeout);
                return Ok(false);
            }

            match response_rx.try_recv() {
                Ok(approved) => {
                    if approved {
                        self.cache_approval(identity);
                    }
                    return Ok(approved);
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    log::error!("Access request {} channel closed", req_id);
                    return Ok(false);
                }
            }
        }
    }
}
