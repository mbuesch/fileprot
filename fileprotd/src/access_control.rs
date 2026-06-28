use anyhow::{self as ah};
use fileprot_common::{Operation, dbus_interface::AccessControlRequest};
use rustix::process::{Pid as RustixPid, PidfdFlags, pidfd_open};
use std::{
    collections::{HashMap, hash_map::Entry},
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, mpsc as std_mpsc},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

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

/// How the user decided on an access request, including which caching scope to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Deny the request; do not cache anything.
    Deny,
    /// Approve using the AccessController's configured coupling mode
    /// (determined by `ApprovalCoupling` at construction time).
    ApproveDefault,
    /// Approve and cache keyed on process exe, path, and operation.
    /// Future requests from any process sharing the same executable will
    /// be auto-approved within the TTL window.
    ApproveExe,
    /// Approve and cache uncoupled; any future process hitting the same
    /// (path, operation) within the TTL will be auto-approved.
    ApproveAny,
}

impl ApprovalDecision {
    pub fn is_approved(&self) -> bool {
        match self {
            ApprovalDecision::Deny => false,
            ApprovalDecision::ApproveDefault
            | ApprovalDecision::ApproveExe
            | ApprovalDecision::ApproveAny => true,
        }
    }
}

/// A request from the FUSE filesystem to the D-Bus service,
/// asking the user for approval.
pub struct AccessRequest {
    pub request: AccessControlRequest,
    /// Sender half of the response channel. The D-Bus handler sends an
    /// `ApprovalDecision` here; it is a std (non-async) Sender so it is safe
    /// to call from async code without blocking the executor.
    pub response_tx: std_mpsc::SyncSender<ApprovalDecision>,
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
    /// Snapshot a process's identity and derive its app name from the executable path.
    pub fn snapshot(pid: u32, uid: u32) -> Option<(Self, String)> {
        // Open a pidfd before any /proc/<pid>/... reads to keep the PID alive
        // for the duration of this function.
        // Note that this is not perfect, because the process may have exited
        // and the PID could have been reused before we opened the pidfd.
        // This just protects against reuse between the two proc reads.
        let rpid = RustixPid::from_raw(pid as i32)?;
        let _pidfd = pidfd_open(rpid, PidfdFlags::empty()).ok()?;
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

/// Returns the set of operations to store in the cache when `op` is approved.
fn implied_ops(op: Operation) -> &'static [Operation] {
    match op {
        Operation::Read => &[Operation::Read],
        Operation::Write => &[Operation::Write, Operation::Read, Operation::SetAttr],
        Operation::Create => &[
            Operation::Create,
            Operation::Write,
            Operation::Read,
            Operation::SetAttr,
        ],
        Operation::SetAttr => &[Operation::SetAttr],
        Operation::Mkdir => &[Operation::SetAttr],
        Operation::Delete | Operation::Rename => &[],
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PidCacheKey {
    pub operation: Operation,
    pub identity: ProcessIdentity,
    pub mount: String,
    pub accessed_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExeCacheKey {
    pub operation: Operation,
    pub exe_path: PathBuf,
    pub mount: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AnyCacheKey {
    pub operation: Operation,
    pub mount: String,
}

/// Handle held by the FUSE filesystem to send access requests.
/// Bridges synchronous FUSE threads to the async D-Bus service.
#[derive(Debug)]
pub struct AccessController {
    request_tx: mpsc::Sender<AccessRequest>,
    timeout: Duration,
    /// How long to remember an approval.
    /// A value of `Duration::ZERO` disables caching entirely.
    approval_ttl: Duration,
    /// Whether cache hits reset the TTL timer.
    renewal: ApprovalRenewal,
    /// Coupling mode used when the GUI sends `ApproveDefault`.
    default_coupling: ApprovalCoupling,
    /// Cache keyed by (ProcessIdentity, path, operation).
    pid_cache: Mutex<HashMap<PidCacheKey, Instant>>,
    /// Cache keyed by (exe_path, path, operation).
    exe_cache: Mutex<HashMap<ExeCacheKey, Instant>>,
    /// Cache keyed by (path, operation).
    any_cache: Mutex<HashMap<AnyCacheKey, Instant>>,
}

impl AccessController {
    pub fn new(
        request_tx: mpsc::Sender<AccessRequest>,
        timeout: Duration,
        approval_ttl: Duration,
        coupling: ApprovalCoupling,
        renewal: ApprovalRenewal,
    ) -> Self {
        AccessController {
            request_tx,
            timeout,
            approval_ttl,
            renewal,
            default_coupling: coupling,
            pid_cache: Mutex::new(HashMap::new()),
            exe_cache: Mutex::new(HashMap::new()),
            any_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Return `true` if a non-expired approval is cached in any scope.
    fn check_cache(
        &self,
        identity: &ProcessIdentity,
        mount: &str,
        accessed_path: &Path,
        operation: Operation,
    ) -> bool {
        let ttl = self.approval_ttl;
        if ttl.is_zero() {
            return false;
        }
        let now = Instant::now();
        let mut approved = false;

        // Check PID-coupled cache.
        {
            let mut cache = self.pid_cache.lock().expect("Lock poisoned");
            cache.retain(|_, approved_at| approved_at.elapsed() < ttl);
            let key = PidCacheKey {
                operation,
                mount: mount.to_string(),
                identity: identity.clone(),
                accessed_path: accessed_path.to_path_buf(),
            };
            if let Entry::Occupied(mut e) = cache.entry(key) {
                if self.renewal == ApprovalRenewal::RenewOnAccess {
                    e.insert(now);
                }
                approved = true;
            }
        }

        // Check exe-coupled cache.
        {
            let mut cache = self.exe_cache.lock().expect("Lock poisoned");
            cache.retain(|_, approved_at| approved_at.elapsed() < ttl);
            let key = ExeCacheKey {
                operation,
                exe_path: identity.exe_path.clone(),
                mount: mount.to_string(),
            };
            if let Entry::Occupied(mut e) = cache.entry(key) {
                if self.renewal == ApprovalRenewal::RenewOnAccess {
                    e.insert(now);
                }
                approved = true;
            }
        }

        // Check uncoupled cache.
        {
            let mut cache = self.any_cache.lock().expect("Lock poisoned");
            cache.retain(|_, approved_at| approved_at.elapsed() < ttl);
            let key = AnyCacheKey {
                operation,
                mount: mount.to_string(),
            };
            if let Entry::Occupied(mut e) = cache.entry(key) {
                if self.renewal == ApprovalRenewal::RenewOnAccess {
                    e.insert(now);
                }
                approved = true;
            }
        }

        approved
    }

    /// Insert or refresh an approval entry based on the given decision.
    fn cache_approval(
        &self,
        decision: ApprovalDecision,
        identity: &ProcessIdentity,
        mount: &str,
        accessed_path: &Path,
        operation: Operation,
    ) {
        let ops = implied_ops(operation);
        let ttl = self.approval_ttl;
        if ttl.is_zero() || ops.is_empty() {
            return;
        }

        // Resolve ApproveDefault to the configured coupling mode.
        let decision = match decision {
            ApprovalDecision::Deny => {
                // Deny is not cached.
                return;
            }
            ApprovalDecision::ApproveDefault => match self.default_coupling {
                ApprovalCoupling::CoupledToProcess => ApprovalDecision::ApproveDefault,
                ApprovalCoupling::Uncoupled => ApprovalDecision::ApproveAny,
            },
            ApprovalDecision::ApproveExe => ApprovalDecision::ApproveExe,
            ApprovalDecision::ApproveAny => ApprovalDecision::ApproveAny,
        };

        let now = Instant::now();

        match decision {
            ApprovalDecision::ApproveDefault => {
                // CoupledToProcess: store in pid_cache.
                let mut cache = self.pid_cache.lock().expect("Lock poisoned");
                if cache.len() >= APPROVAL_CACHE_MAX_ENTRIES {
                    cache.retain(|_, approved_at| approved_at.elapsed() < ttl);
                    if cache.len() >= APPROVAL_CACHE_MAX_ENTRIES {
                        log::warn!(
                            "PID approval cache at capacity ({}), not caching for pid={}",
                            APPROVAL_CACHE_MAX_ENTRIES,
                            identity.pid,
                        );
                        return;
                    }
                }
                for &op in ops {
                    cache.insert(
                        PidCacheKey {
                            operation: op,
                            identity: identity.clone(),
                            mount: mount.to_string(),
                            accessed_path: accessed_path.to_path_buf(),
                        },
                        now,
                    );
                }
            }
            ApprovalDecision::ApproveExe => {
                let mut cache = self.exe_cache.lock().expect("Lock poisoned");
                if cache.len() >= APPROVAL_CACHE_MAX_ENTRIES {
                    cache.retain(|_, approved_at| approved_at.elapsed() < ttl);
                    if cache.len() >= APPROVAL_CACHE_MAX_ENTRIES {
                        log::warn!(
                            "Executable approval cache at capacity ({}), not caching for exe={}",
                            APPROVAL_CACHE_MAX_ENTRIES,
                            identity.exe_path.display(),
                        );
                        return;
                    }
                }
                for &op in ops {
                    cache.insert(
                        ExeCacheKey {
                            operation: op,
                            exe_path: identity.exe_path.clone(),
                            mount: mount.to_string(),
                        },
                        now,
                    );
                }
            }
            ApprovalDecision::ApproveAny => {
                let mut cache = self.any_cache.lock().expect("Lock poisoned");
                if cache.len() >= APPROVAL_CACHE_MAX_ENTRIES {
                    cache.retain(|_, approved_at| approved_at.elapsed() < ttl);
                    if cache.len() >= APPROVAL_CACHE_MAX_ENTRIES {
                        log::warn!(
                            "Uncoupled approval cache at capacity ({}), skipping entry",
                            APPROVAL_CACHE_MAX_ENTRIES,
                        );
                        return;
                    }
                }
                for &op in ops {
                    cache.insert(
                        AnyCacheKey {
                            operation: op,
                            mount: mount.to_string(),
                        },
                        now,
                    );
                }
            }
            ApprovalDecision::Deny => unreachable!("Deny handled above"),
        }
    }

    /// Send an access request and block until the user responds or timeout expires.
    /// Called from FUSE threads (synchronous context).
    pub fn request_access(
        &self,
        identity: ProcessIdentity,
        mount: &str,
        accessed_path: &Path,
        app_name: &str,
        operation: Operation,
    ) -> ah::Result<bool> {
        let pid = identity.pid;

        // Return early if a valid approval is cached.
        if self.check_cache(&identity, mount, accessed_path, operation) {
            log::debug!("Approval cache hit: pid={} op={}", pid, operation);
            return Ok(true);
        }

        let req_id = Uuid::new_v4().to_string();
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
                path: format!("[{}]/{}", mount, accessed_path.display()),
                app_name: app_name.to_string(),
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
            Ok(decision) => {
                if decision.is_approved() {
                    self.cache_approval(decision, &identity, mount, accessed_path, operation);
                }
                Ok(decision.is_approved())
            }
        }
    }
}
