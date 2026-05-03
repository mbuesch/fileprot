use crate::access_control::{AccessController, ProcessIdentity, QueueFullError};
use anyhow::{self as ah, format_err as err};
use fileprot_common::Operation;
use fuser::{
    AccessFlags, BsdFileFlags, CopyFileRangeFlags, Errno, FileAttr, FileHandle as FuseFileHandle,
    FileType, Filesystem, FopenFlags, Generation, INodeNo, IoctlFlags, LockOwner, OpenAccMode,
    OpenFlags, PollEvents, PollFlags, PollNotifier, RenameFlags, ReplyAttr, ReplyBmap, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLock,
    ReplyLseek, ReplyOpen, ReplyPoll, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use nix::{
    fcntl::{AtFlags, OFlag, RenameFlags as NixRenameFlags, openat, readlinkat, renameat2},
    sys::{
        stat::{
            FchmodatFlags, FileStat, Mode, SFlag, UtimensatFlags, fchmodat, fstatat, futimens,
            mkdirat, utimensat,
        },
        time::TimeSpec,
    },
    unistd::{UnlinkatFlags, dup, dup3, unlinkat},
};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INODE: INodeNo = INodeNo(1);
const READ_MAX_SIZE: usize = 1024 * 1024;

/// Convert a `nix::errno::Errno` to a `fuser::Errno`.
fn errno_from_nix(e: nix::errno::Errno) -> Errno {
    Errno::from_i32(e as i32)
}

/// Validate a single path-component name received from the FUSE kernel
/// before joining it to any path.
///
/// Rejected names:
/// - empty string
/// - `.` or `..`
/// - any name containing `/` (would escape the backing directory via
///   `Path::join`, which replaces the base when the argument is absolute or
///   contains a separator)
/// - any name containing a NUL byte (would silently truncate a `CString`)
///
/// Even though the stock Linux FUSE module filters most of these cases
/// before calling the filesystem driver, the driver must not rely on that
/// behaviour for safety.
fn validate_name(name: &OsStr) -> Result<(), Errno> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." {
        return Err(Errno::EINVAL);
    }
    if bytes.contains(&b'/') || bytes.contains(&b'\0') {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Convert a FUSE `TimeOrNow` (or `None` meaning "do not change") to a `TimeSpec`
/// suitable for `utimensat`/`futimens`.
fn time_or_now_to_timespec(t: Option<TimeOrNow>) -> TimeSpec {
    match t {
        Some(TimeOrNow::SpecificTime(sys_time)) => match sys_time.duration_since(UNIX_EPOCH) {
            Ok(d) => TimeSpec::new(d.as_secs() as i64, d.subsec_nanos() as i64),
            Err(_) => TimeSpec::new(0, 0),
        },
        Some(TimeOrNow::Now) => TimeSpec::UTIME_NOW,
        None => TimeSpec::UTIME_OMIT,
    }
}

/// Data associated with a single inode.
#[derive(Debug, Clone)]
struct InodeData {
    /// Path relative to the backing directory (empty for root).
    rel_path: PathBuf,
    /// Reference count.
    ref_count: u64,
}

/// An open file handle.
struct OpenFileHandle {
    file: File,
    _inode: INodeNo,
}

pub struct ProtectedFilesystem {
    /// Name of this mount (from config).
    mount_name: String,
    /// Absolute path to the backing directory (kept for display/logging only).
    backing_dir: PathBuf,
    /// Open file descriptor for the backing directory, used for all *at syscalls.
    /// Stored in an Arc so it can be cheaply shared without copying raw fds.
    backing_dir_fd: Arc<OwnedFd>,
    /// uid that owns all entries in the virtual filesystem.
    mount_uid: u32,
    /// gid that owns all entries in the virtual filesystem.
    mount_gid: u32,
    /// Inode table: inode -> data.
    inodes: RwLock<HashMap<u64, InodeData>>,
    /// Reverse lookup: relative path -> inode number.
    path_to_inode: RwLock<HashMap<PathBuf, u64>>,
    /// Next inode number to allocate.
    next_inode: AtomicU64,
    /// Open file handles.
    open_files: RwLock<HashMap<u64, OpenFileHandle>>,
    /// Next file handle number to allocate.
    next_fh: AtomicU64,
    /// Access controller for requesting user approval.
    access_control: Arc<AccessController>,
}

impl ProtectedFilesystem {
    pub fn new(
        mount_name: String,
        backing_dir: PathBuf,
        mount_uid: u32,
        mount_gid: u32,
        access_control: Arc<AccessController>,
    ) -> ah::Result<Self> {
        let mut inodes = HashMap::new();
        let mut path_to_inode = HashMap::new();

        // Insert root inode.
        inodes.insert(
            ROOT_INODE.0,
            InodeData {
                rel_path: "".into(),
                ref_count: 1,
            },
        );
        path_to_inode.insert("".into(), ROOT_INODE.0);

        // Open the backing directory as a file descriptor rooted for all *at
        // syscalls. O_NOFOLLOW ensures we do not follow a symlink in the final
        // component of backing_dir itself. OpenOptions with custom_flags is
        // safe and avoids any unsafe code.
        let backing_file = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
            .open(&backing_dir)
            .map_err(|e| {
                err!(
                    "Failed to open backing directory '{}': {}",
                    backing_dir.display(),
                    e
                )
            })?;
        let backing_dir_fd: OwnedFd = backing_file.into();

        Ok(ProtectedFilesystem {
            mount_name,
            backing_dir,
            backing_dir_fd: Arc::new(backing_dir_fd),
            mount_uid,
            mount_gid,
            inodes: RwLock::new(inodes),
            path_to_inode: RwLock::new(path_to_inode),
            next_inode: AtomicU64::new(ROOT_INODE.0 + 1),
            open_files: RwLock::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            access_control,
        })
    }

    /// Get the absolute path in the backing directory for a relative path.
    /// Used only for display/logging, not for actual I/O.
    fn backing_path_display(&self, rel_path: &Path) -> PathBuf {
        self.backing_dir.join(rel_path)
    }

    /// Walk `rel_path` component by component starting from the backing dir fd,
    /// opening each intermediate directory with `O_PATH | O_NOFOLLOW | O_DIRECTORY`
    /// to prevent symlink escapes in any component.
    ///
    /// Returns `(parent_fd, leaf_name)` where `parent_fd` is an fd opened on
    /// the directory that contains the leaf, and `leaf_name` is the final path
    /// component as an `OsString`.
    ///
    /// For the root (empty `rel_path`) this returns a dup of the backing dir fd
    /// and an empty leaf name (the caller must handle that case).
    fn resolve_parent_fd(&self, rel_path: &Path) -> Result<(OwnedFd, OsString), nix::errno::Errno> {
        let mut components: Vec<&OsStr> = rel_path
            .components()
            .map(|c| c.as_os_str())
            .filter(|c| !c.is_empty())
            .collect();

        // Dup the backing dir fd so we can close it independently.
        let mut base_fd = dup(self.backing_dir_fd.as_fd())?;
        dup3(self.backing_dir_fd.as_fd(), &mut base_fd, OFlag::O_CLOEXEC)?;

        if components.is_empty() {
            // Caller wants the root itself; return backing dir fd + empty name.
            return Ok((base_fd, OsString::new()));
        }

        let leaf = components.pop().expect("non-empty after check").to_owned();

        let mut current_fd = base_fd;
        for component in components {
            let next_fd = openat(
                current_fd.as_fd(),
                component,
                OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?;
            current_fd = next_fd;
        }

        Ok((current_fd, leaf.to_os_string()))
    }

    /// Open a file (or directory) at `rel_path` inside the backing dir, using
    /// `*at` syscalls that never follow symlinks in any component.
    ///
    /// `flags` are passed to `openat` for the leaf; `O_NOFOLLOW` is always
    /// added automatically.  `mode` is used only when creating a new file.
    fn open_backing_at(
        &self,
        rel_path: &Path,
        flags: OFlag,
        mode: Mode,
    ) -> Result<OwnedFd, nix::errno::Errno> {
        let (parent_fd, leaf) = self.resolve_parent_fd(rel_path)?;
        if leaf.is_empty() {
            // Opening the backing dir itself.
            return openat(
                parent_fd.as_fd(),
                ".",
                (flags | OFlag::O_NOFOLLOW) & !OFlag::O_PATH,
                mode,
            );
        }
        openat(
            parent_fd.as_fd(),
            leaf.as_os_str(),
            flags | OFlag::O_NOFOLLOW,
            mode,
        )
    }

    /// `fstatat` on `rel_path` with `AT_SYMLINK_NOFOLLOW` to avoid following
    /// symlinks in any component.
    fn stat_at(&self, rel_path: &Path) -> Result<FileStat, nix::errno::Errno> {
        let (parent_fd, leaf) = self.resolve_parent_fd(rel_path)?;
        if leaf.is_empty() {
            // Root directory.
            return fstatat(parent_fd.as_fd(), ".", AtFlags::AT_SYMLINK_NOFOLLOW);
        }
        fstatat(
            parent_fd.as_fd(),
            leaf.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
    }

    /// Get the relative path for an inode.
    fn get_rel_path(&self, inode: INodeNo) -> Option<PathBuf> {
        self.inodes
            .read()
            .expect("Lock poisoned")
            .get(&inode.0)
            .map(|data| data.rel_path.clone())
    }

    /// Get or create an inode for a relative path.
    /// Returns Err(Errno::EOVERFLOW) if incrementing or allocating the inode would overflow.
    fn get_or_create_inode(&self, rel_path: &Path) -> Result<INodeNo, Errno> {
        // Fast path: check under read lock.
        {
            let path_map = self.path_to_inode.read().expect("Lock poisoned");
            if let Some(&ino) = path_map.get(rel_path) {
                // Increment reference count.
                let mut inode_map = self.inodes.write().expect("Lock poisoned");
                if let Some(data) = inode_map.get_mut(&ino) {
                    if let Some(new_ref_count) = data.ref_count.checked_add(1) {
                        data.ref_count = new_ref_count;
                    } else {
                        return Err(Errno::EOVERFLOW);
                    }
                }
                return Ok(INodeNo(ino));
            }
        }

        // Slow path: re-check under a write lock on path_to_inode before inserting.
        // Without this re-check, two concurrent lookups for the same new path both
        // miss the read-lock check above, both allocate a fresh inode number, and
        // both insert - the second path_map.insert then silently overwrites the first
        // entry in path_to_inode, leaving the first inode orphaned in inodes (present
        // with no reverse mapping) while already returned to the kernel.
        let mut path_map = self.path_to_inode.write().expect("Lock poisoned");
        if let Some(&ino) = path_map.get(rel_path) {
            let mut inode_map = self.inodes.write().expect("Lock poisoned");
            if let Some(data) = inode_map.get_mut(&ino) {
                if let Some(new_ref_count) = data.ref_count.checked_add(1) {
                    data.ref_count = new_ref_count;
                } else {
                    return Err(Errno::EOVERFLOW);
                }
            }
            return Ok(INodeNo(ino));
        }

        // Allocate new inode, ensuring we do not overflow the counter.
        // path_map write lock is held from the re-check above through the insert
        // below, so no concurrent lookup can sneak in between.
        let ino = self
            .next_inode
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |curr| {
                curr.checked_add(1)
            })
            .map_err(|_| Errno::EOVERFLOW)?;

        let mut inode_map = self.inodes.write().expect("Lock poisoned");
        inode_map.insert(
            ino,
            InodeData {
                rel_path: rel_path.to_owned(),
                ref_count: 1,
            },
        );
        path_map.insert(rel_path.to_owned(), ino);
        Ok(INodeNo(ino))
    }

    /// Convert a [`nix::sys::stat::FileStat`] (from `fstatat`) to [`FileAttr`].
    fn stat_to_attr(&self, ino: INodeNo, st: &FileStat) -> FileAttr {
        let mode = SFlag::from_bits_truncate(st.st_mode);
        let kind = if mode.contains(SFlag::S_IFDIR) {
            FileType::Directory
        } else if mode.contains(SFlag::S_IFLNK) {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        fn ts_to_systime(secs: i64, nsecs: i64) -> std::time::SystemTime {
            let nsecs = nsecs.max(0) as u32;
            if secs >= 0 {
                UNIX_EPOCH + Duration::new(secs as u64, nsecs)
            } else {
                // Pre-epoch timestamp: compute as UNIX_EPOCH - |duration|.
                // The kernel reports (secs, nsecs) where nsecs is always in
                // [0, 999_999_999], so for secs=-2, nsecs=500_000_000 the
                // true offset is -1.5 s.
                let (d_secs, d_nsecs) = if nsecs == 0 {
                    ((-secs) as u64, 0u32)
                } else {
                    ((-secs - 1) as u64, 1_000_000_000 - nsecs)
                };
                UNIX_EPOCH
                    .checked_sub(Duration::new(d_secs, d_nsecs))
                    .unwrap_or(UNIX_EPOCH)
            }
        }

        FileAttr {
            ino,
            size: st.st_size as u64,
            blocks: st.st_blocks as u64,
            atime: ts_to_systime(st.st_atime, st.st_atime_nsec),
            mtime: ts_to_systime(st.st_mtime, st.st_mtime_nsec),
            ctime: ts_to_systime(st.st_ctime, st.st_ctime_nsec),
            crtime: UNIX_EPOCH,
            kind,
            perm: (st.st_mode & 0o7777) as u16,
            nlink: st.st_nlink as u32,
            uid: self.mount_uid,
            gid: self.mount_gid,
            rdev: st.st_rdev as u32,
            blksize: st.st_blksize as u32,
            flags: 0,
        }
    }

    /// Stat `rel_path` (no symlink follow) and return FileAttr.
    fn stat(&self, ino: INodeNo, rel_path: &Path) -> Result<FileAttr, Errno> {
        let st = self.stat_at(rel_path).map_err(errno_from_nix)?;
        Ok(self.stat_to_attr(ino, &st))
    }

    /// Allocate a new file handle.
    fn alloc_fh(&self, file: File, inode: INodeNo) -> Option<FuseFileHandle> {
        let fh = self
            .next_fh
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .ok()?;
        self.open_files.write().expect("Lock poisoned").insert(
            fh,
            OpenFileHandle {
                file,
                _inode: inode,
            },
        );
        Some(FuseFileHandle(fh))
    }

    /// Request access approval from the user.
    fn request_access(
        &self,
        req: &Request,
        rel_path: &Path,
        operation: Operation,
    ) -> Result<bool, Errno> {
        let pid = req.pid();
        let uid = req.uid();
        // Snapshot the process identity and derive the app name in a single
        // coherent read to minimise the PID-reuse race window. If the
        // process has already exited we deny access rather than prompting with
        // stale or mismatched information.
        let (identity, app_name) = match ProcessIdentity::snapshot(pid, uid) {
            Some(s) => s,
            None => {
                log::warn!(
                    "Cannot snapshot pid={}: process has exited, denying access",
                    pid
                );
                return Ok(false);
            }
        };
        let rel_path_str = rel_path.to_str().ok_or(Errno::EINVAL)?;
        let display_path = format!("[{}]/{}", self.mount_name, rel_path_str);

        log::info!(
            "Access request: pid={} app='{}' path='{}' op={}",
            pid,
            app_name,
            display_path,
            operation
        );

        match self.access_control.request_access(
            identity,
            display_path.clone(),
            app_name,
            operation,
        ) {
            Ok(approved) => {
                log::info!("Access {}", if approved { "APPROVED" } else { "DENIED" });
                Ok(approved)
            }
            Err(e) => {
                if e.is::<QueueFullError>() {
                    log::warn!(
                        "Access request queue full: pid={} path='{}' op={} - returning EBUSY",
                        pid,
                        display_path,
                        operation
                    );
                    Err(Errno::EBUSY)
                } else {
                    log::error!("Access request failed: {}. Denying.", e);
                    Ok(false)
                }
            }
        }
    }
}

impl Filesystem for ProtectedFilesystem {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if let Err(e) = validate_name(name) {
            reply.error(e);
            return;
        }

        let parent_path = match self.get_rel_path(parent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let child_rel = parent_path.join(name);

        match self.stat_at(&child_rel) {
            Ok(st) => {
                let ino = match self.get_or_create_inode(&child_rel) {
                    Ok(i) => i,
                    Err(e) => {
                        reply.error(e);
                        return;
                    }
                };
                let attr = self.stat_to_attr(ino, &st);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(_) => {
                reply.error(Errno::ENOENT);
            }
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let mut path_map = self.path_to_inode.write().expect("Lock poisoned");
        let mut inode_map = self.inodes.write().expect("Lock poisoned");

        let remove = if let Some(data) = inode_map.get_mut(&ino.0) {
            if nlookup > data.ref_count {
                log::warn!(
                    "forget: inode {} nlookup underflow: requested {} but ref_count is {} (mount '{}')",
                    ino.0,
                    nlookup,
                    data.ref_count,
                    self.mount_name,
                );
            }
            data.ref_count = data.ref_count.saturating_sub(nlookup);
            data.ref_count == 0 && ino != ROOT_INODE
        } else {
            false
        };
        if remove && let Some(data) = inode_map.remove(&ino.0) {
            // Only remove from path_to_inode if the entry still points to
            // this inode. After unlink/rmdir the path entry is already
            // gone; after a new file is created at the same path the entry
            // maps to the new inode and must not be disturbed.
            if path_map.get(&data.rel_path) == Some(&ino.0) {
                path_map.remove(&data.rel_path);
            }
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FuseFileHandle>, reply: ReplyAttr) {
        let rel_path = match self.get_rel_path(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let backing = self.backing_path_display(&rel_path);
        let _ = backing; // used for display only
        match self.stat(ino, &rel_path) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FuseFileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let rel_path = match self.get_rel_path(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        // Request access approval for setattr.
        match self.request_access(req, &rel_path, Operation::SetAttr) {
            Err(e) => {
                reply.error(e);
                return;
            }
            Ok(false) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(true) => {}
        }

        let backing_display = self.backing_path_display(&rel_path);
        let _ = backing_display;

        // Handle truncation.
        if let Some(new_size) = size {
            if let Some(fh_id) = fh {
                let files = self.open_files.read().expect("Lock poisoned");
                if let Some(handle) = files.get(&fh_id.0)
                    && handle.file.set_len(new_size).is_err()
                {
                    reply.error(Errno::EIO);
                    return;
                }
            } else {
                // Only regular files can be truncated via open-for-write.
                // Directories and symlinks must not be opened this way.
                let st = match self.stat_at(&rel_path) {
                    Ok(s) => s,
                    Err(e) => {
                        reply.error(errno_from_nix(e));
                        return;
                    }
                };
                if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                    reply.error(Errno::EINVAL);
                    return;
                }
                let fd = match self.open_backing_at(
                    &rel_path,
                    OFlag::O_WRONLY | OFlag::O_CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(f) => f,
                    Err(e) => {
                        reply.error(errno_from_nix(e));
                        return;
                    }
                };
                // File::from(OwnedFd) is a safe conversion.
                let file = File::from(fd);
                if file.set_len(new_size).is_err() {
                    reply.error(Errno::EIO);
                    return;
                }
            }
        }

        // Handle mode change.
        if let Some(mode) = mode {
            let (parent_fd, leaf) = match self.resolve_parent_fd(&rel_path) {
                Ok(r) => r,
                Err(e) => {
                    reply.error(errno_from_nix(e));
                    return;
                }
            };
            let leaf_path = if leaf.is_empty() {
                std::ffi::OsString::from(".")
            } else {
                leaf
            };
            let nix_mode = Mode::from_bits_truncate(mode);
            if fchmodat(
                parent_fd.as_fd(),
                leaf_path.as_os_str(),
                nix_mode,
                FchmodatFlags::FollowSymlink,
            )
            .is_err()
            {
                reply.error(Errno::EIO);
                return;
            }
        }

        // Handle uid/gid change.
        // Backing files are always owned by root on disk. The virtual filesystem
        // presents mount_uid/mount_gid to callers. Only "changes" that target
        // exactly mount_uid/mount_gid are accepted (they are no-ops on disk).
        // Any attempt to change to a different uid/gid is rejected with EPERM.
        if uid.is_some() || gid.is_some() {
            let requested_uid = uid.unwrap_or(self.mount_uid);
            let requested_gid = gid.unwrap_or(self.mount_gid);
            if requested_uid != self.mount_uid || requested_gid != self.mount_gid {
                reply.error(Errno::EPERM);
                return;
            }
            // Requested uid/gid match mount_uid/mount_gid; no disk change needed.
        }

        // Handle atime/mtime change.
        // ctime cannot be set directly on Linux (kernel manages it); ignore _ctime.
        // BSD flags (_flags, _crtime, _chgtime, _bkuptime) are not applicable on Linux; ignore.
        if atime.is_some() || mtime.is_some() {
            let ts_atime = time_or_now_to_timespec(atime);
            let ts_mtime = time_or_now_to_timespec(mtime);
            if let Some(fh_id) = fh {
                let files = self.open_files.read().expect("Lock poisoned");
                if let Some(handle) = files.get(&fh_id.0)
                    && let Err(e) = futimens(handle.file.as_fd(), &ts_atime, &ts_mtime)
                {
                    reply.error(errno_from_nix(e));
                    return;
                }
            } else {
                let (parent_fd, leaf) = match self.resolve_parent_fd(&rel_path) {
                    Ok(r) => r,
                    Err(e) => {
                        reply.error(errno_from_nix(e));
                        return;
                    }
                };
                let leaf_path = if leaf.is_empty() {
                    OsString::from(".")
                } else {
                    leaf
                };
                if let Err(e) = utimensat(
                    parent_fd.as_fd(),
                    leaf_path.as_os_str(),
                    &ts_atime,
                    &ts_mtime,
                    UtimensatFlags::NoFollowSymlink,
                ) {
                    reply.error(errno_from_nix(e));
                    return;
                }
            }
        }

        // Return updated attributes.
        match self.stat(ino, &rel_path) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FuseFileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let rel_path = match self.get_rel_path(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let backing = self.backing_path_display(&rel_path);
        let _ = backing;
        // Open the directory safely via *at to avoid following symlinks in
        // any intermediate component of the path.
        let dir_fd = match self.open_backing_at(
            &rel_path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                reply.error(errno_from_nix(e));
                return;
            }
        };
        let dir = match nix::dir::Dir::from_fd(dir_fd) {
            Ok(d) => d,
            Err(e) => {
                reply.error(errno_from_nix(e));
                return;
            }
        };

        // Collect raw directory entries without holding any inode-table lock.
        // Inode numbers in readdir are informational (d_ino); the kernel will
        // call lookup() if it needs a persistent inode.  We therefore look up
        // existing inodes under a single read lock and use INodeNo(0) for
        // entries not yet known, avoiding per-entry write-lock acquisition and
        // the associated stall / leak risk on EOVERFLOW.
        struct RawEntry {
            name: String,
            child_rel: PathBuf,
            file_type: FileType,
        }
        let mut raw: Vec<RawEntry> = vec![];
        for entry in dir.into_iter().flatten() {
            let name_cstr = entry.file_name();
            let name_os = OsStr::from_bytes(name_cstr.to_bytes());
            // Skip . and .. - we add them ourselves below.
            if name_os == "." || name_os == ".." {
                continue;
            }
            let name = name_os.to_string_lossy().into_owned();
            let child_rel = rel_path.join(&name);
            let file_type = match entry.file_type() {
                Some(ft) => match ft {
                    nix::dir::Type::Directory => FileType::Directory,
                    nix::dir::Type::Symlink => FileType::Symlink,
                    _ => FileType::RegularFile,
                },
                None => FileType::RegularFile,
            };
            raw.push(RawEntry {
                name,
                child_rel,
                file_type,
            });
        }

        // Resolve inode numbers under a single read lock snapshot.
        let mut full_entries: Vec<(INodeNo, FileType, String)> = vec![];
        full_entries.push((ino, FileType::Directory, ".".to_string()));
        {
            let path_map = self.path_to_inode.read().expect("Lock poisoned");
            let parent_ino = if ino == ROOT_INODE {
                ROOT_INODE
            } else {
                let parent_rel = rel_path.parent().unwrap_or(Path::new(""));
                path_map
                    .get(parent_rel)
                    .map(|&v| INodeNo(v))
                    .unwrap_or(ROOT_INODE)
            };
            full_entries.push((parent_ino, FileType::Directory, "..".to_string()));
            for e in raw {
                let child_ino = path_map
                    .get(&e.child_rel)
                    .map(|&v| INodeNo(v))
                    .unwrap_or(INodeNo(0));
                full_entries.push((child_ino, e.file_type, e.name));
            }
        }

        let offset: usize = match offset.try_into() {
            Ok(v) => v,
            Err(_) => {
                reply.error(Errno::EOVERFLOW);
                return;
            }
        };
        for (i, (entry_ino, kind, name)) in full_entries.iter().enumerate().skip(offset) {
            if reply.add(*entry_ino, (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let rel_path = match self.get_rel_path(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        // Determine operation type from flags.
        let operation = match flags.acc_mode() {
            OpenAccMode::O_RDONLY => Operation::Read,
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR => Operation::Write,
        };

        // Request access approval.
        match self.request_access(req, &rel_path, operation) {
            Err(e) => {
                reply.error(e);
                return;
            }
            Ok(false) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(true) => {}
        }

        let backing_display = self.backing_path_display(&rel_path);
        let _ = backing_display;
        let mut open_flags = match flags.acc_mode() {
            OpenAccMode::O_RDONLY => OFlag::O_RDONLY,
            OpenAccMode::O_WRONLY => OFlag::O_WRONLY,
            OpenAccMode::O_RDWR => OFlag::O_RDWR,
        };
        if flags.0 & libc::O_APPEND != 0 {
            open_flags |= OFlag::O_APPEND;
        }
        if flags.0 & libc::O_TRUNC != 0 {
            open_flags |= OFlag::O_TRUNC;
        }
        open_flags |= OFlag::O_CLOEXEC;

        match self.open_backing_at(&rel_path, open_flags, Mode::empty()) {
            Ok(owned_fd) => {
                let file = File::from(owned_fd);
                match self.alloc_fh(file, ino) {
                    Some(fh) => reply.opened(fh, FopenFlags::empty()),
                    None => reply.error(Errno::EMFILE),
                }
            }
            Err(e) => {
                reply.error(errno_from_nix(e));
            }
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FuseFileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let size: usize = size.try_into().unwrap_or(READ_MAX_SIZE);
        let size = size.min(READ_MAX_SIZE);
        if size == 0 {
            reply.data(&[]);
            return;
        }

        let mut files = self.open_files.write().expect("Lock poisoned");
        let handle = match files.get_mut(&fh.0) {
            Some(h) => h,
            None => {
                reply.error(Errno::EBADF);
                return;
            }
        };

        if handle.file.seek(SeekFrom::Start(offset)).is_err() {
            reply.error(Errno::EIO);
            return;
        }

        let mut buf = vec![0u8; size];
        match handle.file.read(&mut buf) {
            Ok(n) => {
                reply.data(&buf[..n]);
            }
            Err(e) => {
                reply.error(Errno::from(e));
            }
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FuseFileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if data.is_empty() {
            reply.written(0);
            return;
        }

        let mut files = self.open_files.write().expect("Lock poisoned");
        let handle = match files.get_mut(&fh.0) {
            Some(h) => h,
            None => {
                reply.error(Errno::EBADF);
                return;
            }
        };

        if handle.file.seek(SeekFrom::Start(offset)).is_err() {
            reply.error(Errno::EIO);
            return;
        }

        match handle.file.write(data) {
            Ok(n) => {
                reply.written(n as u32);
            }
            Err(e) => {
                reply.error(Errno::from(e));
            }
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FuseFileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let mut files = self.open_files.write().expect("Lock poisoned");
        if let Some(handle) = files.get_mut(&fh.0) {
            let _ = handle.file.flush();
        }
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FuseFileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let files = self.open_files.read().expect("Lock poisoned");
        if let Some(handle) = files.get(&fh.0) {
            let _ = handle.file.sync_all();
        }
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FuseFileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.open_files
            .write()
            .expect("Lock poisoned")
            .remove(&fh.0);
        reply.ok();
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if let Err(e) = validate_name(name) {
            reply.error(e);
            return;
        }

        let parent_path = match self.get_rel_path(parent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let child_rel = parent_path.join(name);

        // Request access approval for create.
        match self.request_access(req, &child_rel, Operation::Create) {
            Err(e) => {
                reply.error(e);
                return;
            }
            Ok(false) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(true) => {}
        }

        let backing_display = self.backing_path_display(&child_rel);
        let _ = backing_display;

        // Create the file using openat with O_NOFOLLOW to prevent following
        // symlinks in the leaf component.
        // Start with O_CREAT | O_CLOEXEC and apply the caller's exact access
        // mode so we never upgrade O_RDONLY to O_RDWR.
        let mut create_flags = OFlag::O_CREAT | OFlag::O_CLOEXEC;
        let access_mode = flags & libc::O_ACCMODE;
        if access_mode == libc::O_RDONLY {
            create_flags |= OFlag::O_RDONLY;
        } else if access_mode == libc::O_WRONLY {
            create_flags |= OFlag::O_WRONLY;
        } else {
            // O_RDWR or unrecognised - default to O_RDWR.
            create_flags |= OFlag::O_RDWR;
        }
        if flags & libc::O_EXCL != 0 {
            create_flags |= OFlag::O_EXCL;
        }
        if flags & libc::O_TRUNC != 0 {
            create_flags |= OFlag::O_TRUNC;
        }
        let create_mode = Mode::from_bits_truncate(mode);

        match self.open_backing_at(&child_rel, create_flags, create_mode) {
            Ok(owned_fd) => {
                let file = File::from(owned_fd);

                let ino = match self.get_or_create_inode(&child_rel) {
                    Ok(i) => i,
                    Err(e) => {
                        reply.error(e);
                        return;
                    }
                };
                match self.alloc_fh(file, ino) {
                    Some(fh) => match self.stat(ino, &child_rel) {
                        Ok(attr) => {
                            reply.created(&TTL, &attr, Generation(0), fh, FopenFlags::empty())
                        }
                        Err(e) => reply.error(e),
                    },
                    None => reply.error(Errno::EMFILE),
                }
            }
            Err(e) => {
                reply.error(errno_from_nix(e));
            }
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(e) = validate_name(name) {
            reply.error(e);
            return;
        }

        let parent_path = match self.get_rel_path(parent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let child_rel = parent_path.join(name);

        // Request access approval for delete.
        match self.request_access(req, &child_rel, Operation::Delete) {
            Err(e) => {
                reply.error(e);
                return;
            }
            Ok(false) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(true) => {}
        }

        let (parent_fd, leaf) = match self.resolve_parent_fd(&child_rel) {
            Ok(r) => r,
            Err(e) => {
                reply.error(errno_from_nix(e));
                return;
            }
        };
        match unlinkat(
            parent_fd.as_fd(),
            leaf.as_os_str(),
            UnlinkatFlags::NoRemoveDir,
        ) {
            Ok(()) => {
                // Remove from the path table so new lookups start fresh, but
                // do NOT remove from the inode table yet - the kernel may still
                // hold a reference count on the inode (e.g. via open file
                // handles). The FUSE protocol guarantees forget() will be
                // called once the lookup count reaches zero.
                self.path_to_inode
                    .write()
                    .expect("Lock poisoned")
                    .remove(&child_rel);
                reply.ok();
            }
            Err(e) => {
                reply.error(errno_from_nix(e));
            }
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if let Err(e) = validate_name(name) {
            reply.error(e);
            return;
        }

        let parent_path = match self.get_rel_path(parent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let child_rel = parent_path.join(name);

        // Request access approval for mkdir.
        match self.request_access(req, &child_rel, Operation::Mkdir) {
            Err(e) => {
                reply.error(e);
                return;
            }
            Ok(false) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(true) => {}
        }

        let nix_mode = Mode::from_bits_truncate(mode);
        let (parent_fd, leaf) = match self.resolve_parent_fd(&child_rel) {
            Ok(r) => r,
            Err(e) => {
                reply.error(errno_from_nix(e));
                return;
            }
        };
        match mkdirat(parent_fd.as_fd(), leaf.as_os_str(), nix_mode) {
            Ok(()) => {
                let ino = match self.get_or_create_inode(&child_rel) {
                    Ok(i) => i,
                    Err(e) => {
                        reply.error(e);
                        return;
                    }
                };
                match self.stat(ino, &child_rel) {
                    Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    Err(e) => reply.error(e),
                }
            }
            Err(e) => {
                reply.error(errno_from_nix(e));
            }
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(e) = validate_name(name) {
            reply.error(e);
            return;
        }

        let parent_path = match self.get_rel_path(parent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let child_rel = parent_path.join(name);

        // Request access approval for delete.
        match self.request_access(req, &child_rel, Operation::Delete) {
            Err(e) => {
                reply.error(e);
                return;
            }
            Ok(false) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(true) => {}
        }

        let (parent_fd, leaf) = match self.resolve_parent_fd(&child_rel) {
            Ok(r) => r,
            Err(e) => {
                reply.error(errno_from_nix(e));
                return;
            }
        };
        match unlinkat(
            parent_fd.as_fd(),
            leaf.as_os_str(),
            UnlinkatFlags::RemoveDir,
        ) {
            Ok(()) => {
                // Remove from the path table so new lookups start fresh, but
                // do NOT remove from the inode table yet - see unlink.
                self.path_to_inode
                    .write()
                    .expect("Lock poisoned")
                    .remove(&child_rel);
                reply.ok();
            }
            Err(e) => {
                reply.error(errno_from_nix(e));
            }
        }
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if let Err(e) = validate_name(name) {
            reply.error(e);
            return;
        }
        if let Err(e) = validate_name(newname) {
            reply.error(e);
            return;
        }

        // RENAME_EXCHANGE requires atomically swapping two existing paths, which
        // cannot be expressed through a simple fs::rename.  Return EOPNOTSUPP so
        // callers get a clear error rather than a silent wrong-behaviour rename.
        if flags.contains(RenameFlags::RENAME_EXCHANGE) {
            reply.error(Errno::EOPNOTSUPP);
            return;
        }

        let parent_path = match self.get_rel_path(parent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let new_parent_path = match self.get_rel_path(newparent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let old_rel = parent_path.join(name);
        let new_rel = new_parent_path.join(newname);

        // Request access approval for rename.
        match self.request_access(req, &old_rel, Operation::Rename) {
            Err(e) => {
                reply.error(e);
                return;
            }
            Ok(false) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(true) => {}
        }

        let old_backing_display = self.backing_path_display(&old_rel);
        let new_backing_display = self.backing_path_display(&new_rel);
        let _ = (old_backing_display, new_backing_display);

        // Resolve parent fds for both old and new paths to perform
        // renameat2 without following any symlinks in intermediate components.
        let (old_parent_fd, old_leaf) = match self.resolve_parent_fd(&old_rel) {
            Ok(r) => r,
            Err(e) => {
                reply.error(errno_from_nix(e));
                return;
            }
        };
        let (new_parent_fd, new_leaf) = match self.resolve_parent_fd(&new_rel) {
            Ok(r) => r,
            Err(e) => {
                reply.error(errno_from_nix(e));
                return;
            }
        };

        // Perform the rename, honouring any flags (e.g. RENAME_NOREPLACE) via
        // the renameat2 syscall so that callers get correct atomicity semantics.
        let nix_flags = NixRenameFlags::from_bits_retain(flags.bits());
        let rename_result = renameat2(
            old_parent_fd.as_fd(),
            old_leaf.as_os_str(),
            new_parent_fd.as_fd(),
            new_leaf.as_os_str(),
            nix_flags,
        );

        match rename_result {
            Err(e) => {
                reply.error(errno_from_nix(e));
            }
            Ok(()) => {
                let mut path_map = self.path_to_inode.write().expect("Lock poisoned");
                let mut inode_map = self.inodes.write().expect("Lock poisoned");

                // Update the renamed entry itself.
                if let Some(ino) = path_map.remove(&old_rel) {
                    path_map.insert(new_rel.clone(), ino);
                    if let Some(data) = inode_map.get_mut(&ino) {
                        data.rel_path = new_rel.clone();
                    }
                }

                // Rewrite cached paths for all descendants of a renamed
                // directory so that stale rel_paths do not silently target
                // the wrong backing location.
                let descendants: Vec<(PathBuf, u64)> = path_map
                    .iter()
                    .filter(|(path, _)| path.starts_with(&old_rel))
                    .map(|(path, &ino)| (path.clone(), ino))
                    .collect();
                for (old_path, ino) in descendants {
                    let suffix = old_path
                        .strip_prefix(&old_rel)
                        .expect("filtered by starts_with");
                    let new_path = new_rel.join(suffix);
                    path_map.remove(&old_path);
                    path_map.insert(new_path.clone(), ino);
                    if let Some(data) = inode_map.get_mut(&ino) {
                        data.rel_path = new_path;
                    }
                }

                reply.ok();
            }
        }
    }

    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, _size: u32, reply: ReplyXattr) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let rel_path = match self.get_rel_path(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let backing = self.backing_path_display(&rel_path);
        let _ = backing;
        let (parent_fd, leaf) = match self.resolve_parent_fd(&rel_path) {
            Ok(r) => r,
            Err(e) => {
                reply.error(errno_from_nix(e));
                return;
            }
        };
        let leaf_path = if leaf.is_empty() {
            OsString::from(".")
        } else {
            leaf
        };
        match readlinkat(parent_fd.as_fd(), leaf_path.as_os_str()) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(e) => reply.error(errno_from_nix(e)),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn symlink(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _link_name: &OsStr,
        _target: &Path,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn setxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        reply.ok();
    }

    fn getlk(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FuseFileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn setlk(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FuseFileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        _sleep: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn bmap(&self, _req: &Request, _ino: INodeNo, _blocksize: u32, _idx: u64, reply: ReplyBmap) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn ioctl(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FuseFileHandle,
        _flags: IoctlFlags,
        _cmd: u32,
        _in_data: &[u8],
        _out_size: u32,
        reply: ReplyIoctl,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn poll(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FuseFileHandle,
        _ph: PollNotifier,
        _events: PollEvents,
        _flags: PollFlags,
        reply: ReplyPoll,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn fallocate(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FuseFileHandle,
        _offset: u64,
        _length: u64,
        _mode: i32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn lseek(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FuseFileHandle,
        _offset: i64,
        _whence: i32,
        reply: ReplyLseek,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn copy_file_range(
        &self,
        _req: &Request,
        _ino_in: INodeNo,
        _fh_in: FuseFileHandle,
        _offset_in: u64,
        _ino_out: INodeNo,
        _fh_out: FuseFileHandle,
        _offset_out: u64,
        _len: u64,
        _flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn readdirplus(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FuseFileHandle,
        _offset: u64,
        reply: ReplyDirectoryPlus,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FuseFileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }
}
