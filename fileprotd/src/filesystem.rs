use crate::access_control::{AccessController, ProcessIdentity, QueueFullError};
use fileprot_common::Operation;
use fuser::{
    AccessFlags, BsdFileFlags, CopyFileRangeFlags, Errno, FileAttr, FileHandle as FuseFileHandle,
    FileType, Filesystem, FopenFlags, Generation, INodeNo, IoctlFlags, LockOwner, OpenAccMode,
    OpenFlags, PollEvents, PollFlags, PollNotifier, RenameFlags, ReplyAttr, ReplyBmap, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLock,
    ReplyLseek, ReplyOpen, ReplyPoll, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use nix::{
    fcntl::{AT_FDCWD, RenameFlags as NixRenameFlags, renameat2},
    unistd::{Gid, Uid, chown as nix_chown},
};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File, Metadata, OpenOptions, Permissions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
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
    /// Absolute path to the backing directory.
    backing_dir: PathBuf,
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
    ) -> Self {
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

        ProtectedFilesystem {
            mount_name,
            backing_dir,
            mount_uid,
            mount_gid,
            inodes: RwLock::new(inodes),
            path_to_inode: RwLock::new(path_to_inode),
            next_inode: AtomicU64::new(ROOT_INODE.0 + 1),
            open_files: RwLock::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            access_control,
        }
    }

    /// Get the absolute path in the backing directory for a relative path.
    fn backing_path(&self, rel_path: &Path) -> PathBuf {
        self.backing_dir.join(rel_path)
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

    /// Convert [`Metadata`] to [`FileAttr`].
    fn metadata_to_attr(&self, ino: INodeNo, metadata: &Metadata) -> FileAttr {
        let kind = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        FileAttr {
            ino,
            size: metadata.len(),
            blocks: metadata.blocks(),
            atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
            mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
            ctime: {
                let secs = metadata.ctime();
                let nsecs = metadata.ctime_nsec().max(0) as u32;
                if secs >= 0 {
                    UNIX_EPOCH + Duration::new(secs as u64, nsecs)
                } else {
                    // Pre-epoch ctime (e.g. on misconfigured filesystems): compute as
                    // UNIX_EPOCH - |duration|.  The kernel reports (secs, nsecs) where
                    // nsecs is always in [0, 999_999_999], so for secs=-2, nsecs=500_000_000
                    // the true offset is -1.5 s (secs+1 whole seconds before epoch,
                    // then 1e9-nsecs nanoseconds into that second).
                    let (d_secs, d_nsecs) = if nsecs == 0 {
                        ((-secs) as u64, 0u32)
                    } else {
                        ((-secs - 1) as u64, 1_000_000_000 - nsecs)
                    };
                    UNIX_EPOCH
                        .checked_sub(Duration::new(d_secs, d_nsecs))
                        .unwrap_or(UNIX_EPOCH)
                }
            },
            crtime: metadata.created().unwrap_or(UNIX_EPOCH),
            kind,
            perm: (metadata.mode() & 0o7777) as u16,
            nlink: metadata.nlink() as u32,
            uid: self.mount_uid,
            gid: self.mount_gid,
            rdev: metadata.rdev() as u32,
            blksize: metadata.blksize() as u32,
            flags: 0,
        }
    }

    /// Read metadata for a backing path and return FileAttr.
    fn stat(&self, ino: INodeNo, backing_path: &Path) -> Result<FileAttr, Errno> {
        let metadata = fs::symlink_metadata(backing_path).map_err(Errno::from)?;
        Ok(self.metadata_to_attr(ino, &metadata))
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
        let backing = self.backing_path(&child_rel);

        match fs::symlink_metadata(&backing) {
            Ok(metadata) => {
                let ino = match self.get_or_create_inode(&child_rel) {
                    Ok(i) => i,
                    Err(e) => {
                        reply.error(e);
                        return;
                    }
                };
                let attr = self.metadata_to_attr(ino, &metadata);
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

        let backing = self.backing_path(&rel_path);
        match self.stat(ino, &backing) {
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
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
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

        let backing = self.backing_path(&rel_path);

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
                match fs::symlink_metadata(&backing) {
                    Ok(m) if m.is_file() => {}
                    Ok(_) => {
                        reply.error(Errno::EINVAL);
                        return;
                    }
                    Err(e) => {
                        reply.error(Errno::from(e));
                        return;
                    }
                }
                let file = match OpenOptions::new().write(true).open(&backing) {
                    Ok(f) => f,
                    Err(e) => {
                        reply.error(Errno::from(e));
                        return;
                    }
                };
                if file.set_len(new_size).is_err() {
                    reply.error(Errno::EIO);
                    return;
                }
            }
        }

        // Handle mode change.
        if let Some(mode) = mode {
            let perms = Permissions::from_mode(mode);
            if fs::set_permissions(&backing, perms).is_err() {
                reply.error(Errno::EIO);
                return;
            }
        }

        // Handle uid/gid change.
        if uid.is_some() || gid.is_some() {
            let new_uid = uid.map(Uid::from_raw);
            let new_gid = gid.map(Gid::from_raw);
            if let Err(e) = nix_chown(backing.as_path(), new_uid, new_gid) {
                reply.error(Errno::from_i32(e as i32));
                return;
            }
        }

        // Return updated attributes.
        match self.stat(ino, &backing) {
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

        let backing = self.backing_path(&rel_path);
        let entries = match fs::read_dir(&backing) {
            Ok(e) => e,
            Err(e) => {
                reply.error(Errno::from(e));
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
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_rel = rel_path.join(&name);
            let file_type = match entry.file_type() {
                Ok(ft) => {
                    if ft.is_dir() {
                        FileType::Directory
                    } else if ft.is_symlink() {
                        FileType::Symlink
                    } else {
                        FileType::RegularFile
                    }
                }
                Err(_) => FileType::RegularFile,
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

        for (i, (entry_ino, kind, name)) in full_entries.iter().enumerate().skip(offset as usize) {
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

        let backing = self.backing_path(&rel_path);
        let mut opts = OpenOptions::new();
        match flags.acc_mode() {
            OpenAccMode::O_RDONLY => {
                opts.read(true);
            }
            OpenAccMode::O_WRONLY => {
                opts.write(true);
            }
            OpenAccMode::O_RDWR => {
                opts.read(true).write(true);
            }
        }
        if flags.0 & libc::O_APPEND != 0 {
            opts.append(true);
        }
        if flags.0 & libc::O_TRUNC != 0 {
            opts.truncate(true);
        }

        match opts.open(&backing) {
            Ok(file) => match self.alloc_fh(file, ino) {
                Some(fh) => reply.opened(fh, FopenFlags::empty()),
                None => reply.error(Errno::EMFILE),
            },
            Err(e) => {
                reply.error(Errno::from(e));
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

        let mut buf = vec![0u8; size as usize];
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

        let backing = self.backing_path(&child_rel);

        // Create the file.
        let mut opts = OpenOptions::new();
        // O_EXCL: fail if the file already exists (create_new implies create).
        if flags & libc::O_EXCL != 0 {
            opts.create_new(true).write(true);
        } else {
            opts.create(true).write(true);
        }

        let access_mode = flags & libc::O_ACCMODE;
        if access_mode == libc::O_RDWR || access_mode == libc::O_RDONLY {
            opts.read(true);
        }
        if flags & libc::O_TRUNC != 0 {
            opts.truncate(true);
        }

        match opts.open(&backing) {
            Ok(file) => {
                // Set permissions.
                let _ = fs::set_permissions(&backing, Permissions::from_mode(mode));

                let ino = match self.get_or_create_inode(&child_rel) {
                    Ok(i) => i,
                    Err(e) => {
                        reply.error(e);
                        return;
                    }
                };
                match self.alloc_fh(file, ino) {
                    Some(fh) => match self.stat(ino, &backing) {
                        Ok(attr) => {
                            reply.created(&TTL, &attr, Generation(0), fh, FopenFlags::empty())
                        }
                        Err(e) => reply.error(e),
                    },
                    None => reply.error(Errno::EMFILE),
                }
            }
            Err(e) => {
                reply.error(Errno::from(e));
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

        let backing = self.backing_path(&child_rel);
        match fs::remove_file(&backing) {
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
                reply.error(Errno::from(e));
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

        let backing = self.backing_path(&child_rel);

        match fs::create_dir(&backing) {
            Ok(()) => {
                let _ = fs::set_permissions(&backing, Permissions::from_mode(mode));

                let ino = match self.get_or_create_inode(&child_rel) {
                    Ok(i) => i,
                    Err(e) => {
                        reply.error(e);
                        return;
                    }
                };
                match self.stat(ino, &backing) {
                    Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    Err(e) => reply.error(e),
                }
            }
            Err(e) => {
                reply.error(Errno::from(e));
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

        let backing = self.backing_path(&child_rel);
        match fs::remove_dir(&backing) {
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
                reply.error(Errno::from(e));
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

        let old_backing = self.backing_path(&old_rel);
        let new_backing = self.backing_path(&new_rel);

        // Perform the rename, honouring any flags (e.g. RENAME_NOREPLACE) via
        // the renameat2 syscall so that callers get correct atomicity semantics.
        let rename_result = if flags.is_empty() {
            fs::rename(&old_backing, &new_backing)
        } else {
            let nix_flags = NixRenameFlags::from_bits_retain(flags.bits());
            renameat2(
                AT_FDCWD,
                old_backing.as_path(),
                AT_FDCWD,
                new_backing.as_path(),
                nix_flags,
            )
            .map_err(std::io::Error::from)
        };

        match rename_result {
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
            Err(e) => {
                reply.error(Errno::from(e));
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
        let backing = self.backing_path(&rel_path);
        match fs::read_link(&backing) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(e) => reply.error(Errno::from(e)),
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
