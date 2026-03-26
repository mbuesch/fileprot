use crate::access_control::AccessController;
use fileprot_common::{Operation, resolve_app_name};
use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle as FuseFileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
    WriteFlags,
};
use std::{
    collections::HashMap,
    ffi::{CString, OsStr},
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
        // Check if inode already exists.
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

        // Allocate new inode, ensuring we do not overflow the counter.
        let ino = self
            .next_inode
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |curr| {
                curr.checked_add(1)
            })
            .map_err(|_| Errno::EOVERFLOW)?;

        let mut inode_map = self.inodes.write().expect("Lock poisoned");
        let mut path_map = self.path_to_inode.write().expect("Lock poisoned");
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
            ctime: UNIX_EPOCH + Duration::from_secs(metadata.ctime() as u64),
            crtime: metadata.created().unwrap_or(UNIX_EPOCH),
            kind,
            perm: (metadata.mode() & 0o7777) as u16,
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
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
        let app_name = resolve_app_name(pid).map_err(|_| Errno::EIO)?;
        let rel_path_str = rel_path.to_str().ok_or(Errno::EINVAL)?;
        let display_path = format!("[{}]/{}", self.mount_name, rel_path_str);

        log::info!(
            "Access request: pid={} app='{}' path='{}' op={}",
            pid,
            app_name,
            display_path,
            operation
        );

        match self
            .access_control
            .request_access(pid, display_path, app_name, operation)
        {
            Ok(approved) => {
                log::info!("Access {}", if approved { "APPROVED" } else { "DENIED" });
                Ok(approved)
            }
            Err(e) => {
                log::error!("Access request failed: {}. Denying.", e);
                Ok(false)
            }
        }
    }
}

impl Filesystem for ProtectedFilesystem {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
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
        let mut inode_map = self.inodes.write().expect("Lock poisoned");
        let remove = if let Some(data) = inode_map.get_mut(&ino.0) {
            data.ref_count = data.ref_count.saturating_sub(nlookup);
            data.ref_count == 0 && ino != ROOT_INODE
        } else {
            false
        };
        if remove && let Some(data) = inode_map.remove(&ino.0) {
            self.path_to_inode
                .write()
                .expect("Lock poisoned")
                .remove(&data.rel_path);
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
            let path_cstr = CString::new(backing.as_os_str().as_bytes()).unwrap();
            let new_uid = uid.map(|u| u as libc::uid_t).unwrap_or(u32::MAX);
            let new_gid = gid.map(|g| g as libc::gid_t).unwrap_or(u32::MAX);
            let ret = unsafe { libc::chown(path_cstr.as_ptr(), new_uid, new_gid) };
            if ret != 0 {
                reply.error(Errno::from(std::io::Error::last_os_error()));
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

        let mut full_entries: Vec<(INodeNo, FileType, String)> = vec![];

        // Add . and ..
        full_entries.push((ino, FileType::Directory, ".".to_string()));
        let parent_ino = if ino == ROOT_INODE {
            ROOT_INODE
        } else {
            let parent_rel = rel_path.parent().unwrap_or(Path::new(""));
            self.path_to_inode
                .read()
                .expect("Lock poisoned")
                .get(parent_rel)
                .map(|&v| INodeNo(v))
                .unwrap_or(ROOT_INODE)
        };
        full_entries.push((parent_ino, FileType::Directory, "..".to_string()));

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_rel = rel_path.join(&name);
            let child_ino = match self.get_or_create_inode(&child_rel) {
                Ok(i) => i,
                Err(e) => {
                    reply.error(e);
                    return;
                }
            };
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
            full_entries.push((child_ino, file_type, name));
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
        opts.create(true).write(true);

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
                let mut path_map = self.path_to_inode.write().expect("Lock poisoned");
                if let Some(ino) = path_map.remove(&child_rel) {
                    self.inodes.write().expect("Lock poisoned").remove(&ino);
                }
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
                let mut path_map = self.path_to_inode.write().expect("Lock poisoned");
                if let Some(ino) = path_map.remove(&child_rel) {
                    self.inodes.write().expect("Lock poisoned").remove(&ino);
                }
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
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
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

        match fs::rename(&old_backing, &new_backing) {
            Ok(()) => {
                let mut path_map = self.path_to_inode.write().expect("Lock poisoned");
                if let Some(ino) = path_map.remove(&old_rel) {
                    path_map.insert(new_rel.clone(), ino);
                    self.inodes
                        .write()
                        .expect("Lock poisoned")
                        .get_mut(&ino)
                        .unwrap()
                        .rel_path = new_rel;
                }
                reply.ok();
            }
            Err(e) => {
                reply.error(Errno::from(e));
            }
        }
    }
}
