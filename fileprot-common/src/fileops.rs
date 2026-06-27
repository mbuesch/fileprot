use anyhow::{self as ah, format_err as err};
use nix::{
    fcntl::{AtFlags, OFlag, open, openat},
    sys::stat::{FileStat, Mode, fstatat},
};
use std::{
    os::fd::{AsFd, OwnedFd},
    path::{Component, Path},
};

/// Open `path` with `O_PATH | O_CLOEXEC`.
pub fn open_o_path(path: &Path) -> ah::Result<OwnedFd> {
    open(path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
        .map_err(|e| err!("Failed to open '{}' with O_PATH: {}", path.display(), e))
}

/// Walk every component of `path` with
/// `O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, so that no intermediate
/// symlink is ever followed.  Returns an `OwnedFd` for the final directory.
///
/// Only absolute paths whose components are all `Normal` (no `..`, no `.`,
/// no embedded separators) are accepted; anything else is rejected to prevent
/// accidental escape from the expected tree.
pub fn open_dir_components(path: &Path) -> ah::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(err!(
            "Path '{}' is not absolute; refusing to walk components",
            path.display()
        ));
    }
    // Start from "/"; the VFS root is always trusted.
    let mut current: OwnedFd = open(
        Path::new("/"),
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| err!("Failed to open '/': {}", e))?;

    for component in path.components() {
        match component {
            Component::RootDir => {
                // Already opened above; nothing to do for the root separator.
            }
            Component::Normal(name) => {
                let next = openat(
                    current.as_fd(),
                    name,
                    OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| {
                    err!(
                        "Failed to open directory component '{}' of '{}': {}",
                        name.to_string_lossy(),
                        path.display(),
                        e
                    )
                })?;
                current = next;
            }
            other => {
                return Err(err!(
                    "Unsupported path component '{:?}' in '{}'; \
                     path must be absolute with no '..' components",
                    other,
                    path.display()
                ));
            }
        }
    }
    Ok(current)
}

/// Return `(st_dev, st_ino)` for the directory referenced by `fd`.
pub fn fd_id(fd: impl AsFd) -> ah::Result<(u64, u64)> {
    let st: FileStat =
        fstatat(fd, ".", AtFlags::empty()).map_err(|e| err!("fstatat failed: {}", e))?;
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Return `true` if the directory referred to by `child_fd` is the same as,
/// or is a descendant of, the directory identified by `ancestor_id`.
pub fn is_fd_inside(child_fd: OwnedFd, ancestor_id: (u64, u64)) -> ah::Result<bool> {
    let mut current = child_fd;
    loop {
        let cur_id = fd_id(current.as_fd())?;
        if cur_id == ancestor_id {
            return Ok(true);
        }
        let parent = openat(
            current.as_fd(),
            "..",
            OFlag::O_PATH | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| err!("openat(\"..\") failed: {}", e))?;
        let par_id = fd_id(parent.as_fd())?;
        if par_id == cur_id {
            // Reached VFS root: ".." resolves to the same inode as ".".
            return Ok(false);
        }
        current = parent;
    }
}
