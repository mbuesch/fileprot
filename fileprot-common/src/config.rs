use crate::{DEFAULT_BACKING_BASE_DIR, DEFAULT_GUI_BINARY_PATH};
use anyhow::{self as ah, Context, format_err as err};
use nix::unistd::{Group, User};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

/// Resolve a user name or numeric string to a uid.
fn resolve_uid(s: &str) -> ah::Result<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    User::from_name(s)
        .context("failed to look up user")?
        .ok_or_else(|| err!("unknown user '{}'", s))
        .map(|u| u.uid.as_raw())
}

/// Resolve a group name or numeric string to a gid.
fn resolve_gid(s: &str) -> ah::Result<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    Group::from_name(s)
        .context("failed to look up group")?
        .ok_or_else(|| err!("unknown group '{}'", s))
        .map(|g| g.gid.as_raw())
}

/// Top-level configuration structure.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Path to the GUI binary for peer verification.
    /// Defaults to /opt/fileprot/bin/fileprot.
    #[serde(default = "default_gui_binary_path")]
    gui_binary_path: PathBuf,

    /// Timeout in seconds for access requests. If the user does not respond
    /// within this time, the request is denied. Defaults to 30 seconds.
    #[serde(default = "default_request_timeout_secs")]
    request_timeout_secs: u64,

    /// How long (in seconds) to remember an approval for a specific process
    /// without prompting again. The approval is bound to the PID, UID,
    /// executable path, and process start time, so PID reuse cannot bypass it.
    /// Set to 0 to disable approval caching entirely. Defaults to 10 seconds.
    #[serde(default = "default_approval_ttl_secs")]
    approval_ttl_secs: u64,

    /// When true (the default), a cached approval is coupled to the exact
    /// process that obtained it: PID, UID, executable path, and start time
    /// must all match. When false, any process may reuse a recently-granted
    /// approval within the TTL window.
    #[serde(default = "default_couple_approval_to_process")]
    couple_approval_to_process: bool,

    /// When true (the default), each access that hits a cached approval
    /// resets the approval TTL timer, effectively keeping the approval alive as
    /// long as the process keeps accessing files. When false, the TTL is fixed
    /// from the time the user originally granted it.
    #[serde(default = "default_renew_approval_on_access")]
    renew_approval_on_access: bool,

    /// Base directory for all backing storage on the host filesystem.
    /// Mount backing_dir paths that are relative are resolved against this
    /// directory. Defaults to /opt/fileprot/var/lib/fileprot-backing.
    #[serde(default = "default_backing_base_dir")]
    backing_base_dir: PathBuf,

    /// List of FUSE mount configurations.
    #[serde(rename = "mount")]
    mounts: Vec<MountConfig>,
}

impl Config {
    pub fn gui_binary_path(&self) -> &Path {
        &self.gui_binary_path
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    pub fn approval_ttl(&self) -> Duration {
        Duration::from_secs(self.approval_ttl_secs)
    }

    pub fn couple_approval_to_process(&self) -> bool {
        self.couple_approval_to_process
    }

    pub fn renew_approval_on_access(&self) -> bool {
        self.renew_approval_on_access
    }

    pub fn backing_base_dir(&self) -> &Path {
        &self.backing_base_dir
    }

    pub fn mounts(&self) -> &[MountConfig] {
        &self.mounts
    }
}

/// Configuration for a single FUSE mount.
#[derive(Debug, Deserialize)]
pub struct MountConfig {
    /// If true, this mount is disabled and will not be started.
    /// Defaults to false.
    disabled: Option<bool>,

    /// Human-readable name for this mount.
    name: String,

    /// Path where the FUSE filesystem will be mounted.
    mountpoint: PathBuf,

    /// Path to the backing directory on the host filesystem.
    /// If relative, it is resolved against the global backing_base_dir.
    backing_dir: Option<PathBuf>,

    /// Owner user for the mounted filesystem.
    /// Accepts a numeric uid or a user name string.
    /// Defaults to 0 (root) if not set.
    uid: Option<String>,

    /// Owner group for the mounted filesystem.
    /// Accepts a numeric gid or a group name string.
    /// Defaults to 0 (root) if not set.
    gid: Option<String>,

    /// Resolved numeric uid (populated during load).
    #[serde(skip)]
    resolved_uid: u32,

    /// Resolved numeric gid (populated during load).
    #[serde(skip)]
    resolved_gid: u32,
}

impl MountConfig {
    pub fn disabled(&self) -> bool {
        self.disabled.unwrap_or(false)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    pub fn backing_dir(&self) -> PathBuf {
        self.backing_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(&self.name))
    }

    /// Numeric uid that the FUSE filesystem root and files will be owned by.
    pub fn uid(&self) -> u32 {
        self.resolved_uid
    }

    /// Numeric gid that the FUSE filesystem root and files will be owned by.
    pub fn gid(&self) -> u32 {
        self.resolved_gid
    }
}

fn default_gui_binary_path() -> PathBuf {
    PathBuf::from(DEFAULT_GUI_BINARY_PATH)
}

fn default_request_timeout_secs() -> u64 {
    30
}

fn default_approval_ttl_secs() -> u64 {
    10
}

fn default_couple_approval_to_process() -> bool {
    true
}

fn default_renew_approval_on_access() -> bool {
    true
}

fn default_backing_base_dir() -> PathBuf {
    PathBuf::from(DEFAULT_BACKING_BASE_DIR)
}

impl Config {
    /// Load configuration from the given path.
    pub fn load(path: &Path) -> ah::Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config '{}'", path.display()))?;
        let mut config: Config = toml::from_str(&content).context("failed to parse config")?;
        config.resolve_backing_dirs();
        config.resolve_uid_gid()?;
        config.validate()?;
        Ok(config)
    }

    /// Resolve relative backing_dir paths against backing_base_dir.
    fn resolve_backing_dirs(&mut self) {
        for mount in &mut self.mounts {
            let backing_dir = mount.backing_dir();
            if backing_dir.is_absolute() {
                continue;
            }
            mount.backing_dir = Some(self.backing_base_dir.join(&backing_dir));
        }
    }

    /// Resolve uid/gid name strings to numeric values.
    fn resolve_uid_gid(&mut self) -> ah::Result<()> {
        for mount in &mut self.mounts {
            mount.resolved_uid = match &mount.uid {
                Some(s) => resolve_uid(s)
                    .with_context(|| format!("mount '{}': invalid uid '{}'", mount.name, s))?,
                None => 0,
            };
            mount.resolved_gid = match &mount.gid {
                Some(s) => resolve_gid(s)
                    .with_context(|| format!("mount '{}': invalid gid '{}'", mount.name, s))?,
                None => 0,
            };
        }
        Ok(())
    }

    fn validate(&self) -> ah::Result<()> {
        if !self.backing_base_dir.is_absolute() {
            return Err(err!(
                "invalid config: backing_base_dir '{}' must be an absolute path",
                self.backing_base_dir.display()
            ));
        }
        if self.mounts.is_empty() {
            return Err(err!(
                "invalid config: at least one [[mount]] must be configured"
            ));
        }
        for mount in &self.mounts {
            if mount.disabled() {
                continue;
            }
            if mount.name.is_empty() {
                return Err(err!("invalid config: mount name must not be empty"));
            }
            if !mount
                .name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            {
                return Err(err!(
                    "invalid config: mount name '{}' must only contain \
                     alphanumeric characters, '_', or '-'",
                    mount.name
                ));
            }
            if !mount.mountpoint.is_absolute() {
                return Err(err!(
                    "invalid config: mountpoint '{}' must be an absolute path",
                    mount.mountpoint.display()
                ));
            }
            assert!(
                mount.backing_dir().is_absolute(),
                "backing_dir must be absolute"
            );
        }
        Ok(())
    }
}
