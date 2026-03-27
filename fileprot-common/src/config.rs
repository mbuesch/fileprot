use crate::{DEFAULT_BACKING_BASE_DIR, DEFAULT_GUI_BINARY_PATH};
use anyhow::{self as ah, Context, format_err as err};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

/// Top-level configuration structure.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Path to the GUI binary for peer verification.
    /// Defaults to /opt/fileprot/bin/fileprot.
    #[serde(default = "default_gui_binary_path")]
    gui_binary_path: PathBuf,

    /// Timeout in seconds for access requests. If the user does not respond
    /// within this time, the request is denied. Defaults to 120 seconds.
    #[serde(default = "default_request_timeout_secs")]
    request_timeout_secs: u64,

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
}

fn default_gui_binary_path() -> PathBuf {
    PathBuf::from(DEFAULT_GUI_BINARY_PATH)
}

fn default_request_timeout_secs() -> u64 {
    120
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
            assert!(mount.backing_dir().is_absolute(), "backing_dir must be absolute");
        }
        Ok(())
    }
}
