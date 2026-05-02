use anyhow::{self as ah, Context, format_err as err};
use std::{fmt, fs, str::FromStr};

pub mod config;
pub mod dbus_interface;

/// Well-known D-Bus bus name for the daemon.
pub const DBUS_BUS_NAME: &str = "ch.bues.fileprot.Daemon";

/// D-Bus object path for the access control service.
pub const DBUS_OBJECT_PATH: &str = "/ch/bues/fileprot/Daemon";

/// D-Bus interface name.
pub const DBUS_INTERFACE_NAME: &str = "ch.bues.fileprot.AccessControl";

/// Default path to the GUI binary for peer verification.
pub const DEFAULT_GUI_BINARY_PATH: &str = "/opt/fileprot/bin/fileprot";

/// Default configuration file path.
pub const DEFAULT_CONFIG_PATH: &str = "/opt/fileprot/etc/fileprot/fileprotd.conf";

/// Default base directory for all backing storage.
pub const DEFAULT_BACKING_BASE_DIR: &str = "/opt/fileprot/var/lib/fileprot-backing";

/// Operation types for access control requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Operation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
    SetAttr,
    Mkdir,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Read => write!(f, "read"),
            Operation::Write => write!(f, "write"),
            Operation::Create => write!(f, "create"),
            Operation::Delete => write!(f, "delete"),
            Operation::Rename => write!(f, "rename"),
            Operation::SetAttr => write!(f, "setattr"),
            Operation::Mkdir => write!(f, "mkdir"),
        }
    }
}

impl FromStr for Operation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Operation::Read),
            "write" => Ok(Operation::Write),
            "create" => Ok(Operation::Create),
            "delete" => Ok(Operation::Delete),
            "rename" => Ok(Operation::Rename),
            "setattr" => Ok(Operation::SetAttr),
            "mkdir" => Ok(Operation::Mkdir),
            _ => Err(format!("unknown operation: {}", s)),
        }
    }
}

/// Resolve the application name from a process ID.
pub fn resolve_app_name(pid: u32) -> ah::Result<String> {
    let exe = fs::read_link(format!("/proc/{}/exe", pid))
        .with_context(|| format!("failed to read /proc/{}/exe", pid))?;
    let name = exe
        .file_name()
        .unwrap_or(exe.as_os_str())
        .to_str()
        .ok_or_else(|| err!("app name is not valid UTF-8"))?
        .to_owned();
    Ok(name)
}
