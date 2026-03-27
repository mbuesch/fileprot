## fileprot - Simple file protection utility for Linux

## Overview

- Implemented in **Rust**.
- Supports multiple Linux **FUSE** filesystems. Use the *fuser* crate.
- Configurable via a TOML configuration file.
- The FUSE filesystem supports creating, deleting, reading, and writing files and behaves like a normal Linux filesystem.
- Files in the virtual FUSE filesystem are stored under a user-configured directory in the host filesystem. The directory hierarchy mirrors the FUSE filesystem one-to-one.
- On access or modification (read, write, delete, rename, mkdir, etc.), the operation is blocked until the user explicitly approves or rejects it. No data is provided to the requesting application until approval is granted. Readdir shall not require approval.
- The user approves or rejects requests via the GUI.

## Service / Daemon

- The daemon shall be called `fileprotd`
- The FUSE mounts are managed by a systemd service.
- The service runs as root.
- The daemon shall be installed to `/opt/fileprot/bin/`
- The configuration file shall be located in `/opt/fileprot/etc/fileprot/fileprotd.conf`
- Document how to install.

## GUI

- The GUI shall be named `fileprot`
- The GUI is implemented with Dioxus.
- A desktop tray application provides the primary user interface for approving or rejecting access requests.
- The user shall be able to see the PID, file path, application name and operation type of the application that requests access before approval or rejection.
- There shall be no "always allow" or similar shortcuts.
- The GUI shall be installed to `/opt/fileprot/bin/`
- Use the crate `tray-icon`.

## Communication between Daemon and GUI

- Use D-Bus for communication.
- If possible, it shall be verified if the GUI peer during communication is a legitimate fileprot peer.

## Implementation process

- When implementing, always think hard. Do not make shortcuts.
- When unsure, always ask rather than guessing.
- Never use the character `—`. Use `-` instead.
- Use `vec![]` instead of `Vec::new()`.
- When `use`-ing multiple items from the same crate, use a single `use` statement with curly braces.
- `mod` shall come after `use` statements.
- `use` statments shall only be at the top of the file.
- Generally avoid `unwrap()`.
- When unwrapping a lock guard, use `expect("Lock poisoned")` instead of `unwrap()`.
- Avoid using Rust paths that originate in crate root where it makes sense. Instead, use `use` statements to bring them into scope.
- Always run `cargo clippy` after making changes to the code. Do not ignore clippy warnings. `cargo build` is not so important. Prefer clippy.

## Crate versions

Use the latest versions of crates from `crates.io`
