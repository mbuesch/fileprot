## fileprot - Simple file protection utility for Linux

## Overview

- Implemented in **Rust**.
- Supports multiple Linux **FUSE** filesystems (use the `fuser` crate).
- Configurable via a TOML configuration file.
- The FUSE filesystem supports creating, deleting, reading, and writing files, and behaves like a normal Linux filesystem.
- Files in the virtual FUSE filesystem are stored under a user-configured directory on the host; the directory hierarchy mirrors the FUSE filesystem one-to-one.
- On access or modification (read, write, delete, rename, mkdir, etc.), the operation is blocked until the user explicitly approves or rejects it. No data is provided to the requesting application until approval is granted. Directory reads (`readdir`) do not require approval.
- The user approves or rejects requests via the GUI.

## Service / Daemon

- The daemon is called `fileprotd`.
- The FUSE mounts are managed by a systemd service.
- The service runs as root.
- The daemon is installed to `/opt/fileprot/bin/`.
- The configuration file is located at `/opt/fileprot/etc/fileprot/fileprotd.conf`.

## GUI

- The GUI is named `fileprot`.
- The GUI is implemented with Dioxus.
- A desktop tray application provides the primary user interface for approving or rejecting access requests.
- The user can see the PID, file path, application name, and operation type of the requesting application before approving or rejecting.
- There are no "always allow" or similar shortcuts.
- The GUI is installed to `/opt/fileprot/bin/`.
- The GUI uses the `tray-icon` crate.

## Communication between Daemon and GUI

- Communication uses D-Bus.
- D-Bus peers are verified to ensure the GUI is a legitimate fileprot client.

## Implementation process

- When implementing, always think carefully and do not take shortcuts.
- When unsure, ask rather than guess.
- Never use the character `—`; use `-` instead.
- Use `vec![]` instead of `Vec::new()`.
- When using multiple items from the same crate, prefer a single `use` statement with curly braces.
- `mod` statements shall come after `use` statements.
- `use` statements shall be at the top of the file.
- Generally avoid `unwrap()`.
- When unwrapping a lock guard, use `expect("Lock poisoned")` instead of `unwrap()`.
- Prefer `use` statements to bring crate paths into scope rather than using crate-root paths directly.
- Always run `cargo clippy` after making changes and address warnings; prefer clippy over relying solely on `cargo build`.
- After changing code, run `cargo fmt` to ensure consistent formatting.
- After changing Dioxus code, run `dx fmt` to ensure consistent formatting.

## Crate versions

- Use the latest crate versions from crates.io.
