# fileprot - Installation Guide

## Prerequisites

### Rust toolchain

Install Rust via [rustup](https://rustup.rs/).

## Building

```bash
./build.sh
```

This builds both debug and release binaries for `fileprotd` and `fileprot` and runs the test suite.
To build only the release binaries, pass `--release`.

## Installation

### 1. Create mountpoints

Create a mountpoint for each `[[mount]]` you intend to configure:

```bash
sudo mkdir -p /home/user/protected
```

### 2. Run the install script

```bash
sudo ./install.sh
```

This installs the binaries, D-Bus policy, and systemd service, creates the backing storage directory, and starts the daemon.

### 3. Edit the configuration

```bash
sudo $EDITOR /opt/fileprot/etc/fileprot/fileprotd.conf
```

Configure your protected mounts, then restart the daemon:

```bash
sudo systemctl restart fileprotd
```

## Usage

### Starting the daemon

The daemon starts automatically via systemd:

```bash
sudo systemctl start fileprotd
sudo systemctl status fileprotd
```

Check logs:

```bash
journalctl -u fileprotd -f
```

### Starting the tray application

The tray GUI (`fileprot`) can be started as a systemd user service, which automatically launches it on graphical session startup (e.g., XFCE, GNOME):

```bash
systemctl --user enable --now fileprot.service
```

Check status:

```bash
systemctl --user status fileprot.service
```

Check logs:

```bash
journalctl --user -u fileprot.service -f
```

The systemd user service is installed automatically during `sudo ./install.sh`.
