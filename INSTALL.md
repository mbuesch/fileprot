# fileprot - Installation Guide

## Prerequisites

### System packages

Install the required system dependencies:

```bash
# Debian/Ubuntu
sudo apt install build-essential pkg-config libfuse3-dev libdbus-1-dev \
    libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev

# Fedora
sudo dnf install gcc pkg-config fuse3-devel dbus-devel \
    webkit2gtk4.1-devel gtk3-devel libayatana-appindicator-gtk3-devel

# Arch
sudo pacman -S base-devel pkg-config fuse3 dbus webkit2gtk-4.1 gtk3 libayatana-appindicator
```

### Rust toolchain

Install Rust via [rustup](https://rustup.rs/) (requires Rust 1.87+):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Building

```bash
cargo build --release
```

The binaries will be at:
- `target/release/fileprotd` - the FUSE daemon
- `target/release/fileprot` - the GUI tray application

## Installation

### 1. Install binaries

```bash
sudo mkdir -p /opt/fileprot/bin
sudo cp target/release/fileprotd /opt/fileprot/bin/
sudo cp target/release/fileprot /opt/fileprot/bin/
sudo chmod 755 /opt/fileprot/bin/fileprotd /opt/fileprot/bin/fileprot
```

### 2. Install configuration

```bash
sudo mkdir -p /opt/fileprot/etc/fileprot
sudo cp fileprotd.conf.example /opt/fileprot/etc/fileprot/fileprotd.conf
sudo chown -R root:root /opt/fileprot/etc
```

Edit `/opt/fileprot/etc/fileprot/fileprotd.conf` to configure your protected mounts.

### 3. Create backing directories

For each `[[mount]]` in the config, create the backing directory:

```bash
sudo mkdir -p /opt/fileprot/var/lib/fileprot-backing/protected
sudo chown -R root:root /opt/fileprot/var/lib/fileprot-backing
sudo chmod -R 0700 /opt/fileprot/var/lib/fileprot-backing
```

### 4. Create mountpoints

```bash
sudo mkdir -p /mnt/fileprot/protected
sudo chown root:root /mnt/fileprot/protected
```

### 5. Configure FUSE

Enable `user_allow_other` so the daemon (running as root) can
allow other users to access the FUSE mounts:

```bash
echo "user_allow_other" | sudo tee -a /etc/fuse.conf
```

### 6. Install D-Bus policy

```bash
sudo cp dbus/ch.bues.fileprot.Daemon.conf /etc/dbus-1/system.d/
sudo systemctl reload dbus
```

### 7. Install and enable the systemd service

```bash
sudo cp systemd/fileprotd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fileprotd
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

### Running the GUI

Run the GUI tray application as your desktop user:

```bash
/opt/fileprot/bin/fileprot
```

The GUI will appear as a tray icon. When an application tries to access a
protected file, a request will appear in the GUI window showing:

- **PID** - process ID of the requesting application
- **File path** - the protected file being accessed
- **Application** - the executable path of the requesting application
- **Operation** - read, write, create, or delete

Click **Approve** to allow the operation or **Deny** to block it.

If no response is given within the configured timeout (default: 120 seconds),
the request is automatically denied.

## Uninstallation

```bash
sudo systemctl disable --now fileprotd
sudo rm /etc/systemd/system/fileprotd.service
sudo rm /etc/dbus-1/system.d/ch.bues.fileprot.Daemon.conf
sudo systemctl daemon-reload
sudo systemctl reload dbus
sudo rm -rf /opt/fileprot
```
