# Installation & Deployment Guide — SauronEye 👁️

This guide covers building, configuring, and installing **SauronEye** as a system daemon on Linux servers.

---

*Read this in other languages: [English](INSTALL.md) | [Português (Brasil)](INSTALL.pt-BR.md)*

---

## Prerequisites

- **Linux Kernel:** 5.4 or newer (supports `fanotify`, `/proc` connectors, and Netlink interfaces).
- **Rust Toolchain:** Rust 1.75+ (`rustc` and `cargo`).
- **Build Utilities:** `build-essential`, `pkg-config`, `libssl-dev`, `curl` (or distro equivalents).

### 1. Install System Dependencies

```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y build-essential pkg-config libssl-dev curl

# RHEL / Rocky Linux / AlmaLinux
sudo dnf groupinstall -y "Development Tools" && sudo dnf install -y pkgconfig openssl-devel curl

# Alpine Linux
apk add build-base pkgconfig openssl-dev curl
```

### 2. Install Rust Toolchain (via `rustup`)

If you don't have Rust installed, install the official stable toolchain:

```bash
# Install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Load Rust environment into current shell
source "$HOME/.cargo/env"

# Verify installation
rustc --version
cargo --version
```

---

## 1. Building the Release Binary

Compile an optimized, standalone binary:

```bash
cd sauroneye
cargo build --release
```

The compiled binary will be located at `target/release/sauroneye`.

---

## 2. Directory Layout & Permissions

Create the standard runtime directories and install the binary:

```bash
# 1. Install binary to system path
sudo install -m 755 target/release/sauroneye /usr/local/bin/sauroneye

# 2. Create configuration and database directories with restricted permissions
sudo mkdir -p /etc/sauroneye
sudo mkdir -p /var/lib/sauroneye
sudo chmod 700 /etc/sauroneye /var/lib/sauroneye

# 3. Copy configuration template
sudo cp config.toml.example /etc/sauroneye/config.toml
sudo chmod 600 /etc/sauroneye/config.toml
```

---

## 3. Configuring SauronEye

Edit `/etc/sauroneye/config.toml` to customize monitored directories, notification channels (Telegram, WhatsApp), and server hostname:

```bash
sudo nano /etc/sauroneye/config.toml
```

---

## 4. Initializing the Database (One-Time Init)

Run the initial setup to generate the SQLite database, configure the admin password (hashed with Argon2id), and record the initial baseline scan:

```bash
sudo sauroneye --config /etc/sauroneye/config.toml init
```

> **Security Note:** Once initialized, the `--init` command is permanently locked to prevent unauthorized tampering. Future baseline refreshes must be executed via `sauroneye update` using the admin password.

---

## 5. Setting Up Systemd Service

Create the systemd unit file at `/etc/systemd/system/sauroneye.service`:

```ini
[Unit]
Description=SauronEye — Real-Time FIM & Intrusion Sentinel Daemon
After=network.target auditd.service
Wants=network-online.target
RefuseManualStop=yes

[Service]
Type=simple
ExecStart=/usr/local/bin/sauroneye --config /etc/sauroneye/config.toml run
Restart=always
RestartSec=1s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

# Hardening Directives
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/sauroneye
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Enable and start the daemon, then lock the unit file against unauthorized tampering:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sauroneye
sudo systemctl status sauroneye

# Lock systemd unit file with the immutable attribute (prevents stop/mask/tampering by root)
sudo chattr +i /etc/systemd/system/sauroneye.service
```

> **Self-Defense & Upgrades:** With `RefuseManualStop=yes` and `chattr +i`, `systemctl stop sauroneye` is permanently refused by Systemd. Because `Restart=always` (1s) is active, future binary updates do **not** require unlocking the service file: simply replace `/usr/local/bin/sauroneye` and send `sudo killall -SIGTERM sauroneye`. Systemd will instantly resurrect the daemon on the new binary in 1 second.

---

## 6. Verification & Health Check

Verify that SauronEye is running and inspecting the system:

```bash
# Check status via CLI
sudo sauroneye --config /etc/sauroneye/config.toml status

# View live sentinel logs
sudo journalctl -u sauroneye -f
```
