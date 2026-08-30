# Technology Stack & Architecture — SauronEye 👁️

This document describes the complete technology stack, architectural components, dependencies, and engineering design choices utilized in **SauronEye Sentinel**.

---

## 1. Core Engineering & Runtime Stack

* **Programming Language:** [Rust](https://www.rust-lang.org/) (Edition 2021, Rust 1.75+) — Zero-cost abstractions, memory safety without garbage collector, high throughput, and minimal CPU/RAM footprint.
* **Async Runtime:** [Tokio](https://tokio.rs/) (v1.x) with multi-threaded executor (`features = ["full"]`) for asynchronous non-blocking event handling, timers, and messaging pipelines.
* **Async Traits:** `async-trait` for dynamic dispatch and modular notification backend extensibility.

---

## 2. Kernel & Filesystem Monitoring (FIM Engine)

* **Filesystem Event Subsystem:** [Notify](https://crates.io/crates/notify) (v6.x) with automatic backend selection:
  - Prefers Linux `fanotify` for mount/directory level surveillance with fallback to `inotify`.
  - Non-blocking event streaming through bounded channels (`tokio::sync::mpsc`).
* **Recursive Directory Walker:** `walkdir` (v2.x) for fast baseline indexing without recursion-depth stack overflow.
* **POSIX System Calls:** `libc` (v0.2) for low-level Unix process and inode inspections.

---

## 3. Cryptographic Fingerprinting & Hashing

* **BLAKE3 Engine:** [blake3](https://crates.io/crates/blake3) (v1.5) — Extremely fast cryptographic hash (tree hashing with SIMD/AVX support and automatic pure-scalar fallback for legacy/VM CPUs).
* **XxHash Engine:** [twox-hash](https://crates.io/crates/twox-hash) (v1.6) — Ultra-fast non-cryptographic hash for high-throughput checksum verification.
* **Streaming Architecture:** Buffer-based chunked streaming (`BufReader` with 64KB buffers) enabling large binary hashing with fixed, low memory overhead.

---

## 4. Local Database & Audit Storage

* **Embedded Database Engine:** [rusqlite](https://crates.io/crates/rusqlite) (v0.32) — Embedded SQLite3 database engine (pure static link, zero external database service dependency).
* **High-Concurrency Mode:** **Write-Ahead Logging (WAL)** enabled with `PRAGMA synchronous = NORMAL`, `PRAGMA temp_store = MEMORY` and 64MB LRU cache.
* **Storage Schema:**
  - `file_fingerprints`: Indexed by filesystem path and inode with `WITHOUT ROWID` optimization.
  - `admin_users`: One-Time Init admin authentication table.
  - `audit_logs`: Append-only security audit trail with indexed timestamps.
* **POSIX Hardening:** Strict filesystem permissions (`0700` for database parent directory, `0600` for `sauron.db`).

---

## 5. Security & Authentication

* **Password Hashing:** [argon2](https://crates.io/crates/argon2) (v0.5) — Memory-hard password hashing standard with `Argon2id` variant, random salt generation via `OsRng`, and timing-safe constant-time verification.
* **Terminal Password Masking:** `rpassword` (v7.3) for secure interactive CLI credential input without terminal echo.
* **One-Time Init Guard:** Hardened database guard that prevents unauthorized re-initialization of an active baseline.

---

## 6. Real-Time Alerting & Messaging Backends

* **HTTP Client:** [reqwest](https://crates.io/crates/reqwest) (v0.12) with pure Rust TLS (`rustls-tls`, `json`, `multipart`) without OpenSSL runtime dependency.
* **Telegram Bot API:** Standalone HTTP client dispatching structured markdown alerts to configured chat IDs.
* **WhatsApp Bridge API:** Multi-part form/JSON integration dispatching instant alerts to security operations teams.
* **SMTP Mailer Engine:** [lettre](https://crates.io/crates/lettre) (v0.11) with `tokio1-rustls-tls`:
  - Automatic STARTTLS (port 587/25) vs direct SMTPS TLS wrapper (port 465) negotiation.
  - On-demand dispatch of forensic PDF reports with MIME `application/pdf` multipart attachments.

---

## 7. Reporting & Forensic PDF Generation

* **PDF Generator Engine:** [printpdf](https://crates.io/crates/printpdf) (v0.12.5) — Pure Rust PDF document generator without external tools (`wkhtmltopdf`, Chrome headless, or C libraries).
* **Multi-Page Layout:** Dynamic page allocation, executive metrics summarization, and vector line drawing.

---

## 8. CLI & Observability

* **Command Line Parser:** [clap](https://crates.io/crates/clap) (v4.5) with `derive` macros and subcommand support (`init`, `update`, `run`, `status`, `logs`, `report`).
* **Date & Time Engine:** [chrono](https://crates.io/crates/chrono) (v0.4) supporting flexible ISO-8601, human-friendly timestamps, and configurable UTC time representation.
* **Structured Logging:** [tracing](https://crates.io/crates/tracing) and [tracing-subscriber](https://crates.io/crates/tracing-subscriber) with environment filter support (`RUST_LOG`).
* **Serialization & Configuration:** [serde](https://crates.io/crates/serde) (v1.0) and [toml](https://crates.io/crates/toml) (v0.8).
