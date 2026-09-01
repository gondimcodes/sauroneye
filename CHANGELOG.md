# Changelog

All notable changes to **SauronEye** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] - 1.0.7

> ⚠️ **BREAKING CHANGE — Database Schema**: The `file_fingerprints` table no longer contains the
> `package_name` and `package_version` columns. These fields were YAGNI (never populated, never read).
> **The SQLite database must be deleted and recreated** (`rm /var/lib/sauroneye/sauron.db` then
> `sauroneye init`) before running this version. All forensic audit logs in the `audit_logs` table
> are unaffected by this schema change.

### Security
- **[SEG-01] Log Injection Prevention**: Sanitize `raw_message` field in `pam_watcher.rs` — control
  characters (newlines, tabs, CR) embedded in crafted usernames are now replaced with spaces before
  storage and alerting.
- **[SEG-02] Path Traversal Bypass Fix in FIM Exclusion Engine**: `check_excluded()` previously used
  `path_str.contains(pattern)` for relative patterns, which could be exploited to suppress monitoring
  of a target path by embedding an excluded directory name as a substring (e.g., pattern `tmp` would
  match `/var/www/upload_tmp/backdoor.php`). Now uses `path.starts_with()` for absolute patterns and
  component-level matching for relative patterns.
- **[SEG-04] SQLite Mutex Poison Recovery**: All `Mutex<Connection>` lock acquisitions now use
  `unwrap_or_else(|p| p.into_inner())` via the `lock_conn!` macro, preventing a thread panic from
  permanently deadlocking the entire daemon.
- **[SEG-05] Sensitive Field Masking in Logs**: Telegram `chat_id` is now masked (shows only last 4
  digits) in startup logs. WhatsApp `endpoint_url` and `recipient_number` are no longer logged at all,
  preventing exposure of sensitive configuration values in syslog/journald.
- **[RUST-05] Atomic Check-and-Insert in RCE Detector**: Eliminated TOCTOU race in
  `process_tree.rs` where `alerted_pids` was locked twice (once to check, once to insert). Now a
  single lock acquisition handles both operations atomically.
- **[RUST-04] `tokio::sync::Mutex` for `AlertDispatcher`**: The `recent_dispatches` deduplication
  map in the async `dispatch()` method was guarded by `std::sync::Mutex`, which blocks the tokio
  scheduler under contention. Replaced with `tokio::sync::Mutex` with `.await`.

### Performance
- **[PERF-01] `IpSessionCache` — Eliminate Redundant `/proc` Scans**: Added `IpSessionCache` with
  a 3-second TTL in `analyzer/process_context.rs`. The FIM event loop previously called
  `get_active_logged_in_ips()` (which reads every `/proc/<pid>/environ` and `/proc/net/tcp`) once
  per FIM event — up to 500+ extra syscalls per second during bursts. Now resolved once per poll
  cycle at most.
- **[PERF-02] Debounce Map Bounded Growth**: The `recent_alert_debounce` HashMap is now purged
  of entries older than 30s whenever it exceeds 1000 entries, preventing unbounded memory growth
  during high-event-rate periods.
- **[PERF-04] FIM Event Channel Buffer 512 → 2048**: Increased the MPSC channel buffer to handle
  burst events (e.g., `rsync`, `chmod -R`) without blocking the inotify watcher thread.
- **[PERF-06] Cached SMTP Transport**: `SmtpNotifier` now builds the `AsyncSmtpTransport` once at
  construction time instead of per-alert, eliminating TLS handshake overhead on every email sent.
- **[PERF-07] Analyzer `ip_origin` Decoupled**: `analyze_modification()` now accepts `ip_origin: &str`
  as a parameter instead of calling `get_active_logged_in_ips()` internally, eliminating a hidden
  double `/proc` scan per tampered file.

### Refactoring / Code Quality
- **[QC-01] Removed `#![allow(dead_code)]`**: The global suppressor is gone. Remaining dead code
  items are annotated with targeted `#[allow(dead_code)]` and documented rationale.
- **[QC-02/ARQ-01] `MonitorState` Struct**: Extracted the 5 scattered mutable local variables in
  `handle_run()` into a `MonitorState` struct with helper methods (`purge_stale_debounce`). Reduces
  cognitive load and is the foundation for further decomposition.
- **[QC-09/10] Shared Notifier Utilities (`notifier/shared.rs`)**: The `CircuitBreaker` sliding-window
  rate limiter and `retry_http_post` retry helper were copy-pasted across `discord.rs`, `msteams.rs`,
  and `whatsapp.rs`. Extracted into a single shared module, eliminating ~150 lines of duplication.
- **[QC-03] Unified IP Context Resolution**: All FIM event handlers now share the single
  `ip_origin_str` computed once per poll cycle — previously each handler computed its own copy.
- Removed unused `glob` and `libc` dependencies from `Cargo.toml`.
- Removed unused `Clone` derive from `FimEvent` in `engine.rs`.
- Renamed `Xxh3` → `Xxh64` in `hasher.rs` for technical precision (the algorithm is XXH64, not XXH3).
- Removed YAGNI columns `package_name` and `package_version` from `FileFingerprint` and the SQLite
  schema (these fields were never populated or read).
- Increased minimum admin password length from 8 to 12 characters in `cli/auth_prompt.rs`.
- Updated MS Teams Adaptive Card schema URL from `http://` to `https://`.

### Fixed
- **Package Manager Detection Rewritten with `flock()` Advisory Lock**: Replaced the brittle
  `/proc/*/comm` process-name scanning with a kernel-level non-blocking exclusive `flock()` test on
  distro canonical lock files. The previous approach caused all FIM alerts to be silently suppressed
  when daemons like `packagekitd` were running.

---

## [1.0.6] - 2026-08-31

### Added
- **Microsoft Teams Webhook Notifier**: Added native Microsoft Teams alert integration via Incoming Webhooks (Workflows) with Adaptive Cards v1.4, severity color accents, structured fact sets, and dedicated anti-flood Circuit Breaker (capped at 20 alerts/minute).
- **Discord Webhook Notifier**: Added native Discord alert integration via incoming webhooks with styled Rich Embeds (color-coded by severity: Critical red, Warning orange, Info blue), customizable bot username/avatar, and dedicated anti-flood Circuit Breaker (capped at 30 alerts/minute).
- **Security Alert & IP Auditing on Log Purge (`sauroneye logs --purge`)**: Dispatches an explicit security alert to all active notification channels and records the operator's real remote IP whenever an administrator purges audit log entries from the database, preventing silent log tampering.
- **Operator Remote IP Tracking on CLI Actions**: All administrative CLI operations (`update`, `passwd`, `logs --purge`) now capture and log the operator's active SSH session origin IP (`admin:IP`).
- **Native Immutable Watch on `/etc/sauroneye`**: Added kernel-level immutable watch on the daemon configuration directory.





---

## [1.0.5] - 2026-08-31


### Added
- **Anti-Flood Circuit Breaker for WhatsApp**: Implemented rolling 60-second sliding-window circuit breaker (capped at 10 alerts/minute) with automated burst suppression and status notifications (`Throttling Activated` and `Alerting Resumed`), guaranteeing zero risk of WhatsApp account bans or gateway lockouts during mass file changes.
- **Rate-Limited Asynchronous Queue for Telegram & WhatsApp**: Implemented non-blocking background MPSC message queues with strict rate limiting (1.05s interval for Telegram, 1.2s for WhatsApp) and automatic backoff retry on HTTP 429 (`retry_after`), preventing message drops and API rate limit bans during high-volume event bursts.
- **PAM Noise Suppression**: Filtered internal `systemd-user:session` open logs to prevent noisy duplicate login notifications on distributions utilizing systemd user slices.

---

## [1.0.4] - 2026-08-31


### Added
- **Full RFC/Linux IPv6 Socket Decoding (`/proc/net/tcp6`)**: Implemented full 128-bit little-endian word parsing from Linux `/proc/net/tcp6` socket tables into standard `std::net::Ipv6Addr`, providing accurate remote IP tracking for IPv6 SSH and network connections during forensic auditing.

---

## [1.0.3] - 2026-08-31


### Added
- **RCE Whitelist Granular Patterns (`allowed_cmd_patterns`)**: Introduced customizable substring whitelist matching in `[rce_detector]` to allow legitimate child processes and internal scripts (e.g. Kong Gateway / OpenResty healthchecks in Supabase environments) while preserving real-time alerting on malicious shells and webshell intrusions.

---

## [1.0.2] - 2026-08-31

### Added
- **Admin Password Change Command**: Added `sauroneye passwd` CLI command allowing administrators to securely update their password after verifying current credentials, generating fresh Argon2id hashes with 128-bit cryptographic salts.

---

## [1.0.1] - 2026-08-31

### Added
- **Native Self-Defense Protection**: Hardcoded immutable watch for `/var/lib/sauroneye` and parent `/var/lib` to prevent database tampering, moving, or deletion without requiring `config.toml` entries.
- **Enhanced FIM Move/Rename Events**: Introduced dedicated `FimEvent::FileRenamed` and `FimEvent::DirectoryRenamed` events with clear `From:` and `To:` paths in security alerts.
- **Forensic PDF Table Grid**: Rebuilt PDF audit trail using a structured table grid with border boxes, column dividers, dynamic cell heights, and automatic header repetition across pages.
- **Full IPv6 Multi-line Wrapping**: Expanded `ACTOR / IP` column in PDF reports (42mm) with automatic 2-line wrapping to support full 8-hextet IPv6 addresses and `user [IPv6]` combinations cleanly.
- **Global Alert Deduplication**: Thread-safe deduplication engine in `AlertDispatcher` eliminating identical consecutive alerts within a 2.5-second time window.
- **RCE Detection Engine Refinements**:
  - Expanded process detection matching binary command names (`comm`), absolute paths (`/proc/PID/exe`), and command-line arguments (`cmdline`).
  - Added PID-level deduplication to prevent repetitive notifications during long-running child processes.

### Changed
- **Config Cleanliness**: Removed transient editor file exceptions from codebase to adhere to zero-trust principles; all excluded patterns are strictly user-configurable in `config.toml`.
- **Package Manager Report Filtering**: PDF reports and CLI `logs` commands now respect `package_manager.notify_legitimate_updates = false`, hiding benign `PACKAGE_UPDATE` events from security audit trails.
- **Audit Details Cleanup**: Simplified `PURGE_LOGS` entries, removing raw timestamp ranges and displaying only deleted record counts.

---

## [1.0.0] - 2026-08-30

### Initial Release
- **Real-Time FIM (File Integrity Monitoring)**: Linux `fanotify` and `inotify` engine with BLAKE3 and XXH3 cryptographic hashing.
- **RCE & Process Anomaly Sentinel**: `/proc` scanning engine for unauthorized child shell/utility spawns from network daemons (`nginx`, `apache2`, `php-fpm`, etc.).
- **Authentication & Privilege Escalation Auditing**: Native PAM log inspection capturing successful logins, failed attempts, and sudo usage.
- **Multi-Channel Alert Dispatcher**: Immediate notifications via Telegram Bot, WhatsApp API, and SMTP Email with PDF report attachments.
- **Forensic SQLite Storage**: Persistent transaction-safe WAL database with secure argon2id administrative authentication.
- **Enterprise PDF Reporting**: Automated generation of cryptographic PDF forensic audit reports.
