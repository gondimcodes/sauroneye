# Changelog

All notable changes to **SauronEye** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
