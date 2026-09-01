use std::fs::OpenOptions;
use std::path::Path;

pub struct PackageManagerChecker {
    enabled: bool,
}

impl PackageManagerChecker {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Checks if a package manager is currently active by attempting a
    /// non-blocking exclusive flock() on the distro's canonical lock file.
    ///
    /// This is the exact same mechanism used by apt, dpkg, dnf, pacman and
    /// apk themselves to detect concurrent execution — no process-name
    /// guessing, no /proc/locks parsing, no false positives.
    ///
    /// Returns true  → lock is held by someone else (package manager running).
    /// Returns false → lock is free (safe to alert).
    pub fn is_package_manager_locked(&self) -> bool {
        if !self.enabled {
            return false;
        }

        // Canonical lock files per distro — if ANY of them is exclusively
        // locked by another process, a package manager is active.
        let lock_files = [
            "/var/lib/dpkg/lock-frontend", // apt / dpkg (Debian/Ubuntu)
            "/var/lib/dpkg/lock",          // dpkg direct
            "/var/lib/rpm/.rpm.lock",      // rpm / dnf / yum (RedHat family)
            "/var/lib/pacman/db.lck",      // pacman (Arch)
            "/lib/apk/db/lock",            // apk (Alpine)
            "/var/lib/zypp/zypp.lock",     // zypper (openSUSE)
        ];

        for lock_file in &lock_files {
            let p = Path::new(lock_file);
            if !p.exists() {
                continue;
            }
            if Self::is_file_exclusively_locked(p) {
                return true;
            }
        }

        false
    }

    /// Tries to acquire a non-blocking exclusive flock() on `path`.
    /// If it succeeds → nobody holds the lock → returns false.
    /// If it fails with EWOULDBLOCK → lock is held → returns true.
    fn is_file_exclusively_locked(path: &Path) -> bool {
        use nix::fcntl::{Flock, FlockArg};

        let file = match OpenOptions::new().read(true).open(path) {
            Ok(f) => f,
            Err(_) => return false, // Can't open → assume not locked
        };

        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(_guard) => {
                // We got the lock — nobody else holds it.
                // Guard is dropped here, releasing the lock automatically.
                false
            }
            Err((_file, nix::errno::Errno::EWOULDBLOCK)) => {
                // Lock is held by another process — package manager is active.
                true
            }
            Err(_) => {
                // Other error → treat as not locked.
                false
            }
        }
    }

    /// Used by analyze_modification() to check if the process that wrote a
    /// specific file is a known package-manager helper.
    /// NOTE: this is secondary context, not the primary gate for alerts.
    pub fn is_package_manager_process(&self, proc_name: &str) -> bool {
        let name = proc_name.rsplit('/').next().unwrap_or(proc_name);

        // Exact-match primary binaries of every major distro package manager.
        // No prefix wildcards — only the real process names actually written
        // to /proc/<pid>/comm (truncated to 15 chars by the kernel).
        matches!(
            name,
            "apt"
                | "apt-get"
                | "apt-cache"
                | "apt-helper"
                | "dpkg"
                | "dpkg-deb"
                | "dpkg-split"
                | "dpkg-query"
                | "aptitude"
                | "unattended-upgr" // "unattended-upgrade" truncated to 15
                | "debconf"
                | "needrestart"
                | "yum"
                | "dnf"
                | "rpm"
                | "rpmbuild"
                | "pacman"
                | "apk"
                | "zypper"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_package_manager_process_known() {
        let c = PackageManagerChecker::new(true);
        assert!(c.is_package_manager_process("dpkg"));
        assert!(c.is_package_manager_process("apt-get"));
        assert!(c.is_package_manager_process("dpkg-deb"));
        assert!(c.is_package_manager_process("unattended-upgr"));
        assert!(c.is_package_manager_process("/usr/bin/dpkg"));
    }

    #[test]
    fn test_is_package_manager_process_unknown() {
        let c = PackageManagerChecker::new(true);
        assert!(!c.is_package_manager_process("nginx"));
        assert!(!c.is_package_manager_process("bash"));
        assert!(!c.is_package_manager_process("http"));
        assert!(!c.is_package_manager_process("store"));
        assert!(!c.is_package_manager_process("packagekitd"));
        assert!(!c.is_package_manager_process("apt-cacher-ng"));
    }
}
