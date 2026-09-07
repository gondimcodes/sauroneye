use std::fs::OpenOptions;
use std::path::Path;

pub struct PackageManagerChecker {
    enabled: bool,
}

impl PackageManagerChecker {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Checks if a package manager is currently active by attempting non-blocking
    /// exclusive flock() and POSIX fcntl() locks on canonical lock files, and by checking
    /// for active package manager processes running in `/proc`.
    ///
    /// This dual-check eliminates false positives during operations like `apt full-upgrade`
    /// where apt/dpkg hold POSIX locks (`F_SETLK`) which do not conflict with BSD `flock(2)`
    /// on Linux kernels.
    ///
    /// Returns true  → package manager is active.
    /// Returns false → no package manager active (safe to alert).
    pub fn is_package_manager_locked(&self) -> bool {
        if !self.enabled {
            return false;
        }

        // 1. Canonical lock files per distro — check both BSD flock and POSIX fcntl lock
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
            if Self::is_file_locked(p) {
                return true;
            }
        }

        // 2. Fallback check: is any package manager process currently running in /proc?
        if Self::is_any_package_manager_running() {
            return true;
        }

        false
    }

    /// Checks whether `path` is exclusively locked using /proc/locks (POSIX/FLOCK),
    /// or by attempting a non-blocking BSD flock on a dedicated descriptor.
    ///
    /// IMPORTANT: Checking `/proc/locks` first by inode is zero-overhead and avoids
    /// the classic POSIX caveat where calling `close()` on any file descriptor for a path
    /// releases all POSIX record locks held on that inode across the calling process.
    fn is_file_locked(path: &Path) -> bool {
        use nix::fcntl::{Flock, FlockArg};
        use std::os::unix::fs::MetadataExt;

        // 1. Primary check: check /proc/locks for active lock on this specific (device, inode).
        // This detects POSIX F_SETLK/F_SETLKW locks held by apt, dpkg, or any child process
        // without touching or closing file descriptors.
        if let Ok(meta) = std::fs::metadata(path) {
            let target_dev = meta.dev();
            let target_ino = meta.ino();
            if Self::is_device_inode_locked_in_proc_locks(target_dev, target_ino) {
                return true;
            }
        }

        // 2. Secondary check: test BSD flock
        let file = match OpenOptions::new().read(true).open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(guard) => {
                drop(guard);
                false
            }
            Err((_file, nix::errno::Errno::EWOULDBLOCK)) => true,
            Err(_) => false,
        }
    }

    /// Checks if a file (device, inode) appears in `/proc/locks` under POSIX/FLOCK holding an exclusive lock.
    /// In Linux `/proc/locks`, field 5 is `major_hex:minor_hex:inode_dec`.
    /// Device numbers must be decomposed according to standard Linux sys/sysmacros.h:
    /// major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)
    /// minor = (dev & 0xff) | ((dev >> 12) & !0xff)
    fn is_device_inode_locked_in_proc_locks(target_dev: u64, target_ino: u64) -> bool {
        if let Ok(locks_data) = std::fs::read_to_string("/proc/locks") {
            let target_major = (((target_dev >> 8) & 0xfff) | ((target_dev >> 32) & !0xfff)) as u32;
            let target_minor = ((target_dev & 0xff) | ((target_dev >> 12) & !0xff)) as u32;
            let ino_str = target_ino.to_string();

            for line in locks_data.lines() {
                // Line format: 1: POSIX  ADVISORY  WRITE 12345 08:01:1234567 0 EOF
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let dev_ino = parts[5];
                    let mut split = dev_ino.split(':');
                    if let (Some(maj_hex), Some(min_hex), Some(ino)) =
                        (split.next(), split.next(), split.next())
                    {
                        if ino == ino_str {
                            if let (Ok(maj), Ok(min)) = (
                                u32::from_str_radix(maj_hex, 16),
                                u32::from_str_radix(min_hex, 16),
                            ) {
                                if maj == target_major && min == target_minor {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Scans `/proc` to verify if any canonical package manager is actively running.
    /// Fast directory scan reading only `/proc/[pid]/comm` without reading heavy environ.
    /// Excludes persistent background daemon names like unattended-upgr or packagekitd.
    fn is_any_package_manager_running() -> bool {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Check if directory name is numeric (PID)
                if name_str.chars().all(|c| c.is_ascii_digit()) {
                    let comm_path = entry.path().join("comm");
                    if let Ok(comm) = std::fs::read_to_string(comm_path) {
                        let proc_name = comm.trim();
                        if Self::is_active_installer_binary(proc_name) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Identifies active foreground or worker package manager installer binaries.
    /// Note: Does NOT include passive background service daemons (e.g. unattended-upgr)
    /// which can stay permanently idle in RAM waiting for timers.
    fn is_active_installer_binary(name: &str) -> bool {
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

    /// Primary exact match for known package manager processes.
    pub fn is_package_manager_process(&self, proc_name: &str) -> bool {
        let name = proc_name.rsplit('/').next().unwrap_or(proc_name);
        Self::is_active_installer_binary(name) || name == "unattended-upgr"
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

    #[test]
    fn test_is_file_locked_fcntl_and_flock() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let lock_path = temp_dir.join("sauroneye_test_lock.lck");

        // Create the dummy lock file
        {
            let mut f = std::fs::File::create(&lock_path).unwrap();
            writeln!(f, "test lock").unwrap();
        }

        // Unlocked file should return false
        assert!(!PackageManagerChecker::is_file_locked(&lock_path));

        // Lock with POSIX fcntl F_SETLK
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let fl = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        let res = unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) };
        assert_eq!(res, 0, "Failed to acquire test fcntl write lock");

        // Now PackageManagerChecker::is_file_locked MUST detect it as locked (true)
        assert!(
            PackageManagerChecker::is_file_locked(&lock_path),
            "Failed to detect POSIX fcntl lock held by apt/dpkg style process!"
        );

        // Clean up
        let _ = std::fs::remove_file(&lock_path);
    }
}
