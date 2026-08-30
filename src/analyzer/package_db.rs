use std::fs;
use std::path::Path;

pub struct PackageManagerChecker {
    enabled: bool,
}

impl PackageManagerChecker {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Checks if known package managers currently hold lock files or active locks.
    pub fn is_package_manager_locked(&self) -> bool {
        if !self.enabled {
            return false;
        }

        let lock_files = [
            "/var/lib/dpkg/lock-frontend",
            "/var/lib/dpkg/lock",
            "/var/lib/apt/lists/lock",
            "/var/run/yum.pid",
            "/var/run/dnf.pid",
            "/var/lib/pacman/db.lck",
        ];

        for lock_file in &lock_files {
            let p = Path::new(lock_file);
            if p.exists() {
                // In Linux, files like /var/lib/dpkg/lock exist permanently, but fcntl locks indicate active execution
                // We check if any package manager process is currently active in /proc
                if self.is_any_package_manager_running() {
                    return true;
                }
            }
        }

        self.is_any_package_manager_running()
    }

    /// Scans active processes in /proc to check if any package manager is actively executing
    pub fn is_any_package_manager_running(&self) -> bool {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.chars().all(|c| c.is_ascii_digit()) {
                    let comm_path = entry.path().join("comm");
                    if let Ok(comm) = fs::read_to_string(comm_path) {
                        let proc_name = comm.trim();
                        if self.is_package_manager_process(proc_name) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn is_package_manager_process(&self, proc_name: &str) -> bool {
        let known_managers = [
            "apt",
            "apt-get",
            "dpkg",
            "aptitude",
            "unattended-upgrade",
            "apt-helper",
            "http",
            "https",
            "gpgv",
            "store",
            "rred",
            "yum",
            "dnf",
            "rpm",
            "pacman",
            "apk",
            "zypper",
        ];

        for &mgr in &known_managers {
            if proc_name == mgr || proc_name.ends_with(&format!("/{}", mgr)) {
                return true;
            }
        }
        false
    }
}
