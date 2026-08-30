use std::path::Path;

pub struct PackageManagerChecker {
    enabled: bool,
}

impl PackageManagerChecker {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Checks if known package managers currently hold lock files.
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
                return true;
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
