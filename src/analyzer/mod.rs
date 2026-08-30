pub mod package_db;
pub mod process_context;

use crate::fim::state::FileFingerprint;
use crate::notifier::AlertSeverity;
use package_db::PackageManagerChecker;
use process_context::ProcessInspector;
use std::path::Path;

#[derive(Debug)]
pub struct AnalysisResult {
    pub is_legitimate_update: bool,
    pub severity: AlertSeverity,
    pub title: String,
    pub details: String,
}

pub struct Analyzer {
    pkg_checker: PackageManagerChecker,
}

impl Analyzer {
    pub fn new(check_packages: bool) -> Self {
        Self {
            pkg_checker: PackageManagerChecker::new(check_packages),
        }
    }

    pub fn is_package_manager_active(&self) -> bool {
        self.pkg_checker.is_package_manager_locked()
    }

    pub fn analyze_modification(
        &self,
        path: &Path,
        author_pid: Option<u32>,
        old_fp: Option<&FileFingerprint>,
        new_fp: &FileFingerprint,
    ) -> AnalysisResult {
        let (proc_name, proc_cmdline) = if let Some(pid) = author_pid {
            let name =
                ProcessInspector::get_process_name(pid).unwrap_or_else(|| "unknown".to_string());
            let cmd =
                ProcessInspector::get_process_cmdline(pid).unwrap_or_else(|| "unknown".to_string());
            (name, cmd)
        } else {
            ("unknown".to_string(), "unknown".to_string())
        };

        let is_pkg_running = self.pkg_checker.is_package_manager_locked();
        let is_pkg_mgr_process = if proc_name != "unknown" {
            self.pkg_checker.is_package_manager_process(&proc_name)
        } else {
            false
        };

        // Correlate active logged-in IP addresses
        let active_sessions = ProcessInspector::get_active_logged_in_ips();
        let ip_origin_str = if !active_sessions.is_empty() {
            active_sessions
                .iter()
                .map(|s| s.ip_origin.clone())
                .collect::<Vec<String>>()
                .join(", ")
        } else {
            "local console / service".to_string()
        };

        // If package manager is actively running on the system, treat changes as legitimate system updates
        if is_pkg_running || is_pkg_mgr_process {
            return AnalysisResult {
                is_legitimate_update: true,
                severity: AlertSeverity::Info,
                title: "Legitimate System Package Update Detected".to_string(),
                details: format!(
                    "File: {}\nContext: Package Manager Active (apt/dpkg/dnf)\nPrevious Hash: {}\nNew Hash: {}",
                    path.display(),
                    old_fp.map(|f| f.hash_value.as_str()).unwrap_or("none"),
                    new_fp.hash_value
                ),
            };
        }

        AnalysisResult {
            is_legitimate_update: false,
            severity: AlertSeverity::Critical,
            title: "UNAUTHORIZED FILE TAMPERING DETECTED".to_string(),
            details: format!(
                "CRITICAL ALERT: File modification outside package manager!\n\nFile: {}\nActive User Origin IP(s): {}\nAuthor Process: {} (PID: {})\nAuthor Command: {}\nPrevious Hash: {}\nNew Hash: {}",
                path.display(),
                ip_origin_str,
                proc_name,
                author_pid.unwrap_or(0),
                proc_cmdline,
                old_fp.map(|f| f.hash_value.as_str()).unwrap_or("none"),
                new_fp.hash_value
            ),
        }
    }
}
