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
}

impl RceDetector {
    pub fn new(config: RceDetectorConfig) -> Self {
        let protected_services = config.protected_services.iter().cloned().collect();
        Self {
            config,
            protected_services,
        }
    }

    /// Scans active processes in /proc to detect anomalous parent-child relationships.
    pub fn scan_anomalies(&self) -> Vec<RceAlert> {
        let mut alerts = Vec::new();

        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return alerts,
        };

        for entry in proc_dir.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                if let Some(ppid) = ProcessInspector::get_parent_pid(pid) {
                    if let Some(parent_comm) = ProcessInspector::get_process_name(ppid) {
                        if self.is_protected_service(&parent_comm) {
                            if let Some(child_exe) = ProcessInspector::get_process_exe(pid) {
                                if self.is_forbidden_child(&child_exe) {
                                    let raw_cmd = ProcessInspector::get_process_cmdline(pid)
                                        .unwrap_or_else(|| child_exe.clone());
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

                                    alerts.push(RceAlert {
                                        parent_service: parent_comm,
                                        parent_pid: ppid,
                                        child_cmd,
                                        child_pid: pid,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        alerts
    }

    fn is_protected_service(&self, name: &str) -> bool {
        self.protected_services.contains(name)
    }

    fn is_forbidden_child(&self, path: &str) -> bool {
        for forbidden in &self.config.forbidden_children {
            if forbidden.ends_with('*') {
                let prefix = &forbidden[..forbidden.len() - 1];
                if path.starts_with(prefix) {
                    return true;
                }
            } else if path == forbidden || path.ends_with(&format!("/{}", forbidden)) {
                return true;
            }
        }
        false
    }
}
