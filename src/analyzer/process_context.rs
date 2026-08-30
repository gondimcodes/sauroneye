use std::fs;

pub struct ProcessInspector;

impl ProcessInspector {
    pub fn get_process_name(pid: u32) -> Option<String> {
        let comm_path = format!("/proc/{}/comm", pid);
        fs::read_to_string(comm_path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn get_process_cmdline(pid: u32) -> Option<String> {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(bytes) = fs::read(cmdline_path) {
            let cmdline = bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<String>>()
                .join(" ");
            if !cmdline.is_empty() {
                return Some(cmdline);
            }
        }
        None
    }

    pub fn get_process_exe(pid: u32) -> Option<String> {
        let exe_path = format!("/proc/{}/exe", pid);
        fs::read_link(exe_path)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    pub fn get_parent_pid(pid: u32) -> Option<u32> {
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(content) = fs::read_to_string(stat_path) {
            // /proc/[pid]/stat format: pid (comm) state ppid ...
            if let Some(idx) = content.rfind(')') {
                let rest = &content[idx + 2..];
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse::<u32>().ok();
                }
            }
        }
        None
    }
}
