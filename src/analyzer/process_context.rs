use std::fs;
use std::net::Ipv4Addr;

pub struct ProcessInspector;

#[derive(Debug, Clone)]
pub struct ActiveUserSession {
    pub user: String,
    pub tty: String,
    pub ip_origin: String,
}

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

    /// Discovers active logged in sessions and remote client IPs from /proc and socket tables
    pub fn get_active_logged_in_ips() -> Vec<ActiveUserSession> {
        let mut sessions = Vec::new();

        // 1. Check all shell processes (bash, zsh, sh) and sshd in /proc
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(pid) = name.parse::<u32>() {
                    // Check environ of all processes for SSH_CLIENT / SSH_CONNECTION
                    let env_path = entry.path().join("environ");
                    if let Ok(env_bytes) = fs::read(env_path) {
                        for env_var in env_bytes.split(|&b| b == 0) {
                            let s = String::from_utf8_lossy(env_var);
                            if s.starts_with("SSH_CLIENT=") || s.starts_with("SSH_CONNECTION=") {
                                let val = s.split('=').nth(1).unwrap_or("");
                                let parts: Vec<&str> = val.split_whitespace().collect();
                                if !parts.is_empty() {
                                    let ip = parts[0].to_string();
                                    if !ip.is_empty()
                                        && !sessions
                                            .iter()
                                            .any(|s: &ActiveUserSession| s.ip_origin == ip)
                                    {
                                        sessions.push(ActiveUserSession {
                                            user: "ssh-session".to_string(),
                                            tty: format!("pid-{}", pid),
                                            ip_origin: ip,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Parse IPv4 connections from /proc/net/tcp
        if sessions.is_empty() {
            if let Ok(tcp_content) = fs::read_to_string("/proc/net/tcp") {
                for line in tcp_content.lines().skip(1) {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    if cols.len() >= 4 {
                        let local_addr = cols[1];
                        let remote_addr = cols[2];
                        let state = cols[3];

                        // State 01 = ESTABLISHED
                        if state == "01" {
                            if let Some(remote_ip) = Self::parse_hex_ipv4(remote_addr, local_addr) {
                                if !sessions
                                    .iter()
                                    .any(|s: &ActiveUserSession| s.ip_origin == remote_ip)
                                {
                                    sessions.push(ActiveUserSession {
                                        user: "remote-client".to_string(),
                                        tty: "tcp".to_string(),
                                        ip_origin: remote_ip,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Parse IPv6 connections from /proc/net/tcp6 (e.g. ::1 or remote IPv6)
        if sessions.is_empty() {
            if let Ok(tcp6_content) = fs::read_to_string("/proc/net/tcp6") {
                for line in tcp6_content.lines().skip(1) {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    if cols.len() >= 4 {
                        let local_addr = cols[1];
                        let remote_addr = cols[2];
                        let state = cols[3];

                        if state == "01" {
                            if let Some(remote_ip) = Self::parse_hex_ipv6(remote_addr, local_addr) {
                                if !sessions
                                    .iter()
                                    .any(|s: &ActiveUserSession| s.ip_origin == remote_ip)
                                {
                                    sessions.push(ActiveUserSession {
                                        user: "remote-client".to_string(),
                                        tty: "tcp6".to_string(),
                                        ip_origin: remote_ip,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        sessions
    }

    fn parse_hex_ipv4(remote: &str, local: &str) -> Option<String> {
        let local_parts: Vec<&str> = local.split(':').collect();
        let remote_parts: Vec<&str> = remote.split(':').collect();

        if local_parts.len() == 2 && remote_parts.len() == 2 {
            let local_port = u16::from_str_radix(local_parts[1], 16).ok()?;
            // Check if local port is standard SSH (22) or commonly used SSH ports
            if local_port == 22 || local_port == 2222 {
                let ip_hex = u32::from_str_radix(remote_parts[0], 16).ok()?;
                // /proc/net/tcp stores IPv4 addresses in little-endian byte order on x86/ARM
                let ip = Ipv4Addr::from(u32::from_be(ip_hex.to_le()));
                let port = u16::from_str_radix(remote_parts[1], 16).ok().unwrap_or(0);
                return Some(format!("{}:{}", ip, port));
            }
        }
        None
    }

    fn parse_hex_ipv6(remote: &str, local: &str) -> Option<String> {
        let local_parts: Vec<&str> = local.split(':').collect();
        let remote_parts: Vec<&str> = remote.split(':').collect();

        if local_parts.len() == 2 && remote_parts.len() == 2 {
            let local_port = u16::from_str_radix(local_parts[1], 16).ok()?;
            if local_port == 22 || local_port == 2222 {
                let remote_hex = remote_parts[0];
                if remote_hex.len() == 32 {
                    if remote_hex == "00000000000000000000000001000000" {
                        return Some("::1 (localhost)".to_string());
                    }
                    return Some("IPv6 remote client".to_string());
                }
            }
        }
        None
    }
}
