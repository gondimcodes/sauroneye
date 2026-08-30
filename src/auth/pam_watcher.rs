use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub user: String,
    pub service: String,
    pub rhost: Option<String>,
    pub tty: Option<String>,
    pub success: bool,
    pub raw_message: String,
}

pub struct PamWatcher {
    log_path: String,
    last_pos: u64,
}

impl PamWatcher {
    pub fn new() -> Self {
        let candidates = ["/var/log/auth.log", "/var/log/secure"];
        let log_path = candidates
            .iter()
            .find(|&&p| Path::new(p).exists())
            .unwrap_or(&"/var/log/auth.log")
            .to_string();

        let initial_pos = if let Ok(metadata) = std::fs::metadata(&log_path) {
            metadata.len()
        } else {
            0
        };

        Self {
            log_path,
            last_pos: initial_pos,
        }
    }

    pub fn poll_new_events(&mut self) -> io::Result<Vec<AuthEvent>> {
        let file = match File::open(&self.log_path) {
            Ok(f) => f,
            Err(_) => return Ok(Vec::new()),
        };

        let mut reader = BufReader::new(file);
        let current_len = reader.get_ref().metadata()?.len();

        if current_len < self.last_pos {
            // Log rotated
            self.last_pos = 0;
        }

        reader.seek(SeekFrom::Start(self.last_pos))?;
        let mut events = Vec::new();
        let mut line = String::new();

        while reader.read_line(&mut line)? > 0 {
            if let Some(event) = Self::parse_auth_line(&line) {
                events.push(event);
            }
            line.clear();
        }

        self.last_pos = reader.stream_position()?;
        Ok(events)
    }

    fn parse_auth_line(line: &str) -> Option<AuthEvent> {
        let lower = line.to_lowercase();

        // Avoid duplicate SSH alerts: sshd already logs "Accepted publickey/password" with real origin IP,
        // so ignore the redundant "pam_unix(sshd:session): session opened" event
        if lower.contains("sshd") && lower.contains("session opened for user") {
            return None;
        }

        if lower.contains("accepted password")
            || lower.contains("accepted publickey")
            || lower.contains("session opened for user")
            || lower.contains("authentication failure")
            || lower.contains("failed password")
        {
            let is_success = !lower.contains("failure") && !lower.contains("failed");
            let user = if let Some(idx) = line.find("for user ") {
                line[idx + 9..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("unknown")
                    .to_string()
            } else if let Some(idx) = line.find("for ") {
                line[idx + 4..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                "unknown".to_string()
            };

            let rhost = if let Some(idx) = line.find("from ") {
                line[idx + 5..]
                    .split_whitespace()
                    .next()
                    .map(|s| s.to_string())
            } else {
                None
            };

            let service = if lower.contains("sshd") {
                "sshd".to_string()
            } else if lower.contains("cron") {
                "cron".to_string()
            } else if lower.contains("sudo") {
                "sudo".to_string()
            } else if lower.contains("su:") {
                "su".to_string()
            } else {
                "pam".to_string()
            };

            return Some(AuthEvent {
                user,
                service,
                rhost,
                tty: None,
                success: is_success,
                raw_message: line.trim().to_string(),
            });
        }
        None
    }
}
