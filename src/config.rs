use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub database: DatabaseConfig,
    pub fim: FimConfig,
    #[serde(default)]
    pub distro_exclusions: DistroExclusionsConfig,
    #[serde(default)]
    pub package_manager: PackageManagerConfig,
    #[serde(default)]
    pub auth_monitor: AuthMonitorConfig,
    #[serde(default)]
    pub rce_detector: RceDetectorConfig,
    pub notifications: NotificationsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_true")]
    pub use_utc_time: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    #[serde(default = "default_true")]
    pub enable_wal: bool,
    #[serde(default = "default_batch_flush_interval")]
    pub batch_flush_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimConfig {
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,
    pub include_paths: Vec<PathBuf>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default = "default_distro")]
    pub distro_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DistroExclusionsConfig {
    #[serde(default)]
    pub debian: Vec<String>,
    #[serde(default)]
    pub redhat: Vec<String>,
    #[serde(default)]
    pub alpine: Vec<String>,
    #[serde(default)]
    pub arch: Vec<String>,
}

fn default_distro() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManagerConfig {
    #[serde(default = "default_true")]
    pub auto_detect: bool,
    #[serde(default = "default_true")]
    pub check_package_db: bool,
    #[serde(default = "default_false")]
    pub notify_legitimate_updates: bool,
}

impl Default for PackageManagerConfig {
    fn default() -> Self {
        Self {
            auto_detect: true,
            check_package_db: true,
            notify_legitimate_updates: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMonitorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub monitor_successful_logins: bool,
    #[serde(default = "default_true")]
    pub monitor_failed_attempts: bool,
    #[serde(default = "default_true")]
    pub track_sudo_elevation: bool,
    #[serde(default = "default_true")]
    pub ignore_cron_sessions: bool,
}

impl Default for AuthMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitor_successful_logins: true,
            monitor_failed_attempts: true,
            track_sudo_elevation: true,
            ignore_cron_sessions: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RceDetectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_protected_services")]
    pub protected_services: Vec<String>,
    #[serde(default = "default_forbidden_children")]
    pub forbidden_children: Vec<String>,
}

impl Default for RceDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protected_services: default_protected_services(),
            forbidden_children: default_forbidden_children(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    #[serde(default)]
    pub whatsapp: Option<WhatsappConfig>,
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    #[serde(default)]
    pub enabled: bool,
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    #[serde(default)]
    pub to_default: Option<String>,
    #[serde(default = "default_true")]
    pub use_tls: bool,
}

fn default_smtp_port() -> u16 {
    587
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    #[serde(default)]
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
    #[serde(default)]
    pub silent: bool,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsappConfig {
    #[serde(default)]
    pub enabled: bool,
    pub endpoint_url: String,
    pub api_key: String,
    pub recipient_number: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

// Defaults
fn default_hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "sauron-node".to_string())
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_poll_interval() -> u64 {
    500
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_batch_flush_interval() -> u64 {
    1000
}

fn default_backend() -> String {
    "auto".to_string()
}

fn default_hash_algorithm() -> String {
    "blake3".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

fn default_protected_services() -> Vec<String> {
    vec![
        "nginx".to_string(),
        "apache2".to_string(),
        "httpd".to_string(),
        "php-fpm".to_string(),
        "named".to_string(),
        "unbound".to_string(),
        "mysqld".to_string(),
        "redis-server".to_string(),
    ]
}

fn default_forbidden_children() -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "/bin/bash".to_string(),
        "/bin/dash".to_string(),
        "/usr/bin/python*".to_string(),
        "/usr/bin/perl".to_string(),
        "/usr/bin/curl".to_string(),
        "/usr/bin/wget".to_string(),
        "/usr/bin/nc".to_string(),
        "/usr/bin/ncat".to_string(),
        "/usr/bin/socat".to_string(),
    ]
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| {
            format!(
                "Failed to read config file at {}: {}",
                path.as_ref().display(),
                e
            )
        })?;
        let config: Config =
            toml::from_str(&content).map_err(|e| format!("Failed to parse config file: {}", e))?;
        Ok(config)
    }
}
