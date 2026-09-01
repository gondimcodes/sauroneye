pub mod discord;
pub mod email;
pub mod msteams;
pub mod shared;
pub mod telegram;
pub mod whatsapp;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::error;

pub use discord::DiscordNotifier;
pub use email::SmtpNotifier;
pub use msteams::MsTeamsNotifier;
pub use telegram::TelegramNotifier;
pub use whatsapp::WhatsappNotifier;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl AlertSeverity {
    pub fn icon(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "ℹ️",
            AlertSeverity::Warning => "⚠️",
            AlertSeverity::Critical => "🚨",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "INFO",
            AlertSeverity::Warning => "WARNING",
            AlertSeverity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AlertMessage {
    pub host: String,
    pub title: String,
    pub severity: AlertSeverity,
    pub details: String,
    pub timestamp: String,
}

impl AlertMessage {
    pub fn new(host: &str, title: &str, severity: AlertSeverity, details: &str) -> Self {
        Self::with_timezone(host, title, severity, details, true)
    }

    pub fn with_timezone(
        host: &str,
        title: &str,
        severity: AlertSeverity,
        details: &str,
        use_utc: bool,
    ) -> Self {
        let timestamp = if use_utc {
            chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
        } else {
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
        };

        Self {
            host: host.to_string(),
            title: title.to_string(),
            severity,
            details: details.to_string(),
            timestamp,
        }
    }

    pub fn format_text(&self) -> String {
        format!(
            "{} [SAURONEYE - {}]\nHost: {}\nTimestamp: {}\n\n*{}*\n{}",
            self.severity.icon(),
            self.severity.as_str(),
            self.host,
            self.timestamp,
            self.title,
            self.details
        )
    }
}

#[async_trait]
pub trait Notifier: Send + Sync {
    async fn send_alert(
        &self,
        alert: &AlertMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

pub struct AlertDispatcher {
    notifiers: Vec<Arc<dyn Notifier>>,
    recent_dispatches: Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

impl AlertDispatcher {
    pub fn new() -> Self {
        Self {
            notifiers: Vec::new(),
            recent_dispatches: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn add_notifier(&mut self, notifier: Arc<dyn Notifier>) {
        self.notifiers.push(notifier);
    }

    pub async fn dispatch(&self, alert: AlertMessage) {
        // Deduplicação Global: Impede que qualquer alerta exatamente igual (mesmo título e detalhes)
        // seja disparado em duplicidade dentro de 2.5 segundos
        let dedup_key = format!("{}::{}", alert.title, alert.details);
        let now = std::time::Instant::now();
        {
            let mut map = self.recent_dispatches.lock().await;
            // Remove entradas antigas para não acumular memória
            map.retain(|_, v| now.duration_since(*v) < std::time::Duration::from_secs(10));

            if let Some(last_time) = map.get(&dedup_key) {
                if now.duration_since(*last_time) < std::time::Duration::from_millis(2500) {
                    return;
                }
            }
            map.insert(dedup_key, now);
        }

        for notifier in &self.notifiers {
            if let Err(e) = notifier.send_alert(&alert).await {
                error!("Failed to dispatch alert to notifier: {}", e);
            }
        }
    }
}
