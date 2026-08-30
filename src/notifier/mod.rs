pub mod telegram;
pub mod whatsapp;

use async_trait::async_trait;
use std::sync::Arc;
use tracing::error;

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
        let now = chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();
        Self {
            host: host.to_string(),
            title: title.to_string(),
            severity,
            details: details.to_string(),
            timestamp: now,
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
}

impl AlertDispatcher {
    pub fn new() -> Self {
        Self {
            notifiers: Vec::new(),
        }
    }

    pub fn add_notifier(&mut self, notifier: Arc<dyn Notifier>) {
        self.notifiers.push(notifier);
    }

    pub async fn dispatch(&self, alert: AlertMessage) {
        for notifier in &self.notifiers {
            if let Err(e) = notifier.send_alert(&alert).await {
                error!("Failed to dispatch alert to notifier: {}", e);
            }
        }
    }
}
