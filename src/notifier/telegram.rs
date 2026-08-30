use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tracing::{error, info};

use crate::config::TelegramConfig;
use crate::notifier::{AlertMessage, Notifier};

#[derive(Serialize)]
struct TelegramPayload<'a> {
    chat_id: &'a str,
    text: &'a str,
    disable_notification: bool,
}

pub struct TelegramNotifier {
    config: TelegramConfig,
    client: Client,
    api_url: String,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_secs.max(1));
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        let api_url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            config.bot_token
        );

        Self {
            config,
            client,
            api_url,
        }
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    async fn send_alert(
        &self,
        alert: &AlertMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            return Ok(());
        }

        let message_text = alert.format_text();
        let payload = TelegramPayload {
            chat_id: &self.config.chat_id,
            text: &message_text,
            disable_notification: self.config.silent,
        };

        let response = self
            .client
            .post(&self.api_url)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Telegram alert dispatched successfully: {}", alert.title);
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Telegram API error (status {}): {}", status, body);
            Err(format!("Telegram API error (status {}): {}", status, body).into())
        }
    }
}
