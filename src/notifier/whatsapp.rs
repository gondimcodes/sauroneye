use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tracing::{error, info};

use crate::config::WhatsappConfig;
use crate::notifier::{AlertMessage, Notifier};

#[derive(Serialize)]
struct WhatsappPayload<'a> {
    number: &'a str,
    text: &'a str,
}

pub struct WhatsappNotifier {
    config: WhatsappConfig,
    client: Client,
}

impl WhatsappNotifier {
    pub fn new(config: WhatsappConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_secs.max(1));
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self { config, client }
    }
}

#[async_trait]
impl Notifier for WhatsappNotifier {
    async fn send_alert(
        &self,
        alert: &AlertMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            return Ok(());
        }

        let message_text = alert.format_text();
        let payload = WhatsappPayload {
            number: &self.config.recipient_number,
            text: &message_text,
        };

        let response = self
            .client
            .post(&self.config.endpoint_url)
            .header("apikey", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("WhatsApp alert dispatched successfully: {}", alert.title);
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("WhatsApp API error (status {}): {}", status, body);
            Err(format!("WhatsApp API error (status {}): {}", status, body).into())
        }
    }
}
