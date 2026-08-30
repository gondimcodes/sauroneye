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

        let mut request = self.client.post(&self.config.endpoint_url);

        // Include Authorization / apikey header only if api_key is non-empty
        let key_trimmed = self.config.api_key.trim();
        if !key_trimmed.is_empty() {
            request = request
                .header("apikey", key_trimmed)
                .header("Authorization", format!("Bearer {}", key_trimmed));
        }

        // Send as multipart/form-data for whatsapp-bridge compatibility with fallback payload
        let form = reqwest::multipart::Form::new()
            .text("number", self.config.recipient_number.clone())
            .text("message", message_text.clone());

        let response = request.multipart(form).send().await?;

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
