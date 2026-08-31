use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::WhatsappConfig;
use crate::notifier::{AlertMessage, Notifier};

pub struct WhatsappNotifier {
    enabled: bool,
    sender: Option<mpsc::Sender<AlertMessage>>,
}

impl WhatsappNotifier {
    pub fn new(config: WhatsappConfig) -> Self {
        if !config.enabled {
            return Self {
                enabled: false,
                sender: None,
            };
        }

        let (tx, mut rx) = mpsc::channel::<AlertMessage>(256);

        tokio::spawn(async move {
            let timeout = Duration::from_secs(config.timeout_secs.max(1));
            let client = Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default();

            // WhatsApp rate limiting interval (1.2s to be conservative with bridge instances)
            let min_interval = Duration::from_millis(1200);

            while let Some(alert) = rx.recv().await {
                let message_text = alert.format_text();
                let mut attempts = 0;
                let max_attempts = 3;

                while attempts < max_attempts {
                    attempts += 1;
                    let mut request = client.post(&config.endpoint_url);

                    let key_trimmed = config.api_key.trim();
                    if !key_trimmed.is_empty() {
                        request = request
                            .header("apikey", key_trimmed)
                            .header("Authorization", format!("Bearer {}", key_trimmed));
                    }

                    let form = reqwest::multipart::Form::new()
                        .text("number", config.recipient_number.clone())
                        .text("message", message_text.clone());

                    match request.multipart(form).send().await {
                        Ok(response) => {
                            let status = response.status();
                            if status.is_success() {
                                info!("WhatsApp alert dispatched successfully: {}", alert.title);
                                break;
                            } else if status.as_u16() == 429 {
                                warn!(
                                    "WhatsApp rate limit hit (429). Backing off for 10s (attempt {}/{})",
                                    attempts, max_attempts
                                );
                                tokio::time::sleep(Duration::from_secs(10)).await;
                            } else {
                                let body = response.text().await.unwrap_or_default();
                                error!("WhatsApp API error (status {}): {}", status, body);
                                break;
                            }
                        }
                        Err(e) => {
                            error!(
                                "WhatsApp network error (attempt {}/{}): {}",
                                attempts, max_attempts, e
                            );
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                }

                tokio::time::sleep(min_interval).await;
            }
        });

        Self {
            enabled: true,
            sender: Some(tx),
        }
    }
}

#[async_trait]
impl Notifier for WhatsappNotifier {
    async fn send_alert(
        &self,
        alert: &AlertMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.enabled {
            return Ok(());
        }

        if let Some(ref tx) = self.sender {
            if let Err(e) = tx.send(alert.clone()).await {
                error!("Failed to enqueue WhatsApp alert: {}", e);
            }
        }
        Ok(())
    }
}
