use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::TelegramConfig;
use crate::notifier::{AlertMessage, Notifier};

#[derive(Serialize)]
struct TelegramPayload<'a> {
    chat_id: &'a str,
    text: &'a str,
    disable_notification: bool,
}

#[derive(Deserialize, Debug)]
struct TelegramRateLimitResponse {
    parameters: Option<TelegramResponseParameters>,
}

#[derive(Deserialize, Debug)]
struct TelegramResponseParameters {
    retry_after: Option<u64>,
}

pub struct TelegramNotifier {
    enabled: bool,
    sender: Option<mpsc::Sender<AlertMessage>>,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig) -> Self {
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
            let api_url = format!(
                "https://api.telegram.org/bot{}/sendMessage",
                config.bot_token
            );

            // Minimum interval between Telegram messages to avoid 429 errors (Telegram limits ~1 msg/sec per chat)
            let min_interval = Duration::from_millis(1050);

            while let Some(alert) = rx.recv().await {
                let message_text = alert.format_text();
                let mut attempts = 0;
                let max_attempts = 3;

                while attempts < max_attempts {
                    attempts += 1;
                    let payload = TelegramPayload {
                        chat_id: &config.chat_id,
                        text: &message_text,
                        disable_notification: config.silent,
                    };

                    match client.post(&api_url).json(&payload).send().await {
                        Ok(response) => {
                            let status = response.status();
                            if status.is_success() {
                                info!("Telegram alert dispatched successfully: {}", alert.title);
                                break;
                            } else if status.as_u16() == 429 {
                                let mut sleep_secs = 5;
                                if let Ok(parsed) =
                                    response.json::<TelegramRateLimitResponse>().await
                                {
                                    if let Some(params) = parsed.parameters {
                                        if let Some(ra) = params.retry_after {
                                            sleep_secs = ra.max(1);
                                        }
                                    }
                                }
                                warn!(
                                    "Telegram rate limit hit (429). Backing off for {}s before retry (attempt {}/{})",
                                    sleep_secs, attempts, max_attempts
                                );
                                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
                            } else {
                                let body = response.text().await.unwrap_or_default();
                                error!("Telegram API error (status {}): {}", status, body);
                                break;
                            }
                        }
                        Err(e) => {
                            error!(
                                "Telegram network error (attempt {}/{}): {}",
                                attempts, max_attempts, e
                            );
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                }

                // Rate limiting pause between dispatches
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
impl Notifier for TelegramNotifier {
    async fn send_alert(
        &self,
        alert: &AlertMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.enabled {
            return Ok(());
        }

        if let Some(ref tx) = self.sender {
            if let Err(e) = tx.send(alert.clone()).await {
                error!("Failed to enqueue Telegram alert: {}", e);
            }
        }
        Ok(())
    }
}
