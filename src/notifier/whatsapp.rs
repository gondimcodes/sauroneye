use async_trait::async_trait;
use reqwest::Client;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::WhatsappConfig;
use crate::notifier::{AlertMessage, AlertSeverity, Notifier};

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

            // WhatsApp rate limiting cadence (1.2s minimum between consecutive requests)
            let min_interval = Duration::from_millis(1200);

            // Circuit Breaker Sliding Window: max 10 alerts per 60 seconds
            const MAX_ALERTS_PER_MINUTE: usize = 10;
            let window_duration = Duration::from_secs(60);
            let mut recent_timestamps: VecDeque<Instant> = VecDeque::new();
            let mut circuit_breaker_active = false;
            let mut suppressed_count = 0usize;

            while let Some(alert) = rx.recv().await {
                let now = Instant::now();

                // Evict entries older than 60s
                while let Some(&front) = recent_timestamps.front() {
                    if now.duration_since(front) > window_duration {
                        recent_timestamps.pop_front();
                    } else {
                        break;
                    }
                }

                // Check if Circuit Breaker condition is triggered
                if recent_timestamps.len() >= MAX_ALERTS_PER_MINUTE {
                    suppressed_count += 1;
                    if !circuit_breaker_active {
                        circuit_breaker_active = true;
                        warn!(
                            "WhatsApp Circuit Breaker TRIGGERED (threshold: {} alerts/min reached). Throttling outgoing WhatsApp messages.",
                            MAX_ALERTS_PER_MINUTE
                        );

                        // Send one consolidated throttling warning message to WhatsApp
                        let warning_msg = AlertMessage::with_timezone(
                            &alert.host,
                            "WhatsApp Alert Throttling Activated (Anti-Flood Circuit Breaker)",
                            AlertSeverity::Warning,
                            &format!(
                                "High frequency of security events detected (exceeded {} alerts/min).\n\n\
                                🛡️ WhatsApp messaging is temporarily throttled to protect your account against anti-spam bans.\n\
                                📋 100% of events continue being audited in SQLite and forensic PDF reports.",
                                MAX_ALERTS_PER_MINUTE
                            ),
                            true,
                        );

                        Self::dispatch_raw(
                            &client,
                            &config,
                            &warning_msg.format_text(),
                            &warning_msg.title,
                        )
                        .await;
                    }
                    continue;
                }

                // When volume normalizes below threshold
                if circuit_breaker_active && recent_timestamps.len() < MAX_ALERTS_PER_MINUTE {
                    circuit_breaker_active = false;
                    if suppressed_count > 0 {
                        info!(
                            "WhatsApp Circuit Breaker RESET. Suppressed {} alerts during burst window.",
                            suppressed_count
                        );
                        let recovery_msg = AlertMessage::with_timezone(
                            &alert.host,
                            "WhatsApp Alerting Resumed",
                            AlertSeverity::Info,
                            &format!(
                                "Traffic normalized. {} alerts were suppressed on WhatsApp during the burst and securely preserved in forensic database.",
                                suppressed_count
                            ),
                            true,
                        );
                        Self::dispatch_raw(
                            &client,
                            &config,
                            &recovery_msg.format_text(),
                            &recovery_msg.title,
                        )
                        .await;
                        suppressed_count = 0;
                    }
                }

                recent_timestamps.push_back(Instant::now());

                let message_text = alert.format_text();
                Self::dispatch_raw(&client, &config, &message_text, &alert.title).await;

                tokio::time::sleep(min_interval).await;
            }
        });

        Self {
            enabled: true,
            sender: Some(tx),
        }
    }

    async fn dispatch_raw(
        client: &Client,
        config: &WhatsappConfig,
        message_text: &str,
        alert_title: &str,
    ) {
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
                .text("message", message_text.to_string());

            match request.multipart(form).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        info!("WhatsApp alert dispatched successfully: {}", alert_title);
                        break;
                    } else if status.as_u16() == 429 {
                        warn!(
                            "WhatsApp rate limit hit (429). Backing off for 15s (attempt {}/{})",
                            attempts, max_attempts
                        );
                        tokio::time::sleep(Duration::from_secs(15)).await;
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
