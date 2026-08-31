use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::DiscordConfig;
use crate::notifier::{AlertMessage, AlertSeverity, Notifier};

pub struct DiscordNotifier {
    enabled: bool,
    sender: Option<mpsc::Sender<AlertMessage>>,
}

#[derive(Serialize)]
struct DiscordWebhookPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_url: Option<&'a str>,
    embeds: Vec<DiscordEmbed<'a>>,
}

#[derive(Serialize)]
struct DiscordEmbed<'a> {
    title: &'a str,
    color: u32,
    fields: Vec<DiscordEmbedField<'a>>,
    description: &'a str,
    footer: DiscordEmbedFooter<'a>,
}

#[derive(Serialize)]
struct DiscordEmbedField<'a> {
    name: &'a str,
    value: &'a str,
    inline: bool,
}

#[derive(Serialize)]
struct DiscordEmbedFooter<'a> {
    text: &'a str,
}

impl DiscordNotifier {
    pub fn new(config: DiscordConfig) -> Self {
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

            // Discord rate limit per webhook is 5 requests per 2 seconds (safe cadence: 500ms)
            let min_interval = Duration::from_millis(500);

            // Circuit Breaker: max 30 alerts per 60 seconds
            const MAX_ALERTS_PER_MINUTE: usize = 30;
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

                // Check Circuit Breaker threshold
                if recent_timestamps.len() >= MAX_ALERTS_PER_MINUTE {
                    suppressed_count += 1;
                    if !circuit_breaker_active {
                        circuit_breaker_active = true;
                        warn!(
                            "Discord Circuit Breaker TRIGGERED (threshold: {} alerts/min reached). Throttling outgoing Discord messages.",
                            MAX_ALERTS_PER_MINUTE
                        );

                        let warning_msg = AlertMessage::with_timezone(
                            &alert.host,
                            "Discord Alert Throttling Activated (Anti-Flood Circuit Breaker)",
                            AlertSeverity::Warning,
                            &format!(
                                "High frequency of security events detected (exceeded {} alerts/min).\n\n\
                                🛡️ Discord notifications are temporarily throttled to avoid rate limits.\n\
                                📋 100% of events continue being audited in SQLite and forensic PDF reports.",
                                MAX_ALERTS_PER_MINUTE
                            ),
                            true,
                        );

                        Self::dispatch_embed(&client, &config, &warning_msg).await;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }

                // When traffic normalizes
                if circuit_breaker_active {
                    circuit_breaker_active = false;
                    if suppressed_count > 0 {
                        info!(
                            "Discord Circuit Breaker RESET. Suppressed {} alerts during burst window.",
                            suppressed_count
                        );
                        let recovery_msg = AlertMessage::with_timezone(
                            &alert.host,
                            "Discord Alerting Resumed",
                            AlertSeverity::Info,
                            &format!(
                                "Traffic normalized. {} alerts were suppressed on Discord during the burst and securely preserved in forensic database.",
                                suppressed_count
                            ),
                            true,
                        );
                        Self::dispatch_embed(&client, &config, &recovery_msg).await;
                        suppressed_count = 0;
                    }
                }

                recent_timestamps.push_back(Instant::now());

                Self::dispatch_embed(&client, &config, &alert).await;

                tokio::time::sleep(min_interval).await;
            }
        });

        Self {
            enabled: true,
            sender: Some(tx),
        }
    }

    async fn dispatch_embed(client: &Client, config: &DiscordConfig, alert: &AlertMessage) {
        // Color coding (Hex in Decimal): Critical (Red 0xDC2626 = 14427686), Warning (Orange 0xF59E0B = 16096779), Info (Blue 0x2563EB = 2450411)
        let (color, title_prefix) = match alert.severity {
            AlertSeverity::Critical => (14427686u32, "🚨 [SAURONEYE - CRITICAL]"),
            AlertSeverity::Warning => (16096779u32, "⚠️ [SAURONEYE - WARNING]"),
            AlertSeverity::Info => (2450411u32, "ℹ️ [SAURONEYE - INFO]"),
        };

        let embed_title = format!("{} {}", title_prefix, alert.title);

        let payload = DiscordWebhookPayload {
            username: config.username.as_deref().or(Some("SauronEye Sentinel")),
            avatar_url: config.avatar_url.as_deref(),
            embeds: vec![DiscordEmbed {
                title: &embed_title,
                color,
                description: &alert.details,
                fields: vec![
                    DiscordEmbedField {
                        name: "Host",
                        value: &alert.host,
                        inline: true,
                    },
                    DiscordEmbedField {
                        name: "Timestamp (UTC)",
                        value: &alert.timestamp,
                        inline: true,
                    },
                ],
                footer: DiscordEmbedFooter {
                    text: "SauronEye Security Sentinel",
                },
            }],
        };

        let mut attempts = 0;
        let max_attempts = 3;

        while attempts < max_attempts {
            attempts += 1;
            match client.post(&config.webhook_url).json(&payload).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        info!("Discord alert dispatched successfully: {}", alert.title);
                        break;
                    } else if status.as_u16() == 429 {
                        warn!(
                            "Discord rate limit hit (429). Backing off for 5s (attempt {}/{})",
                            attempts, max_attempts
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    } else {
                        let body = response.text().await.unwrap_or_default();
                        error!("Discord API error (status {}): {}", status, body);
                        break;
                    }
                }
                Err(e) => {
                    error!(
                        "Discord network error (attempt {}/{}): {}",
                        attempts, max_attempts, e
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
}

#[async_trait]
impl Notifier for DiscordNotifier {
    async fn send_alert(
        &self,
        alert: &AlertMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.enabled {
            return Ok(());
        }

        if let Some(ref tx) = self.sender {
            if let Err(e) = tx.send(alert.clone()).await {
                error!("Failed to enqueue Discord alert: {}", e);
            }
        }
        Ok(())
    }
}
