use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::DiscordConfig;
use crate::notifier::shared::{retry_http_post, BreakerDecision, CircuitBreaker};
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

            // QC-09: CircuitBreaker replaces the previous inline VecDeque sliding-window logic
            let mut breaker = CircuitBreaker::new(30); // max 30 alerts/min

            while let Some(alert) = rx.recv().await {
                match breaker.check() {
                    BreakerDecision::Suppress { first_open } => {
                        if first_open {
                            warn!(
                                "Discord Circuit Breaker TRIGGERED (threshold: 30 alerts/min reached). Throttling outgoing Discord messages."
                            );
                            let warning_msg = AlertMessage::with_timezone(
                                &alert.host,
                                "Discord Alert Throttling Activated (Anti-Flood Circuit Breaker)",
                                AlertSeverity::Warning,
                                "High frequency of security events detected (exceeded 30 alerts/min).\n\n\
                                🛡️ Discord notifications are temporarily throttled to avoid rate limits.\n\
                                📋 100% of events continue being audited in SQLite and forensic PDF reports.",
                                true,
                            );
                            Self::dispatch_embed(&client, &config, &warning_msg).await;
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    BreakerDecision::JustRecovered { suppressed } => {
                        if suppressed > 0 {
                            info!(
                                "Discord Circuit Breaker RESET. Suppressed {} alerts during burst window.",
                                suppressed
                            );
                            let recovery_msg = AlertMessage::with_timezone(
                                &alert.host,
                                "Discord Alerting Resumed",
                                AlertSeverity::Info,
                                &format!(
                                    "Traffic normalized. {} alerts were suppressed on Discord during the burst and securely preserved in forensic database.",
                                    suppressed
                                ),
                                true,
                            );
                            Self::dispatch_embed(&client, &config, &recovery_msg).await;
                        }
                    }
                    BreakerDecision::Pass => {}
                }

                breaker.record_sent();
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

        // QC-10: retry_http_post replaces the previous inline retry loop
        let sent = retry_http_post(
            client,
            &config.webhook_url,
            &payload,
            3,
            Duration::from_secs(5),
            Duration::from_secs(2),
            "Discord",
        )
        .await;

        if sent {
            info!("Discord alert dispatched successfully: {}", alert.title);
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
