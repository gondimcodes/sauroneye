use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::MsTeamsConfig;
use crate::notifier::{AlertMessage, AlertSeverity, Notifier};

pub struct MsTeamsNotifier {
    enabled: bool,
    sender: Option<mpsc::Sender<AlertMessage>>,
}

#[derive(Serialize)]
struct AdaptiveCardEnvelope<'a> {
    #[serde(rename = "type")]
    msg_type: &'a str,
    attachments: Vec<AdaptiveCardAttachment<'a>>,
}

#[derive(Serialize)]
struct AdaptiveCardAttachment<'a> {
    #[serde(rename = "contentType")]
    content_type: &'a str,
    content: AdaptiveCardContent<'a>,
}

#[derive(Serialize)]
struct AdaptiveCardContent<'a> {
    #[serde(rename = "$schema")]
    schema: &'a str,
    #[serde(rename = "type")]
    card_type: &'a str,
    version: &'a str,
    body: Vec<AdaptiveCardElement<'a>>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum AdaptiveCardElement<'a> {
    TextBlock {
        text: &'a str,
        weight: &'a str,
        size: &'a str,
        color: &'a str,
        wrap: bool,
    },
    FactSet {
        facts: Vec<AdaptiveCardFact<'a>>,
    },
}

#[derive(Serialize)]
struct AdaptiveCardFact<'a> {
    title: &'a str,
    value: &'a str,
}

impl MsTeamsNotifier {
    pub fn new(config: MsTeamsConfig) -> Self {
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

            // Cadence to respect MS Teams incoming webhook rate limit (~4 req/sec per webhook)
            let min_interval = Duration::from_millis(800);

            // Circuit Breaker: max 20 alerts per 60s
            const MAX_ALERTS_PER_MINUTE: usize = 20;
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
                            "MS Teams Circuit Breaker TRIGGERED (threshold: {} alerts/min reached). Throttling outgoing Teams messages.",
                            MAX_ALERTS_PER_MINUTE
                        );

                        let warning_msg = AlertMessage::with_timezone(
                            &alert.host,
                            "MS Teams Alert Throttling Activated (Anti-Flood Circuit Breaker)",
                            AlertSeverity::Warning,
                            &format!(
                                "High frequency of security events detected (exceeded {} alerts/min).\n\n\
                                🛡️ Microsoft Teams notifications are temporarily throttled to avoid rate limits.\n\
                                📋 100% of events continue being audited in SQLite and forensic PDF reports.",
                                MAX_ALERTS_PER_MINUTE
                            ),
                            true,
                        );

                        Self::dispatch_card(&client, &config, &warning_msg).await;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }

                // When traffic normalizes below threshold
                if circuit_breaker_active {
                    circuit_breaker_active = false;
                    if suppressed_count > 0 {
                        info!(
                            "MS Teams Circuit Breaker RESET. Suppressed {} alerts during burst window.",
                            suppressed_count
                        );
                        let recovery_msg = AlertMessage::with_timezone(
                            &alert.host,
                            "MS Teams Alerting Resumed",
                            AlertSeverity::Info,
                            &format!(
                                "Traffic normalized. {} alerts were suppressed on Microsoft Teams during the burst and securely preserved in forensic database.",
                                suppressed_count
                            ),
                            true,
                        );
                        Self::dispatch_card(&client, &config, &recovery_msg).await;
                        suppressed_count = 0;
                    }
                }

                recent_timestamps.push_back(Instant::now());

                Self::dispatch_card(&client, &config, &alert).await;

                tokio::time::sleep(min_interval).await;
            }
        });

        Self {
            enabled: true,
            sender: Some(tx),
        }
    }

    async fn dispatch_card(client: &Client, config: &MsTeamsConfig, alert: &AlertMessage) {
        let (color, title_prefix) = match alert.severity {
            AlertSeverity::Critical => ("Attention", "🚨 [SAURONEYE - CRITICAL]"),
            AlertSeverity::Warning => ("Warning", "⚠️ [SAURONEYE - WARNING]"),
            AlertSeverity::Info => ("Accent", "ℹ️ [SAURONEYE - INFO]"),
        };

        let card_title = format!("{} {}", title_prefix, alert.title);

        // Teams Adaptive Card TextBlock does not interpret bare \n as line breaks.
        // Markdown line-break syntax requires two trailing spaces before \n.
        let details_md = alert.details.replace('\n', "  \n");

        let payload = AdaptiveCardEnvelope {
            msg_type: "message",
            attachments: vec![AdaptiveCardAttachment {
                content_type: "application/vnd.microsoft.card.adaptive",
                content: AdaptiveCardContent {
                    schema: "http://adaptivecards.io/schemas/adaptive-card.json",
                    card_type: "AdaptiveCard",
                    version: "1.4",
                    body: vec![
                        AdaptiveCardElement::TextBlock {
                            text: &card_title,
                            weight: "Bolder",
                            size: "Medium",
                            color,
                            wrap: true,
                        },
                        AdaptiveCardElement::FactSet {
                            facts: vec![
                                AdaptiveCardFact {
                                    title: "Host:",
                                    value: &alert.host,
                                },
                                AdaptiveCardFact {
                                    title: "Timestamp:",
                                    value: &alert.timestamp,
                                },
                            ],
                        },
                        AdaptiveCardElement::TextBlock {
                            text: &details_md,
                            weight: "Default",
                            size: "Default",
                            color: "Default",
                            wrap: true,
                        },
                    ],
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
                        info!("MS Teams alert dispatched successfully: {}", alert.title);
                        break;
                    } else if status.as_u16() == 429 {
                        warn!(
                            "MS Teams rate limit hit (429). Backing off for 10s (attempt {}/{})",
                            attempts, max_attempts
                        );
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    } else {
                        let body = response.text().await.unwrap_or_default();
                        error!("MS Teams API error (status {}): {}", status, body);
                        break;
                    }
                }
                Err(e) => {
                    error!(
                        "MS Teams network error (attempt {}/{}): {}",
                        attempts, max_attempts, e
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
}

#[async_trait]
impl Notifier for MsTeamsNotifier {
    async fn send_alert(
        &self,
        alert: &AlertMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.enabled {
            return Ok(());
        }

        if let Some(ref tx) = self.sender {
            if let Err(e) = tx.send(alert.clone()).await {
                error!("Failed to enqueue MS Teams alert: {}", e);
            }
        }
        Ok(())
    }
}
