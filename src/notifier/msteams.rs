use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::MsTeamsConfig;
use crate::notifier::shared::{retry_http_post, BreakerDecision, CircuitBreaker};
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

            // QC-09: CircuitBreaker replaces the previous inline VecDeque sliding-window logic
            let mut breaker = CircuitBreaker::new(20); // max 20 alerts/min

            while let Some(alert) = rx.recv().await {
                match breaker.check() {
                    BreakerDecision::Suppress { first_open } => {
                        if first_open {
                            warn!(
                                "MS Teams Circuit Breaker TRIGGERED (threshold: 20 alerts/min reached). Throttling outgoing Teams messages."
                            );
                            let warning_msg = AlertMessage::with_timezone(
                                &alert.host,
                                "MS Teams Alert Throttling Activated (Anti-Flood Circuit Breaker)",
                                AlertSeverity::Warning,
                                "High frequency of security events detected (exceeded 20 alerts/min).\n\n\
                                🛡️ Microsoft Teams notifications are temporarily throttled to avoid rate limits.\n\
                                📋 100% of events continue being audited in SQLite and forensic PDF reports.",
                                true,
                            );
                            Self::dispatch_card(&client, &config, &warning_msg).await;
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    BreakerDecision::JustRecovered { suppressed } => {
                        if suppressed > 0 {
                            info!(
                                "MS Teams Circuit Breaker RESET. Suppressed {} alerts during burst window.",
                                suppressed
                            );
                            let recovery_msg = AlertMessage::with_timezone(
                                &alert.host,
                                "MS Teams Alerting Resumed",
                                AlertSeverity::Info,
                                &format!(
                                    "Traffic normalized. {} alerts were suppressed on Microsoft Teams during the burst and securely preserved in forensic database.",
                                    suppressed
                                ),
                                true,
                            );
                            Self::dispatch_card(&client, &config, &recovery_msg).await;
                        }
                    }
                    BreakerDecision::Pass => {}
                }

                breaker.record_sent();
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
                    schema: "https://adaptivecards.io/schemas/adaptive-card.json",
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

        // QC-10: retry_http_post replaces the previous inline retry loop
        let sent = retry_http_post(
            client,
            &config.webhook_url,
            &payload,
            3,
            Duration::from_secs(10),
            Duration::from_secs(2),
            "MS Teams",
        )
        .await;

        if sent {
            info!("MS Teams alert dispatched successfully: {}", alert.title);
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
