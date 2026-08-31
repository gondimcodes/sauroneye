use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::config::MsTeamsConfig;
use crate::notifier::{AlertMessage, AlertSeverity, Notifier};

pub struct MsTeamsNotifier {
    enabled: bool,
    sender: Option<mpsc::Sender<AlertMessage>>,
}

#[derive(Deserialize)]
struct AzureOAuthTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct GraphMessageBody<'a> {
    body: GraphItemBody<'a>,
}

#[derive(Serialize)]
struct GraphItemBody<'a> {
    #[serde(rename = "contentType")]
    content_type: &'a str,
    content: String,
}

// Adaptive Cards structures for Webhook mode (if configured)
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

struct TokenCache {
    token: String,
    expires_at: Instant,
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

            let token_cache: Arc<RwLock<Option<TokenCache>>> = Arc::new(RwLock::new(None));

            // Cadence to respect MS Teams incoming limits
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

                        Self::dispatch_message(&client, &config, &token_cache, &warning_msg).await;
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
                        Self::dispatch_message(&client, &config, &token_cache, &recovery_msg).await;
                        suppressed_count = 0;
                    }
                }

                recent_timestamps.push_back(Instant::now());

                Self::dispatch_message(&client, &config, &token_cache, &alert).await;

                tokio::time::sleep(min_interval).await;
            }
        });

        Self {
            enabled: true,
            sender: Some(tx),
        }
    }

    async fn get_access_token(
        client: &Client,
        config: &MsTeamsConfig,
        token_cache: &Arc<RwLock<Option<TokenCache>>>,
    ) -> Option<String> {
        let (tenant_id, client_id, client_secret) =
            match (&config.tenant_id, &config.client_id, &config.client_secret) {
                (Some(t), Some(c), Some(s)) if !t.is_empty() && !c.is_empty() && !s.is_empty() => {
                    (t, c, s)
                }
                _ => return None,
            };

        // Check cached token
        {
            let cache = token_cache.read().await;
            if let Some(ref tc) = *cache {
                if tc.expires_at > Instant::now() + Duration::from_secs(60) {
                    return Some(tc.token.clone());
                }
            }
        }

        // Request new OAuth 2.0 access token
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        );

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
        ];

        match client.post(&token_url).form(&params).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(token_data) = resp.json::<AzureOAuthTokenResponse>().await {
                        let token = token_data.access_token;
                        let expires_at =
                            Instant::now() + Duration::from_secs(token_data.expires_in.max(60));
                        let mut cache = token_cache.write().await;
                        *cache = Some(TokenCache {
                            token: token.clone(),
                            expires_at,
                        });
                        return Some(token);
                    }
                } else {
                    let err_body = resp.text().await.unwrap_or_default();
                    error!("Azure Entra ID OAuth token error: {}", err_body);
                }
            }
            Err(e) => {
                error!("Failed to request Azure OAuth token: {}", e);
            }
        }

        None
    }

    async fn dispatch_message(
        client: &Client,
        config: &MsTeamsConfig,
        token_cache: &Arc<RwLock<Option<TokenCache>>>,
        alert: &AlertMessage,
    ) {
        // Mode 1: Microsoft Graph API (OAuth 2.0 Client Credentials)
        if let (Some(team_id), Some(channel_id)) = (&config.team_id, &config.channel_id) {
            if !team_id.is_empty() && !channel_id.is_empty() {
                Self::dispatch_graph(client, config, token_cache, team_id, channel_id, alert).await;
                return;
            }
        }

        // Mode 2: Incoming Webhook (Fallback if webhook_url is configured)
        if let Some(ref webhook_url) = config.webhook_url {
            if !webhook_url.is_empty() {
                Self::dispatch_webhook(client, webhook_url, alert).await;
                return;
            }
        }

        error!("MS Teams notifier enabled, but neither (tenant_id/client_id/client_secret/team_id/channel_id) nor webhook_url is properly configured.");
    }

    async fn dispatch_graph(
        client: &Client,
        config: &MsTeamsConfig,
        token_cache: &Arc<RwLock<Option<TokenCache>>>,
        team_id: &str,
        channel_id: &str,
        alert: &AlertMessage,
    ) {
        let token = match Self::get_access_token(client, config, token_cache).await {
            Some(t) => t,
            None => {
                error!("Cannot dispatch MS Teams alert: Failed to acquire OAuth2 access token.");
                return;
            }
        };

        let graph_url = format!(
            "https://graph.microsoft.com/v1.0/teams/{}/channels/{}/messages",
            team_id, channel_id
        );

        let (color_hex, title_prefix) = match alert.severity {
            AlertSeverity::Critical => ("#DC2626", "🚨 [SAURONEYE - CRITICAL]"),
            AlertSeverity::Warning => ("#F59E0B", "⚠️ [SAURONEYE - WARNING]"),
            AlertSeverity::Info => ("#2563EB", "ℹ️ [SAURONEYE - INFO]"),
        };

        let html_content = format!(
            "<div style='border-left: 4px solid {}; padding-left: 10px; font-family: Segoe UI, sans-serif;'>\
            <h3 style='margin: 0 0 8px 0; color: {};'>{} {}</h3>\
            <table style='margin-bottom: 8px;'>\
                <tr><td><b>Host:</b></td><td>{}</td></tr>\
                <tr><td><b>Timestamp (UTC):</b></td><td>{}</td></tr>\
            </table>\
            <pre style='background: #f4f4f4; padding: 8px; border-radius: 4px; font-family: monospace;'>{}</pre>\
            </div>",
            color_hex,
            color_hex,
            title_prefix,
            html_escape(&alert.title),
            html_escape(&alert.host),
            html_escape(&alert.timestamp),
            html_escape(&alert.details),
        );

        let payload = GraphMessageBody {
            body: GraphItemBody {
                content_type: "html",
                content: html_content,
            },
        };

        let mut attempts = 0;
        let max_attempts = 3;

        while attempts < max_attempts {
            attempts += 1;
            match client
                .post(&graph_url)
                .bearer_auth(&token)
                .json(&payload)
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        info!(
                            "MS Teams (Graph API) alert dispatched successfully: {}",
                            alert.title
                        );
                        break;
                    } else if status.as_u16() == 429 {
                        warn!(
                            "MS Teams Graph rate limit hit (429). Backing off for 10s (attempt {}/{})",
                            attempts, max_attempts
                        );
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    } else {
                        let body = response.text().await.unwrap_or_default();
                        error!("MS Teams Graph API error (status {}): {}", status, body);
                        break;
                    }
                }
                Err(e) => {
                    error!(
                        "MS Teams Graph network error (attempt {}/{}): {}",
                        attempts, max_attempts, e
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    async fn dispatch_webhook(client: &Client, webhook_url: &str, alert: &AlertMessage) {
        let (color, title_prefix) = match alert.severity {
            AlertSeverity::Critical => ("Attention", "🚨 [SAURONEYE - CRITICAL]"),
            AlertSeverity::Warning => ("Warning", "⚠️ [SAURONEYE - WARNING]"),
            AlertSeverity::Info => ("Accent", "ℹ️ [SAURONEYE - INFO]"),
        };

        let card_title = format!("{} {}", title_prefix, alert.title);

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
                            text: &alert.details,
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
            match client.post(webhook_url).json(&payload).send().await {
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

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
