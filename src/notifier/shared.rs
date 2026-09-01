/// Shared utilities for notifier implementations.
///
/// This module provides reusable building blocks that were previously duplicated
/// verbatim across `discord.rs`, `msteams.rs`, and `whatsapp.rs`:
///  - `CircuitBreaker`: sliding-window rate limiter that suppresses alerts during bursts
///  - `retry_http_post`: generic retry helper with per-status-code backoff
use reqwest::Client;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::warn;

// ──────────────────────────────────────────────────────────────────────────────
// CircuitBreaker
// ──────────────────────────────────────────────────────────────────────────────

/// Result returned by [`CircuitBreaker::check`].
pub enum BreakerDecision {
    /// Alert should be suppressed; `first_open` is true only on the very first trigger.
    Suppress { first_open: bool },
    /// Circuit was previously open but traffic has now normalized.
    /// `suppressed` is the number of alerts that were dropped.
    JustRecovered { suppressed: usize },
    /// Normal — go ahead and send.
    Pass,
}

/// Sliding-window circuit breaker shared by all notifier background tasks.
///
/// # How it works
/// A `VecDeque<Instant>` tracks timestamps of recently sent messages. Before each
/// send the front of the deque is evicted if older than `window_duration` (60s).
/// If the deque length reaches `max_per_minute`, the breaker opens and alerts are
/// suppressed until traffic drops below the threshold again.
pub struct CircuitBreaker {
    max_per_minute: usize,
    window_duration: Duration,
    timestamps: VecDeque<Instant>,
    active: bool,
    suppressed: usize,
}

impl CircuitBreaker {
    pub fn new(max_per_minute: usize) -> Self {
        Self {
            max_per_minute,
            window_duration: Duration::from_secs(60),
            timestamps: VecDeque::new(),
            active: false,
            suppressed: 0,
        }
    }

    /// Evaluate the current state. Call once per incoming alert **before** dispatching.
    pub fn check(&mut self) -> BreakerDecision {
        // Evict expired entries
        let now = Instant::now();
        while let Some(&front) = self.timestamps.front() {
            if now.duration_since(front) > self.window_duration {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }

        if self.timestamps.len() >= self.max_per_minute {
            // Over threshold — suppress
            self.suppressed += 1;
            let first_open = !self.active;
            if first_open {
                self.active = true;
            }
            return BreakerDecision::Suppress { first_open };
        }

        if self.active {
            // Traffic normalized — reset
            self.active = false;
            let suppressed = self.suppressed;
            self.suppressed = 0;
            return BreakerDecision::JustRecovered { suppressed };
        }

        BreakerDecision::Pass
    }

    /// Record that one message was successfully dispatched (for window accounting).
    pub fn record_sent(&mut self) {
        self.timestamps.push_back(Instant::now());
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// retry_http_post
// ──────────────────────────────────────────────────────────────────────────────

/// Retry an HTTP POST with JSON body up to `max_attempts` times.
///
/// - On HTTP 429 (rate-limited), waits `backoff_429` before retrying.
/// - On network/connection errors, waits `backoff_err` before retrying.
/// - Any other non-success status breaks the loop immediately.
///
/// Returns `true` if any attempt succeeded.
pub async fn retry_http_post<T: Serialize>(
    client: &Client,
    url: &str,
    payload: &T,
    max_attempts: u32,
    backoff_429: Duration,
    backoff_err: Duration,
    service_name: &str,
) -> bool {
    let mut attempts = 0u32;
    while attempts < max_attempts {
        attempts += 1;
        match client.post(url).json(payload).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return true;
                } else if status.as_u16() == 429 {
                    warn!(
                        "{} rate limit hit (429). Backing off for {:?} (attempt {}/{})",
                        service_name, backoff_429, attempts, max_attempts
                    );
                    tokio::time::sleep(backoff_429).await;
                } else {
                    let body = response.text().await.unwrap_or_default();
                    tracing::error!(
                        "{} API error (status {}): {}",
                        service_name, status, body
                    );
                    break;
                }
            }
            Err(e) => {
                tracing::error!(
                    "{} network error (attempt {}/{}): {}",
                    service_name, attempts, max_attempts, e
                );
                tokio::time::sleep(backoff_err).await;
            }
        }
    }
    false
}
