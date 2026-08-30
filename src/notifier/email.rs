use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::error::Error;
use std::path::Path;
use tracing::{error, info};

use crate::config::SmtpConfig;
use crate::notifier::{AlertMessage, Notifier};

pub struct SmtpNotifier {
    config: SmtpConfig,
}

impl SmtpNotifier {
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }

    fn build_transport(
        &self,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, Box<dyn Error + Send + Sync>> {
        let creds = Credentials::new(self.config.username.clone(), self.config.password.clone());

        let transport = if self.config.use_tls {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.host)?
                .port(self.config.port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.host)
                .port(self.config.port)
                .credentials(creds)
                .build()
        };

        Ok(transport)
    }

    /// Sends a generated PDF report attached to an email
    pub async fn send_pdf_report(
        &self,
        to_email: &str,
        subject: &str,
        body_text: &str,
        pdf_path: &Path,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let pdf_data = std::fs::read(pdf_path)?;
        let file_name = pdf_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let content_type = ContentType::parse("application/pdf")
            .unwrap_or_else(|_| ContentType::parse("application/octet-stream").unwrap());
        let attachment = Attachment::new(file_name).body(pdf_data, content_type);

        let email = Message::builder()
            .from(self.config.from_address.parse()?)
            .to(to_email.parse()?)
            .subject(subject)
            .multipart(
                MultiPart::mixed()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(body_text.to_string()),
                    )
                    .singlepart(attachment),
            )?;

        let transport = self.build_transport()?;
        transport.send(email).await?;
        info!("PDF Report sent via SMTP successfully to {}", to_email);
        Ok(())
    }
}

#[async_trait]
impl Notifier for SmtpNotifier {
    async fn send_alert(&self, alert: &AlertMessage) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.enabled {
            return Ok(());
        }

        let to_addr = match &self.config.to_default {
            Some(addr) if !addr.trim().is_empty() => addr.trim(),
            _ => return Ok(()),
        };

        let email = Message::builder()
            .from(self.config.from_address.parse()?)
            .to(to_addr.parse()?)
            .subject(format!(
                "[SAURONEYE - {}] {}",
                alert.severity.as_str(),
                alert.title
            ))
            .singlepart(SinglePart::plain(alert.format_text()))?;

        let transport = self.build_transport()?;
        match transport.send(email).await {
            Ok(_) => {
                info!("Email alert dispatched successfully to {}", to_addr);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send SMTP email: {}", e);
                Err(Box::new(e))
            }
        }
    }
}
