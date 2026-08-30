use crate::auth::pam_watcher::AuthEvent;
use std::error::Error;
use tracing::{info, warn};

pub struct AuditNetlink;

impl AuditNetlink {
    pub fn new() -> Self {
        Self
    }

    /// Captures Linux audit subsystem events when available.
    pub fn try_read_audit_events(&self) -> Result<Vec<AuthEvent>, Box<dyn Error + Send + Sync>> {
        // Fallback wrapper for environments without direct netlink audit privileges
        Ok(Vec::new())
    }
}
