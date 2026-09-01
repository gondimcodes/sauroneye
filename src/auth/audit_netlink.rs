use crate::auth::pam_watcher::AuthEvent;
use std::error::Error;

/// NOT YET IMPLEMENTED — Linux Audit Netlink integration.
///
/// This module is a placeholder for future direct integration with the Linux
/// Audit subsystem via netlink socket. Currently the daemon reads auth events
/// exclusively from `/var/log/auth.log` via `PamWatcher`.
///
/// When implemented, this will provide: syscall-level auditing, more reliable
/// event capture than log polling, and kernel-level timestamps.
#[allow(dead_code)]
pub struct AuditNetlink;

#[allow(dead_code)]
impl AuditNetlink {
    pub fn new() -> Self {
        Self
    }

    /// Returns an empty list. Netlink audit integration is not yet implemented.
    pub fn try_read_audit_events(&self) -> Result<Vec<AuthEvent>, Box<dyn Error + Send + Sync>> {
        // TODO: implement direct netlink socket reading for kernel-level audit events
        Ok(Vec::new())
    }
}
