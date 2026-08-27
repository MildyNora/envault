//! The single choke point for using the private key. Centralizes the Touch ID
//! gate (when enabled) and audit logging, so every decryption path is covered
//! consistently.

use anyhow::Result;
use std::path::Path;

use crate::{audit, biometric, crypto, settings::Settings};

/// Load the private key for a decryption, applying the configured gate and
/// recording the access. `action` is a short verb (run/reveal/copy/fill/rotate)
/// and `detail` is the command or alias involved.
pub fn unlock(home: &Path, action: &str, detail: &str) -> Result<age::x25519::Identity> {
    let s = Settings::load(home);
    if s.touch_id {
        biometric::require(&format!("Approve envault {action}: {detail}"))?;
    }
    let identity = crypto::load_identity()?;
    if s.audit_log {
        // Best-effort: a logging hiccup must not block the actual operation.
        let _ = audit::record(home, action, detail);
    }
    Ok(identity)
}
