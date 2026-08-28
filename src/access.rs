//! The single choke point for using the private key. Centralizes the Touch ID
//! gate (when enabled) and audit logging, so every decryption path is covered
//! consistently.

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result};
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
        // Key the log with the Keychain-protected identity so it can't be
        // forged, and FAIL CLOSED: if we can't record the access, don't grant
        // it (auditing was explicitly enabled). (M1)
        let secret = identity.to_string();
        audit::record(home, secret.expose_secret().as_bytes(), action, detail)
            .context("audit logging failed and auditing is enabled — refusing to proceed")?;
    }
    Ok(identity)
}
