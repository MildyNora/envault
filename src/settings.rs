//! User-configurable settings, stored at `~/.envault/config.json`.
//! Changing them is gated (see `commands::config`) so an agent can't silently
//! disable the audit log or the Touch ID requirement.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    /// Record every decryption to the audit log.
    pub audit_log: bool,
    /// Require a Touch ID / password prompt before each decryption.
    pub touch_id: bool,
    /// Allow `envault fill` (browser form-fill over CDP). Off by default and
    /// fail-closed because its origin guard cannot be trusted against a
    /// same-user malicious process (it can run its own loopback CDP endpoint).
    pub fill: bool,
}

fn config_file(home: &Path) -> std::path::PathBuf {
    home.join("config.json")
}

/// Secure defaults used when the stored settings are present but corrupt or
/// unreadable — we must not silently downgrade, so fail closed. (H4)
const FAIL_CLOSED: Settings = Settings {
    audit_log: true,
    touch_id: true,
    fill: false,
};

impl Settings {
    /// Load the authoritative settings.
    /// - never configured → default (both off; the user hasn't opted in)
    /// - present but corrupt / a store error → fail closed (both on)
    ///
    /// In release builds the source of truth is the Keychain, so editing the
    /// on-disk `config.json` cannot flip a flag. In debug/test builds the file
    /// is used (the Keychain can't be exercised in tests).
    pub fn load(home: &Path) -> Settings {
        match Self::load_raw(home) {
            Ok(Some(s)) => s,
            Ok(None) => Settings::default(),
            Err(_) => FAIL_CLOSED,
        }
    }

    #[cfg(debug_assertions)]
    fn load_raw(home: &Path) -> Result<Option<Settings>> {
        match std::fs::read_to_string(config_file(home)) {
            Ok(raw) => Ok(Some(
                serde_json::from_str(&raw).context("parsing config.json")?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(not(debug_assertions))]
    fn load_raw(_home: &Path) -> Result<Option<Settings>> {
        let entry = keyring::Entry::new("envault", "settings").context("opening settings entry")?;
        match entry.get_password() {
            Ok(raw) => Ok(Some(
                serde_json::from_str(&raw).context("parsing settings")?,
            )),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        std::fs::create_dir_all(home)?;
        // Always write a readable mirror for transparency / the dashboard.
        let path = config_file(home);
        std::fs::write(&path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))?;
        crate::platform::set_mode(&path, 0o600)?;
        // In release, the Keychain copy is authoritative (agent-tamper-resistant).
        #[cfg(not(debug_assertions))]
        {
            keyring::Entry::new("envault", "settings")
                .context("opening settings entry")?
                .set_password(&serde_json::to_string(self)?)
                .context("storing settings in the Keychain")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn defaults_when_missing() {
        let home = TempDir::new().unwrap();
        let s = Settings::load(home.path());
        assert!(!s.audit_log && !s.touch_id);
    }

    #[test]
    fn save_load_roundtrip() {
        let home = TempDir::new().unwrap();
        let s = Settings {
            audit_log: true,
            touch_id: true,
            fill: true,
        };
        s.save(home.path()).unwrap();
        assert_eq!(Settings::load(home.path()), s);
    }

    #[test]
    fn corrupt_config_fails_closed() {
        let home = TempDir::new().unwrap();
        std::fs::write(home.path().join("config.json"), "{ not valid json").unwrap();
        let s = Settings::load(home.path());
        assert!(s.audit_log && s.touch_id, "corrupt config must fail closed");
        assert!(!s.fill, "fill must fail closed to OFF");
    }
}
