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
}

fn config_file(home: &Path) -> std::path::PathBuf {
    home.join("config.json")
}

impl Settings {
    /// Load settings, falling back to defaults if the file is missing or
    /// unreadable (never fails — settings are best-effort).
    pub fn load(home: &Path) -> Settings {
        std::fs::read_to_string(config_file(home))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        std::fs::create_dir_all(home)?;
        let path = config_file(home);
        std::fs::write(&path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))?;
        crate::platform::set_mode(&path, 0o600)?;
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
        };
        s.save(home.path()).unwrap();
        assert_eq!(Settings::load(home.path()), s);
    }
}
