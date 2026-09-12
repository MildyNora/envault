use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::paths::vault_file;

/// Serialize dashboard snapshots/saves with identity rotation. Keep the lock
/// file in place: removing it would let waiters lock different inodes.
/// Other mutation paths are handled by the separate storage-transaction work.
pub(crate) fn lock_generation(home: &Path) -> Result<fs::File> {
    let path = home.join("vault.lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .context("opening vault generation lock")?;
    crate::platform::set_mode(&path, 0o600)?;
    file.lock().context("locking vault generation")?;
    Ok(file)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretEntry {
    pub alias: String,
    pub label: String,
    pub cipher: String, // base64 of binary age ciphertext
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
    pub created_at: String, // RFC3339
    pub updated_at: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Vault {
    pub secrets: Vec<SecretEntry>,
}

impl Vault {
    pub fn load(home: &Path) -> Result<Vault> {
        let path = vault_file(home);
        if !path.exists() {
            bail!(
                "no vault found at {} — run `envault init` first",
                path.display()
            );
        }
        let raw =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        fs::create_dir_all(home)?;
        let path = vault_file(home);
        fs::write(&path, serde_json::to_string_pretty(self)?)?;
        crate::platform::set_mode(&path, 0o600)?;
        Ok(())
    }

    pub fn get(&self, alias: &str) -> Option<&SecretEntry> {
        self.secrets.iter().find(|s| s.alias == alias)
    }

    pub fn insert(&mut self, e: SecretEntry) -> Result<()> {
        if self.get(&e.alias).is_some() {
            bail!("alias '{}' already exists", e.alias);
        }
        self.secrets.push(e);
        self.secrets.sort_by_key(|s| s.alias.clone());
        Ok(())
    }
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn is_valid_alias(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn entry(alias: &str) -> SecretEntry {
        SecretEntry {
            alias: alias.into(),
            label: format!("{alias} label"),
            cipher: "Y2lwaGVy".into(),
            url: None,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            notes: String::new(),
        }
    }

    #[test]
    fn save_load_roundtrip() {
        let home = TempDir::new().unwrap();
        let mut v = Vault::default();
        v.insert(entry("openrouter")).unwrap();
        v.save(home.path()).unwrap();
        let loaded = Vault::load(home.path()).unwrap();
        assert_eq!(loaded.secrets.len(), 1);
        assert_eq!(loaded.get("openrouter").unwrap().label, "openrouter label");
    }

    #[test]
    fn generation_lock_excludes_other_handles_and_releases_on_drop() {
        let home = TempDir::new().unwrap();
        let guard = lock_generation(home.path()).unwrap();
        let second = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(home.path().join("vault.lock"))
            .unwrap();
        assert!(matches!(
            second.try_lock(),
            Err(fs::TryLockError::WouldBlock)
        ));
        drop(guard);
        second.try_lock().unwrap();
    }

    #[test]
    fn load_without_vault_mentions_init() {
        let home = TempDir::new().unwrap();
        let err = Vault::load(home.path()).unwrap_err().to_string();
        assert!(err.contains("envault init"), "got: {err}");
    }

    #[test]
    fn duplicate_alias_rejected() {
        let mut v = Vault::default();
        v.insert(entry("a-key")).unwrap();
        let err = v.insert(entry("a-key")).unwrap_err().to_string();
        assert!(err.contains("already exists"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn vault_json_is_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().unwrap();
        Vault::default().save(home.path()).unwrap();
        let mode = std::fs::metadata(crate::paths::vault_file(home.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn alias_validation() {
        assert!(is_valid_alias("openrouter"));
        assert!(is_valid_alias("my-key-2"));
        assert!(!is_valid_alias("My-Key"));
        assert!(!is_valid_alias("-lead"));
        assert!(!is_valid_alias(""));
        assert!(!is_valid_alias("has_underscore"));
    }
}
