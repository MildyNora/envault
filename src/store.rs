use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::paths::vault_file;

/// One permanent inode serializes storage transactions and identity generation.
pub(crate) fn lock_generation(home: &Path) -> Result<File> {
    let lock = open_lock(home)?;
    lock.lock().context("locking vault generation")?;
    Ok(lock)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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
        if !home.exists() {
            bail!(
                "no vault found at {} — run `envault init` first",
                vault_file(home).display()
            );
        }
        let _generation = lock_generation(home)?;
        crate::crypto::recover_rotation_locked(home)?;
        Self::load_locked(home)
    }

    /// Caller holds vault.lock and has completed any pending recovery. This
    /// primitive also supports legacy identity validation without reacquiring.
    pub(crate) fn load_locked(home: &Path) -> Result<Vault> {
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
        let _generation = lock_generation(home)?;
        crate::crypto::recover_rotation_locked(home)?;
        self.save_locked(home)
    }

    #[cfg(test)]
    pub fn transaction<T>(
        home: &Path,
        mutate: impl FnOnce(&mut Vault) -> Result<T>,
    ) -> Result<(T, Vault)> {
        let _generation = lock_generation(home)?;
        crate::crypto::recover_rotation_locked(home)?;
        let mut vault = Self::load_locked(home)?;
        let result = mutate(&mut vault)?;
        vault.save_locked(home)?;
        Ok((result, vault))
    }

    /// Explicit authorization and user input precede this transaction. Native
    /// credential revalidation may itself prompt; do not promise otherwise.
    pub fn transaction_for_recipient<T>(
        home: &Path,
        expected_recipient: &age::x25519::Recipient,
        mutate: impl FnOnce(&mut Vault, &age::x25519::Recipient) -> Result<T>,
    ) -> Result<(T, Vault)> {
        wait_at_test_transaction_barrier()?;
        let _generation = lock_generation(home)?;
        // Recovery can replace the active identity. Finish it BEFORE loading
        // persisted bytes or performing even a metadata-only edit/deletion.
        let current_recipient = crate::crypto::load_identity_locked(home)?.to_public();
        anyhow::ensure!(
            current_recipient == *expected_recipient,
            "vault identity changed while waiting for the storage lock — retry"
        );
        let mut vault = Self::load_locked(home)?;
        let result = mutate(&mut vault, &current_recipient)?;
        vault.save_locked(home)?;
        Ok((result, vault))
    }

    pub(crate) fn save_locked(&self, home: &Path) -> Result<()> {
        let path = vault_file(home);
        let staged = home.join("vault.json.tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&staged)
            .with_context(|| format!("opening {}", staged.display()))?;
        file.write_all(serde_json::to_string_pretty(self)?.as_bytes())
            .with_context(|| format!("writing {}", staged.display()))?;
        crate::platform::set_mode(&staged, 0o600)?;
        file.sync_all()
            .with_context(|| format!("syncing {}", staged.display()))?;
        fs::rename(&staged, &path).with_context(|| format!("replacing {}", path.display()))?;
        sync_parent(home)?;
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

#[cfg(debug_assertions)]
fn wait_at_test_transaction_barrier() -> Result<()> {
    let (Ok(ready), Ok(release)) = (
        std::env::var("ENVAULT_TEST_TRANSACTION_READY"),
        std::env::var("ENVAULT_TEST_TRANSACTION_RELEASE"),
    ) else {
        return Ok(());
    };
    fs::write(&ready, b"ready").context("signaling test transaction readiness")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !Path::new(&release).exists() {
        if std::time::Instant::now() >= deadline {
            bail!("timed out waiting for test transaction release");
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn wait_at_test_transaction_barrier() -> Result<()> {
    Ok(())
}

fn open_lock(home: &Path) -> Result<File> {
    let path = home.join("vault.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    crate::platform::set_mode(&path, 0o600)?;
    Ok(file)
}

#[cfg(unix)]
fn sync_parent(home: &Path) -> Result<()> {
    File::open(home)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_home: &Path) -> Result<()> {
    Ok(())
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
    fn transaction_commits_the_latest_vault_atomically() {
        let home = TempDir::new().unwrap();
        Vault::default().save(home.path()).unwrap();

        let (alias, committed) = Vault::transaction(home.path(), |vault| {
            vault.insert(entry("new-key"))?;
            Ok("new-key")
        })
        .unwrap();

        assert_eq!(alias, "new-key");
        assert!(committed.get("new-key").is_some());
        assert!(Vault::load(home.path()).unwrap().get("new-key").is_some());
        assert!(!home.path().join("vault.json.tmp").exists());
    }

    #[test]
    fn failed_transaction_does_not_write_partial_mutation() {
        let home = TempDir::new().unwrap();
        Vault::default().save(home.path()).unwrap();

        let result: Result<((), Vault)> = Vault::transaction(home.path(), |vault| {
            vault.insert(entry("not-committed"))?;
            bail!("synthetic failure")
        });

        assert!(result.is_err());
        assert!(Vault::load(home.path())
            .unwrap()
            .get("not-committed")
            .is_none());
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
