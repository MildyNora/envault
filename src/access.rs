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
    unlock_authorized(home, action, detail, s.audit_log, || Ok(()))
}

// The hook is an internal deterministic test seam, never a user callback.
fn unlock_authorized(
    home: &Path,
    action: &str,
    detail: &str,
    audit_enabled: bool,
    selected: impl FnOnce() -> Result<()>,
) -> Result<age::x25519::Identity> {
    // Explicit biometric authorization above is outside the generation lock.
    // Native credential revalidation below may still prompt.
    let _generation = crate::store::lock_generation(home)?;
    let identity = crypto::load_identity_locked(home)?;
    selected()?;
    if audit_enabled {
        // Select the stable key under the same generation lock. If recording
        // fails, refuse access while auditing is enabled. (M1)
        let secret = audit::verification_key_locked(home, &identity)?;
        audit::record_locked(home, secret.expose_secret().as_bytes(), action, detail)
            .context("audit logging failed and auditing is enabled — refusing to proceed")?;
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Used only while crypto::test_env_lock() is held, including worker joins.
    struct SyntheticAuditCredentials {
        _directory: tempfile::TempDir,
        prior_directory: Option<std::ffi::OsString>,
        prior_file: Option<std::ffi::OsString>,
    }

    impl SyntheticAuditCredentials {
        fn new() -> Self {
            let directory = tempfile::TempDir::new().unwrap();
            let prior_directory = std::env::var_os("ENVAULT_IDENTITY_DIR");
            let prior_file = std::env::var_os("ENVAULT_IDENTITY_FILE");
            std::env::remove_var("ENVAULT_IDENTITY_FILE");
            std::env::set_var("ENVAULT_IDENTITY_DIR", directory.path());
            Self {
                _directory: directory,
                prior_directory,
                prior_file,
            }
        }
    }

    impl Drop for SyntheticAuditCredentials {
        fn drop(&mut self) {
            for (name, prior) in [
                ("ENVAULT_IDENTITY_DIR", &self.prior_directory),
                ("ENVAULT_IDENTITY_FILE", &self.prior_file),
            ] {
                match prior {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    #[test]
    fn competing_authorized_appends_preserve_all_events_after_rotation() {
        let _env = crypto::test_env_lock();
        let _credentials = SyntheticAuditCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        crypto::store_identity(&crypto::generate_identity(), home.path()).unwrap();
        crate::store::Vault::default().save(home.path()).unwrap();
        std::fs::write(
            home.path().join("config.json"),
            r#"{"audit_log":true,"touch_id":false}"#,
        )
        .unwrap();
        unlock(home.path(), "run", "seed").unwrap();
        crate::commands::rotate::rotate_in_place(home.path()).unwrap();
        let identity = crypto::load_identity(home.path()).unwrap().to_public();
        let before = {
            let _generation = crate::store::lock_generation(home.path()).unwrap();
            audit::read_locked(home.path()).unwrap().len()
        };
        const WRITERS: usize = 8;
        let start = std::sync::Barrier::new(WRITERS);
        let (selected_tx, selected_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let home = home.path();
            // Pause the first writer after identity selection with vault.lock held.
            let first = scope.spawn(move || {
                unlock_authorized(home, "run", "writer-0", true, || {
                    selected_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .unwrap();
                    Ok(())
                })
                .map(|identity| identity.to_public())
            });
            selected_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            let mut workers = Vec::new();
            for index in 1..WRITERS {
                let start = &start;
                workers.push(scope.spawn(move || {
                    // All contenders synchronize outside the generation boundary.
                    start.wait();
                    unlock(home, "run", &format!("writer-{index}"))
                        .map(|identity| identity.to_public())
                }));
            }
            start.wait();
            let probe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(home.join("vault.lock"))
                .unwrap();
            assert!(
                probe.try_lock().is_err(),
                "selected writer must retain the generation lock"
            );
            release_tx.send(()).unwrap();
            assert_eq!(first.join().unwrap().unwrap(), identity);
            for worker in workers {
                assert_eq!(worker.join().unwrap().unwrap(), identity);
            }
        });
        {
            let _generation = crate::store::lock_generation(home.path()).unwrap();
            let identity = crypto::load_identity_locked(home.path()).unwrap();
            let key = audit::verification_key_locked(home.path(), &identity).unwrap();
            let entries = audit::read_locked(home.path()).unwrap();
            assert_eq!(entries.len(), before + WRITERS);
            assert_eq!(entries[before].detail, "writer-0");
            let mut details: Vec<_> = entries[before..].iter().map(|e| e.detail.clone()).collect();
            details.sort();
            assert_eq!(
                details,
                (0..WRITERS)
                    .map(|i| format!("writer-{i}"))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                audit::verify_locked(home.path(), key.expose_secret().as_bytes(), &entries),
                audit::Integrity::Ok
            );
        }
        crate::commands::rotate::rotate_in_place(home.path()).unwrap();
        unlock(home.path(), "run", "after-second-rotation").unwrap();
        let _generation = crate::store::lock_generation(home.path()).unwrap();
        let identity = crypto::load_identity_locked(home.path()).unwrap();
        let key = audit::verification_key_locked(home.path(), &identity).unwrap();
        let entries = audit::read_locked(home.path()).unwrap();
        assert_eq!(entries.len(), before + WRITERS + 2);
        assert_eq!(
            audit::verify_locked(home.path(), key.expose_secret().as_bytes(), &entries),
            audit::Integrity::Ok
        );
    }

    #[test]
    fn audited_access_refuses_damaged_history_without_changing_evidence() {
        let _env = crypto::test_env_lock();
        let _credentials = SyntheticAuditCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        crypto::store_identity(&crypto::generate_identity(), home.path()).unwrap();
        crate::store::Vault::default().save(home.path()).unwrap();
        std::fs::write(
            home.path().join("config.json"),
            r#"{"audit_log":true,"touch_id":false}"#,
        )
        .unwrap();
        unlock(home.path(), "run", "first").unwrap();
        unlock(home.path(), "run", "second").unwrap();
        let log = home.path().join("audit.log");
        let head = home.path().join("audit.head");
        let raw = std::fs::read_to_string(&log).unwrap();
        std::fs::write(&log, format!("{}\n", raw.lines().next().unwrap())).unwrap();
        let damaged = std::fs::read(&log).unwrap();
        let anchor = std::fs::read(&head).unwrap();
        assert!(unlock(home.path(), "run", "refused").is_err());
        assert_eq!(std::fs::read(log).unwrap(), damaged);
        assert_eq!(std::fs::read(head).unwrap(), anchor);
    }

    #[test]
    fn selected_identity_and_audit_append_exclude_rotation() {
        let _env = crypto::test_env_lock();
        let home = tempfile::TempDir::new().unwrap();
        let credentials = tempfile::TempDir::new().unwrap();
        std::env::remove_var("ENVAULT_IDENTITY_FILE");
        std::env::set_var("ENVAULT_IDENTITY_DIR", credentials.path());
        let old = crypto::generate_identity();
        crypto::store_identity(&old, home.path()).unwrap();
        crate::store::Vault::default().save(home.path()).unwrap();
        let (selected_tx, selected_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let home = home.path();
            let reader = scope.spawn(move || {
                unlock_authorized(home, "run", "before-rotation", true, || {
                    selected_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .unwrap();
                    Ok(())
                })
                .unwrap()
                .to_public()
            });
            selected_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            let probe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(home.join("vault.lock"))
                .unwrap();
            assert!(
                probe.try_lock().is_err(),
                "rotation must not enter after key selection"
            );
            release_tx.send(()).unwrap();
            assert_eq!(reader.join().unwrap(), old.to_public());
        });
        // Rotate after the selected-generation append; history must migrate intact.
        crate::commands::rotate::rotate_in_place(home.path()).unwrap();
        let identity =
            unlock_authorized(home.path(), "run", "after-rotation", true, || Ok(())).unwrap();
        let _lock = crate::store::lock_generation(home.path()).unwrap();
        let key = audit::verification_key_locked(home.path(), &identity).unwrap();
        let entries = audit::read_locked(home.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            audit::verify_locked(home.path(), key.expose_secret().as_bytes(), &entries),
            audit::Integrity::Ok
        );
        std::env::remove_var("ENVAULT_IDENTITY_DIR");
    }
}
