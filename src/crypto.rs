use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

pub fn generate_identity() -> age::x25519::Identity {
    age::x25519::Identity::generate()
}

pub fn encrypt_value(recipient: &age::x25519::Recipient, plaintext: &str) -> Result<String> {
    let bytes = age::encrypt(recipient, plaintext.as_bytes()).context("age encryption failed")?;
    Ok(B64.encode(bytes))
}

pub fn decrypt_value(identity: &age::x25519::Identity, cipher_b64: &str) -> Result<String> {
    let bytes = B64
        .decode(cipher_b64.trim())
        .context("cipher is not valid base64")?;
    let plain = age::decrypt(identity, &bytes)
        .context("decryption failed (wrong key or corrupt cipher)")?;
    String::from_utf8(plain).context("decrypted value is not UTF-8")
}

use age::secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::str::FromStr;

const KEYCHAIN_SERVICE: &str = "envault";
const LEGACY_KEYCHAIN_ACCOUNT: &str = "age-identity";
const STABLE_KEYCHAIN_PREFIX: &str = "age-identity-v2-";

fn path_identity_account(home: &Path) -> Result<String> {
    let home = fs::canonicalize(home)
        .with_context(|| format!("resolving envault home {}", home.display()))?;
    let digest = Sha256::digest(home.as_os_str().as_encoded_bytes());
    Ok(format!("age-identity-{digest:x}"))
}

fn fixed_identity_file() -> Option<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    {
        if std::env::var_os("ENVAULT_IDENTITY_DIR").is_none() {
            return std::env::var("ENVAULT_IDENTITY_FILE").ok().map(Into::into);
        }
        None
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// Test-only escape hatches use either one fixed file or a directory whose
/// filenames model distinct Keychain accounts. Release builds ignore both.
fn credential_file(account: &str) -> Option<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    {
        if let Some(path) = fixed_identity_file() {
            if account.starts_with("rotation-recovery-") {
                return Some(path.with_extension("rotation-recovery"));
            }
            return Some(path);
        }
        std::env::var("ENVAULT_IDENTITY_DIR")
            .ok()
            .map(|dir| std::path::PathBuf::from(dir).join(account))
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = account;
        None
    }
}

fn get_credential(account: &str) -> Result<Option<String>> {
    #[cfg(test)]
    assert!(
        credential_file(account).is_some(),
        "unit tests require an isolated credential backend"
    );
    if let Some(path) = credential_file(account) {
        return match fs::read_to_string(&path) {
            Ok(raw) => Ok(Some(raw)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading identity file {}", path.display())),
        };
    }
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).context("opening Keychain entry")?;
    match entry.get_password() {
        Ok(raw) => Ok(Some(raw)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("reading identity from the Keychain"),
    }
}

fn set_credential(account: &str, raw: &str) -> Result<()> {
    #[cfg(test)]
    assert!(
        credential_file(account).is_some(),
        "unit tests require an isolated credential backend"
    );
    if let Some(path) = credential_file(account) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, format!("{raw}\n"))?;
        crate::platform::set_mode(&path, 0o600)?;
        return Ok(());
    }
    keyring::Entry::new(KEYCHAIN_SERVICE, account)
        .context("opening Keychain entry")?
        .set_password(raw)
        .context("storing identity in the OS credential store")
}

fn remove_credential(account: &str) -> Result<()> {
    #[cfg(test)]
    assert!(
        credential_file(account).is_some(),
        "unit tests require an isolated credential backend"
    );
    if let Some(path) = credential_file(account) {
        return match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing identity file {}", path.display())),
        };
    }
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).context("opening Keychain entry")?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("deleting identity from the OS credential store"),
    }
}

fn parse_identity(raw: &str) -> Result<age::x25519::Identity> {
    age::x25519::Identity::from_str(raw.trim())
        .map_err(|e| anyhow::anyhow!("invalid age identity: {e}"))
}

fn parse_matching_identity(raw: &str, home: &Path) -> Result<age::x25519::Identity> {
    let identity = parse_identity(raw)?;
    let vault = crate::store::Vault::load_locked(home)?;
    anyhow::ensure!(
        !vault.secrets.is_empty(),
        "empty legacy vault: run `envault init --empty-legacy` to create a fresh identity; legacy credentials will be preserved"
    );
    for entry in &vault.secrets {
        decrypt_value(&identity, &entry.cipher)
            .context("no matching envault identity for legacy migration")?;
    }
    Ok(identity)
}

fn read_vault_id(home: &Path) -> Result<Option<String>> {
    let path = crate::paths::identity_id_file(home);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let id = raw.trim();
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        anyhow::bail!("invalid vault identity identifier at {}", path.display());
    }
    Ok(Some(id.to_owned()))
}

fn new_vault_id() -> String {
    // age already supplies the OS-backed CSPRNG we use for vault identities.
    // Hashing a throwaway public key yields an opaque, non-secret identifier
    // without coupling two vaults that happen to share a legacy identity.
    let nonce = age::x25519::Identity::generate().to_public().to_string();
    let digest = Sha256::digest(nonce.as_bytes());
    format!("{digest:x}")
}

fn ensure_vault_id(home: &Path) -> Result<String> {
    if let Some(id) = read_vault_id(home)? {
        return Ok(id);
    }

    let id = new_vault_id();
    let path = crate::paths::identity_id_file(home);
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            return read_vault_id(home)?.context("vault identity identifier disappeared")
        }
        Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
    };
    writeln!(file, "{id}")?;
    file.sync_all()?;
    crate::platform::set_mode(&path, 0o600)?;
    Ok(id)
}

fn stable_identity_account(id: &str) -> String {
    format!("{STABLE_KEYCHAIN_PREFIX}{id}")
}

fn migrate_identity(
    home: &Path,
    raw: &str,
    remove_source: Option<&str>,
) -> Result<age::x25519::Identity> {
    let identity = parse_matching_identity(raw, home)?;
    let id = ensure_vault_id(home)?;
    let account = stable_identity_account(&id);
    set_credential(&account, raw.trim())?;
    let saved = get_credential(&account)?.context("migrated identity was not persisted")?;
    parse_matching_identity(&saved, home)?;
    if let Some(source) = remove_source {
        if source != account {
            remove_credential(source)?;
        }
    }
    Ok(identity)
}

/// Explicit opt-in for a vault with no ciphertext from which to prove ownership.
/// Never adopt or remove a legacy key; it may belong to another vault or backup.
pub fn initialize_empty_legacy(home: &Path) -> Result<()> {
    initialize_empty_legacy_using(home, set_credential)
}

fn initialize_empty_legacy_using(
    home: &Path,
    write: impl FnOnce(&str, &str) -> Result<()>,
) -> Result<()> {
    let _generation = crate::store::lock_generation(home)?;
    anyhow::ensure!(
        crate::store::Vault::load_locked(home)?.secrets.is_empty(),
        "refusing empty-legacy initialization: vault contains secrets"
    );
    // Any identity metadata, including an unreadable/broken link, could name an
    // active identity or pending rotation recovery. Do not enter recovery here.
    match fs::symlink_metadata(crate::paths::identity_id_file(home)) {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("checking existing identity metadata"),
        Ok(_) => anyhow::bail!(
            "identity metadata already exists; preserve it and use normal access or recovery"
        ),
    }
    let identity = generate_identity();
    let id = new_vault_id();
    let account = stable_identity_account(&id);
    anyhow::ensure!(
        get_credential(&account)?.is_none()
            && get_credential(&format!("rotation-recovery-{id}"))?.is_none(),
        "identity or recovery credential already exists; refusing to replace it"
    );
    // Backend failures leave no identity-id, so the explicit operation is retryable.
    write(&account, identity.to_string().expose_secret())?;
    let saved = get_credential(&account)?.context("fresh identity was not persisted")?;
    anyhow::ensure!(
        parse_identity(&saved)?.to_public() == identity.to_public(),
        "fresh identity verification failed"
    );
    // Publish complete metadata atomically without replacing an existing path.
    // Interrupted attempts may leave an unreferenced fresh credential; old keys
    // and the empty vault remain untouched and the operation can be retried.
    let temporary = home.join(format!(".identity-id-{id}.new"));
    let publish = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        writeln!(file, "{id}")?;
        file.sync_all()?;
        crate::platform::set_mode(&temporary, 0o600)?;
        fs::hard_link(&temporary, crate::paths::identity_id_file(home))
            .context("publishing fresh identity metadata; preserve credentials and retry")?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    publish
}

pub fn store_identity(identity: &age::x25519::Identity, home: &Path) -> Result<()> {
    let _generation = crate::store::lock_generation(home)?;
    store_identity_locked(identity, home)
}

pub(crate) fn store_identity_locked(identity: &age::x25519::Identity, home: &Path) -> Result<()> {
    let key = identity.to_string(); // SecretString
    let id = ensure_vault_id(home)?;
    set_credential(&stable_identity_account(&id), key.expose_secret())
}

pub fn load_identity(home: &Path) -> Result<age::x25519::Identity> {
    let _generation = crate::store::lock_generation(home)?;
    load_identity_locked(home)
}

/// Caller holds vault.lock. Read migration sources only after acquiring it;
/// a waiter must observe a completed rotation instead of replaying an old key.
pub(crate) fn load_identity_locked(home: &Path) -> Result<age::x25519::Identity> {
    recover_rotation_locked(home)?;
    if let Some(id) = read_vault_id(home)? {
        let account = stable_identity_account(&id);
        if let Some(raw) = get_credential(&account)? {
            return parse_identity(&raw);
        }
    }

    // The first scoped implementation used a canonical-path hash. Migrate it
    // once while the vault is still at that path, then remove the obsolete
    // account so future directory moves use only the stable identifier.
    let path_account = path_identity_account(home)?;
    if let Some(raw) = get_credential(&path_account)? {
        return migrate_identity(home, &raw, Some(&path_account));
    }

    // Pre-scoping releases used one shared account. Copy a matching legacy key
    // to this vault's stable account, but retain the shared slot because another
    // unmigrated vault may still need it. Rotation retires only this vault's
    // account and its known path/shared aliases, never another vault's account.
    if let Some(raw) = get_credential(LEGACY_KEYCHAIN_ACCOUNT)? {
        return migrate_identity(home, &raw, None);
    }

    anyhow::bail!(
        "no matching envault identity for {} — restore its original identity or backup",
        home.display()
    )
}

fn remove_if_matching(account: &str, expected: &age::x25519::Identity) -> Result<()> {
    if let Some(raw) = get_credential(account)? {
        let Ok(parsed) = parse_identity(&raw) else {
            return Ok(());
        };
        if parsed.to_string().expose_secret() == expected.to_string().expose_secret() {
            remove_credential(account)?;
        }
    }
    Ok(())
}

pub fn delete_identity(home: &Path, expected: &age::x25519::Identity) -> Result<()> {
    let id = read_vault_id(home)?.context("vault identity identifier is missing")?;
    let stable = stable_identity_account(&id);
    let raw = get_credential(&stable)?.context("vault identity credential is missing")?;
    let stored = parse_identity(&raw)?;
    if stored.to_string().expose_secret() != expected.to_string().expose_secret() {
        anyhow::bail!("refusing to delete an unexpected vault identity");
    }
    let path_account = path_identity_account(home)?;
    if fixed_identity_file().is_none() {
        remove_if_matching(&path_account, expected)?;
        remove_if_matching(LEGACY_KEYCHAIN_ACCOUNT, expected)?;
    }
    remove_credential(&stable)
}

pub fn identity_recovery_present(home: &Path) -> Result<bool> {
    if crate::paths::recipient_file(home).exists()
        || crate::paths::identity_id_file(home).exists()
        || fixed_identity_file().is_some_and(|path| path.exists())
    {
        return Ok(true);
    }
    Ok(get_credential(&path_identity_account(home)?)?.is_some())
}

// Stored only in the protected credential backend (or isolated debug backend).
// The hashes bind both recoverable keys to the exact staged/current vaults.
#[derive(serde::Serialize, serde::Deserialize)]
struct RotationRecovery {
    before: String,
    after: String,
    old_key: String,
    new_key: String,
    #[serde(default)]
    audit_snapshot: Option<String>,
}

fn recovery_account(home: &Path) -> Result<Option<String>> {
    Ok(read_vault_id(home)?.map(|id| format!("rotation-recovery-{id}")))
}

fn vault_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn prepare_rotation_locked(
    home: &Path,
    old: &age::x25519::Identity,
    new: &age::x25519::Identity,
    before: &[u8],
    after: &[u8],
) -> Result<()> {
    let account = recovery_account(home)?.context("missing vault identity identifier")?;
    anyhow::ensure!(
        get_credential(&account)?.is_none(),
        "pending identity recovery"
    );
    let record = RotationRecovery {
        before: vault_digest(before),
        after: vault_digest(after),
        old_key: old.to_string().expose_secret().to_owned(),
        new_key: new.to_string().expose_secret().to_owned(),
        audit_snapshot: Some(crate::audit::prepare_snapshot_locked(home, old, new)?),
    };
    let raw = serde_json::to_string(&record)?;
    set_credential(&account, &raw)?;
    anyhow::ensure!(
        get_credential(&account)?.is_some_and(|saved| saved.trim() == raw),
        "rotation recovery record was not persisted"
    );
    Ok(())
}

/// Caller holds vault.lock. Interrupted rotation selects the credential for the
/// vault actually on disk. Unknown bytes fail closed and retain both keys.
pub(crate) fn recover_rotation_locked(home: &Path) -> Result<()> {
    let Some(account) = recovery_account(home)? else {
        return Ok(());
    };
    let Some(raw) = get_credential(&account)? else {
        return Ok(());
    };
    let record: RotationRecovery = serde_json::from_str(&raw)
        .map_err(|_| anyhow::anyhow!("invalid protected rotation recovery record"))?;
    let current = vault_digest(&fs::read(crate::paths::vault_file(home))?);
    let stable = stable_identity_account(&read_vault_id(home)?.context("missing vault id")?);
    // An empty vault can have identical before/after bytes. Its active slot
    // distinguishes completed replacement from interruption before replacement.
    let activated_empty = record.before == record.after
        && get_credential(&stable)?.is_some_and(|raw| raw.trim() == record.new_key);
    let key = if current == record.after && activated_empty {
        &record.new_key
    } else if current == record.before {
        &record.old_key
    } else if current == record.after {
        &record.new_key
    } else {
        anyhow::bail!("vault differs from rotation recovery record; preserve files for recovery");
    };
    let identity = parse_identity(key)?;
    if let Some(digest) = &record.audit_snapshot {
        crate::audit::recover_snapshot_locked(
            home, digest, key == &record.new_key, &identity,
        )?;
    }
    store_identity_locked(&identity, home)?;
    let saved = get_credential(&stable)?.context("recovered credential missing")?;
    anyhow::ensure!(
        parse_identity(&saved)?.to_public() == identity.to_public(),
        "credential recovery failed"
    );
    // Retry directory synchronization even when recovered bytes already match.
    // A previous rename/deletion may have succeeded before its sync failed.
    crate::audit::sync_rotation_directory(home)?;
    // Audit restoration and verification must finish before retiring either key.
    remove_credential(&account)?;
    // Snapshot bytes contain no private identities. Cleanup is best effort only
    // after the protected record has been removed; a later prepare replaces it.
    if record.audit_snapshot.is_some() {
        let _ = fs::remove_file(home.join("audit.rotation.json"));
    }
    Ok(())
}

pub fn store_recipient(identity: &age::x25519::Identity, home: &Path) -> Result<()> {
    fs::create_dir_all(home)?;
    fs::write(
        crate::paths::recipient_file(home),
        format!("{}\n", identity.to_public()),
    )?;
    Ok(())
}

// Production encryption must never trust this unauthenticated public mirror.
#[cfg(test)]
pub fn load_recipient(home: &Path) -> Result<age::x25519::Recipient> {
    let path = crate::paths::recipient_file(home);
    if !path.exists() {
        anyhow::bail!(
            "no recipient at {} — run `envault init` first",
            path.display()
        );
    }
    let raw = fs::read_to_string(&path)?;
    age::x25519::Recipient::from_str(raw.trim())
        .map_err(|e| anyhow::anyhow!("invalid recipient: {e}"))
}

/// The recipient to encrypt to, derived from the authoritative Keychain
/// identity rather than the on-disk `recipient.txt`. Use this on every encrypt
/// path so a tampered `recipient.txt` or an agent-chosen `ENVAULT_HOME` cannot
/// reseal secrets to an attacker's key. (H2, H3)
pub fn recipient_from_identity(home: &Path) -> Result<age::x25519::Recipient> {
    Ok(load_identity(home)?.to_public())
}

/// Serializes the handful of unit tests that mutate the process-wide
/// `ENVAULT_IDENTITY_FILE` env var, so they don't race under parallel `cargo test`.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let id = generate_identity();
        let cipher = encrypt_value(&id.to_public(), "sk-or-v1-secret").unwrap();
        assert_ne!(cipher, "sk-or-v1-secret");
        assert!(!cipher.contains("secret"));
        let plain = decrypt_value(&id, &cipher).unwrap();
        assert_eq!(plain, "sk-or-v1-secret");
    }

    #[test]
    fn wrong_identity_fails() {
        let id = generate_identity();
        let other = generate_identity();
        let cipher = encrypt_value(&id.to_public(), "value-123").unwrap();
        assert!(decrypt_value(&other, &cipher).is_err());
    }

    #[test]
    fn garbage_cipher_fails() {
        let id = generate_identity();
        assert!(decrypt_value(&id, "not base64 !!!").is_err());
        assert!(decrypt_value(&id, "aGVsbG8=").is_err()); // valid b64, not age data
    }

    fn seed_vault(home: &Path, identity: &age::x25519::Identity) -> String {
        let cipher = encrypt_value(&identity.to_public(), "synthetic-value").unwrap();
        let vault = crate::store::Vault {
            secrets: vec![crate::store::SecretEntry {
                alias: "test".into(),
                label: "Test".into(),
                cipher: cipher.clone(),
                url: None,
                created_at: "test".into(),
                updated_at: "test".into(),
                notes: String::new(),
            }],
        };
        vault.save(home).unwrap();
        cipher
    }

    #[test]
    fn identity_file_roundtrip() {
        let _guard = test_env_lock();
        let dir = tempfile::TempDir::new().unwrap();
        let id_path = dir.path().join("identity.txt");
        std::env::set_var("ENVAULT_IDENTITY_FILE", &id_path);
        let id = generate_identity();
        store_identity(&id, dir.path()).unwrap();
        store_recipient(&id, dir.path()).unwrap();
        let loaded = load_identity(dir.path()).unwrap();
        std::env::remove_var("ENVAULT_IDENTITY_FILE");

        let cipher = encrypt_value(&load_recipient(dir.path()).unwrap(), "roundtrip").unwrap();
        assert_eq!(decrypt_value(&loaded, &cipher).unwrap(), "roundtrip");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&id_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn migration_must_decrypt_the_vault_not_trust_the_mirror() {
        let home = tempfile::TempDir::new().unwrap();
        let identity = generate_identity();
        let other = generate_identity();
        seed_vault(home.path(), &identity);
        store_recipient(&generate_identity(), home.path()).unwrap();

        let raw = identity.to_string();
        assert!(parse_matching_identity(raw.expose_secret(), home.path()).is_ok());

        let raw = other.to_string();
        let err = match parse_matching_identity(raw.expose_secret(), home.path()) {
            Ok(_) => panic!("unrelated legacy identity was accepted"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("no matching envault identity"));
    }

    #[test]
    fn path_scoped_identity_migrates_to_stable_account() {
        let _guard = test_env_lock();
        let home = tempfile::TempDir::new().unwrap();
        let credentials = tempfile::TempDir::new().unwrap();
        std::env::remove_var("ENVAULT_IDENTITY_FILE");
        std::env::set_var("ENVAULT_IDENTITY_DIR", credentials.path());

        let identity = generate_identity();
        seed_vault(home.path(), &identity);
        store_recipient(&generate_identity(), home.path()).unwrap();
        let old_account = path_identity_account(home.path()).unwrap();
        let raw = identity.to_string();
        set_credential(&old_account, raw.expose_secret()).unwrap();

        let loaded = load_identity(home.path()).unwrap();
        let id = read_vault_id(home.path()).unwrap().unwrap();
        let stable_account = stable_identity_account(&id);
        assert_eq!(loaded.to_public(), identity.to_public());
        assert!(get_credential(&stable_account).unwrap().is_some());
        assert!(get_credential(&old_account).unwrap().is_none());

        std::env::remove_var("ENVAULT_IDENTITY_DIR");
    }

    #[test]
    fn legacy_identity_is_retained_on_migration_and_revoked_on_rotation() {
        let _guard = test_env_lock();
        let home = tempfile::TempDir::new().unwrap();
        let credentials = tempfile::TempDir::new().unwrap();
        std::env::remove_var("ENVAULT_IDENTITY_FILE");
        std::env::set_var("ENVAULT_IDENTITY_DIR", credentials.path());

        let identity = generate_identity();
        seed_vault(home.path(), &identity);
        store_recipient(&generate_identity(), home.path()).unwrap();
        let raw = identity.to_string();
        set_credential(LEGACY_KEYCHAIN_ACCOUNT, raw.expose_secret()).unwrap();

        load_identity(home.path()).unwrap();
        let id = read_vault_id(home.path()).unwrap().unwrap();
        let stable_account = stable_identity_account(&id);
        assert!(get_credential(&stable_account).unwrap().is_some());
        assert!(get_credential(LEGACY_KEYCHAIN_ACCOUNT).unwrap().is_some());

        delete_identity(home.path(), &identity).unwrap();
        assert!(get_credential(&stable_account).unwrap().is_none());
        assert!(get_credential(LEGACY_KEYCHAIN_ACCOUNT).unwrap().is_none());

        std::env::remove_var("ENVAULT_IDENTITY_DIR");
    }

    #[test]
    fn missing_recipient_mentions_init() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = load_recipient(dir.path()).unwrap_err().to_string();
        assert!(err.contains("envault init"), "got: {err}");
    }
    // All credential operations in these tests use a synthetic directory.
    struct SyntheticCredentials(tempfile::TempDir);
    impl SyntheticCredentials {
        fn new() -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            std::env::remove_var("ENVAULT_IDENTITY_FILE");
            std::env::set_var("ENVAULT_IDENTITY_DIR", dir.path());
            Self(dir)
        }
    }
    impl Drop for SyntheticCredentials {
        fn drop(&mut self) {
            std::env::remove_var("ENVAULT_IDENTITY_DIR");
        }
    }

    #[test]
    fn malformed_obsolete_credential_does_not_destroy_rotation() {
        let _env = test_env_lock();
        let creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        store_identity(&old, home.path()).unwrap();
        seed_vault(home.path(), &old);
        fs::write(
            creds.0.path().join(LEGACY_KEYCHAIN_ACCOUNT),
            "unrelated malformed value",
        )
        .unwrap();
        let outcome = crate::commands::rotate::rotate_in_place(home.path()).unwrap();
        assert_ne!(outcome.recipient, old.to_public());
        let active = load_identity(home.path()).unwrap();
        let vault = crate::store::Vault::load(home.path()).unwrap();
        assert_eq!(
            decrypt_value(&active, &vault.secrets[0].cipher).unwrap(),
            "synthetic-value"
        );
        assert_eq!(
            fs::read_to_string(creds.0.path().join(LEGACY_KEYCHAIN_ACCOUNT)).unwrap(),
            "unrelated malformed value"
        );
    }

    #[test]
    fn obsolete_cleanup_io_error_preserves_active_key_and_vault() {
        let _env = test_env_lock();
        let creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        store_identity(&old, home.path()).unwrap();
        seed_vault(home.path(), &old);
        let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
        fs::create_dir(creds.0.path().join(LEGACY_KEYCHAIN_ACCOUNT)).unwrap();
        assert!(crate::commands::rotate::rotate_in_place(home.path()).is_err());
        assert_eq!(
            load_identity(home.path()).unwrap().to_public(),
            old.to_public()
        );
        assert_eq!(
            fs::read(crate::paths::vault_file(home.path())).unwrap(),
            before
        );
    }

    #[test]
    fn vault_activation_sync_failure_retries_with_no_audit_writes() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        for empty in [false, true] {
            let home = tempfile::TempDir::new().unwrap();
            let old = generate_identity();
            store_identity(&old, home.path()).unwrap();
            if empty {
                crate::store::Vault::default().save(home.path()).unwrap();
            } else {
                seed_vault(home.path(), &old);
            }
            let _lock = crate::store::lock_generation(home.path()).unwrap();
            // Stage and snapshot sync succeed; the sync after vault rename fails.
            let fault = crate::audit::DirectorySyncFailure::after(2);
            let error = match crate::commands::rotate::rotate_authorized_locked(home.path(), &old) {
                Err(error) => error,
                Ok(_) => panic!("activation must report the directory sync failure"),
            };
            assert!(error.downcast_ref::<std::io::Error>().is_some());
            assert_eq!(fault.errors(), 2); // activation, then mandatory recovery sync
            assert!(!home.path().join("vault.json.new").exists());
            let account = recovery_account(home.path()).unwrap().unwrap();
            let protected = get_credential(&account).unwrap().unwrap();
            let snapshot = fs::read(home.path().join("audit.rotation.json")).unwrap();
            let record: RotationRecovery = serde_json::from_str(&protected).unwrap();
            let activated = fs::read(crate::paths::vault_file(home.path())).unwrap();
            assert_eq!(vault_digest(&activated), record.after);
            let new = parse_identity(&record.new_key).unwrap();
            assert_ne!(new.to_public(), old.to_public());
            let vault: crate::store::Vault = serde_json::from_slice(&activated).unwrap();
            assert_eq!(vault.secrets.len(), usize::from(!empty));
            for entry in &vault.secrets {
                assert_eq!(decrypt_value(&new, &entry.cipher).unwrap(), "synthetic-value");
            }
            for name in ["audit.log", "audit.head", "audit.key.age"] {
                assert!(!home.path().join(name).exists());
            }
            assert!(recover_rotation_locked(home.path()).is_err());
            assert_eq!(fault.errors(), 3);
            assert_eq!(get_credential(&account).unwrap().as_deref(), Some(protected.as_str()));
            assert_eq!(fs::read(home.path().join("audit.rotation.json")).unwrap(), snapshot);
            assert_eq!(fs::read(crate::paths::vault_file(home.path())).unwrap(), activated);
            drop(fault);
            recover_rotation_locked(home.path()).unwrap();
            assert!(get_credential(&account).unwrap().is_none());
            assert!(!home.path().join("audit.rotation.json").exists());
            assert_eq!(load_identity_locked(home.path()).unwrap().to_public(), new.to_public());
            assert_eq!(fs::read(crate::paths::vault_file(home.path())).unwrap(), activated);
        }
    }

    #[test]
    fn last_audit_change_sync_failure_is_retried_when_bytes_already_match() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        for rollback in [false, true] {
            let home = tempfile::TempDir::new().unwrap();
            let old = generate_identity();
            let new = generate_identity();
            store_identity(&old, home.path()).unwrap();
            seed_vault(home.path(), &old);
            let _lock = crate::store::lock_generation(home.path()).unwrap();
            crate::audit::record_locked(
                home.path(), old.to_string().expose_secret().as_bytes(), "run", "synthetic",
            ).unwrap();
            let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
            let mut vault = crate::store::Vault::load_locked(home.path()).unwrap();
            vault.secrets[0].cipher = encrypt_value(&new.to_public(), "synthetic-value").unwrap();
            let after = serde_json::to_vec_pretty(&vault).unwrap();
            prepare_rotation_locked(home.path(), &old, &new, &before, &after).unwrap();
            let account = recovery_account(home.path()).unwrap().unwrap();
            let protected = get_credential(&account).unwrap().unwrap();
            let snapshot = fs::read(home.path().join("audit.rotation.json")).unwrap();
            let states: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
            let target = if rollback { "before" } else { "after" };
            let selected = if rollback { &old } else { &new };
            if !rollback {
                store_identity_locked(&new, home.path()).unwrap();
                fs::write(crate::paths::vault_file(home.path()), &after).unwrap();
            }
            // Earlier audit components already match. Only the final wrapper
            // replacement (forward) or deletion (rollback) remains to perform.
            for (index, name) in ["audit.log", "audit.head", "audit.key.age"].iter().enumerate() {
                let state = if index == 2 {
                    if rollback { "after" } else { "before" }
                } else {
                    target
                };
                let bytes: Option<Vec<u8>> = serde_json::from_value(states[state][index].clone()).unwrap();
                match bytes {
                    Some(bytes) => fs::write(home.path().join(name), bytes).unwrap(),
                    None => assert!(!home.path().join(name).exists()),
                }
            }
            let fault = crate::audit::DirectorySyncFailure::after(0);
            let error = recover_rotation_locked(home.path()).unwrap_err();
            assert!(error.downcast_ref::<std::io::Error>().is_some());
            assert_eq!(fault.errors(), 1);
            // The real replacement/deletion ran before the injected sync error.
            for (index, name) in ["audit.log", "audit.head", "audit.key.age"].iter().enumerate() {
                let expected: Option<Vec<u8>> = serde_json::from_value(states[target][index].clone()).unwrap();
                match expected {
                    Some(bytes) => assert_eq!(fs::read(home.path().join(name)).unwrap(), bytes),
                    None => assert!(!home.path().join(name).exists()),
                }
            }
            assert_eq!(get_credential(&account).unwrap().as_deref(), Some(protected.as_str()));
            assert_eq!(fs::read(home.path().join("audit.rotation.json")).unwrap(), snapshot);
            // All bytes now match, but the final directory sync must still run.
            assert!(recover_rotation_locked(home.path()).is_err());
            assert_eq!(fault.errors(), 2);
            assert_eq!(get_credential(&account).unwrap().as_deref(), Some(protected.as_str()));
            assert_eq!(fs::read(home.path().join("audit.rotation.json")).unwrap(), snapshot);
            drop(fault);
            recover_rotation_locked(home.path()).unwrap();
            assert!(get_credential(&account).unwrap().is_none());
            assert!(!home.path().join("audit.rotation.json").exists());
            let identity = load_identity_locked(home.path()).unwrap();
            assert_eq!(identity.to_public(), selected.to_public());
            let key = crate::audit::verification_key_locked(home.path(), &identity).unwrap();
            let entries = crate::audit::read_locked(home.path()).unwrap();
            assert_eq!(crate::audit::verify_locked(home.path(), key.expose_secret().as_bytes(), &entries),
                crate::audit::Integrity::Ok);
            assert_eq!(decrypt_value(&identity, &crate::store::Vault::load_locked(home.path()).unwrap().secrets[0].cipher).unwrap(),
                "synthetic-value");
        }
    }

    #[test]
    fn audit_and_vault_recover_together_at_each_activation_boundary() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        for previously_rotated in [false, true] {
            for empty in [false, true] {
                for activation in 0..3 {
                    for failure in 0..3 {
                        let home = tempfile::TempDir::new().unwrap();
                        let first = generate_identity();
                        store_identity(&first, home.path()).unwrap();
                        if empty {
                            crate::store::Vault::default().save(home.path()).unwrap();
                        } else {
                            seed_vault(home.path(), &first);
                        }
                        fs::write(home.path().join("config.json"),
                            r#"{"audit_log":true,"touch_id":false}"#).unwrap();
                        crate::access::unlock(home.path(), "run", "synthetic-before").unwrap();
                        if previously_rotated {
                            crate::commands::rotate::rotate_in_place(home.path()).unwrap();
                        }
                        let old = load_identity(home.path()).unwrap();
                        let new = generate_identity();
                        let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
                        let mut vault = crate::store::Vault::load(home.path()).unwrap();
                        for entry in &mut vault.secrets {
                            entry.cipher = encrypt_value(&new.to_public(), "synthetic-value").unwrap();
                        }
                        let after = serde_json::to_vec_pretty(&vault).unwrap();
                        let expected_new = if empty { activation >= 1 } else { activation == 2 };
                        let expected = if expected_new { &new } else { &old };
                        {
                            let _lock = crate::store::lock_generation(home.path()).unwrap();
                            prepare_rotation_locked(home.path(), &old, &new, &before, &after).unwrap();
                            let account = recovery_account(home.path()).unwrap().unwrap();
                            let protected = get_credential(&account).unwrap();
                            assert!(protected.as_ref().unwrap().len() < 2048);
                            if activation >= 1 {
                                store_identity_locked(&new, home.path()).unwrap();
                            }
                            if activation == 2 {
                                fs::write(crate::paths::vault_file(home.path()), &after).unwrap();
                            } else {
                                // Model interrupted audit activation while the old vault survives.
                                let snapshot: serde_json::Value = serde_json::from_slice(
                                    &fs::read(home.path().join("audit.rotation.json")).unwrap(),
                                ).unwrap();
                                let post_log: Option<Vec<u8>> =
                                    serde_json::from_value(snapshot["after"][0].clone()).unwrap();
                                if let Some(log) = post_log {
                                    fs::write(home.path().join("audit.log"), log).unwrap();
                                }
                            }
                            crate::audit::fail_recovery_after(failure);
                            assert!(recover_rotation_locked(home.path()).is_err());
                            assert_eq!(get_credential(&account).unwrap(), protected);
                            assert!(home.path().join("audit.rotation.json").exists());
                            recover_rotation_locked(home.path()).unwrap();
                            assert!(get_credential(&account).unwrap().is_none());
                            let recovered = load_identity_locked(home.path()).unwrap();
                            assert_eq!(recovered.to_public(), expected.to_public());
                            let key = crate::audit::verification_key_locked(home.path(), &recovered).unwrap();
                            let entries = crate::audit::read_locked(home.path()).unwrap();
                            assert_eq!(crate::audit::verify_locked(home.path(), key.expose_secret().as_bytes(), &entries),
                                crate::audit::Integrity::Ok);
                            for entry in crate::store::Vault::load_locked(home.path()).unwrap().secrets {
                                assert_eq!(decrypt_value(&recovered, &entry.cipher).unwrap(), "synthetic-value");
                            }
                        }
                        // Ordinary audited access completes after pending recovery, then another rotation.
                        crate::access::unlock(home.path(), "run", "synthetic-after").unwrap();
                        crate::commands::rotate::rotate_in_place(home.path()).unwrap();
                        crate::access::unlock(home.path(), "run", "synthetic-repeat").unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn missing_snapshot_preserves_recovery_and_retries_through_audited_access() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        store_identity(&old, home.path()).unwrap();
        seed_vault(home.path(), &old);
        let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
        let new = generate_identity();
        {
            let _lock = crate::store::lock_generation(home.path()).unwrap();
            // Absent audit history is an explicit snapshot state, not a missing backup.
            prepare_rotation_locked(home.path(), &old, &new, &before, b"not-activated").unwrap();
            store_identity_locked(&new, home.path()).unwrap();
        }
        let snapshot = home.path().join("audit.rotation.json");
        let saved = fs::read(&snapshot).unwrap();
        let account = recovery_account(home.path()).unwrap().unwrap();
        let protected = get_credential(&account).unwrap();
        fs::remove_file(&snapshot).unwrap();
        fs::write(home.path().join("config.json"), r#"{"audit_log":true,"touch_id":false}"#).unwrap();
        assert!(crate::access::unlock(home.path(), "run", "must-not-log").is_err());
        assert_eq!(get_credential(&account).unwrap(), protected);
        assert_eq!(fs::read(crate::paths::vault_file(home.path())).unwrap(), before);
        assert!(!home.path().join("audit.log").exists());
        fs::write(snapshot, saved).unwrap();
        let recovered = crate::access::unlock(home.path(), "run", "retried").unwrap();
        assert_eq!(recovered.to_public(), old.to_public());
        assert!(get_credential(&account).unwrap().is_none());
        assert_eq!(crate::audit::read_locked(home.path()).unwrap().len(), 1);
    }

    #[test]
    fn audit_restore_backend_failure_retains_keys_and_large_snapshot_for_retry() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        let new = generate_identity();
        store_identity(&old, home.path()).unwrap();
        seed_vault(home.path(), &old);
        fs::write(home.path().join("config.json"), r#"{"audit_log":true,"touch_id":false}"#).unwrap();
        crate::access::unlock(home.path(), "run", &"synthetic-detail-".repeat(4096)).unwrap();
        let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
        let mut vault = crate::store::Vault::load(home.path()).unwrap();
        vault.secrets[0].cipher = encrypt_value(&new.to_public(), "synthetic-value").unwrap();
        let after = serde_json::to_vec_pretty(&vault).unwrap();
        let stable = stable_identity_account(&read_vault_id(home.path()).unwrap().unwrap());
        let stable_file = credential_file(&stable).unwrap();
        {
            let _lock = crate::store::lock_generation(home.path()).unwrap();
            prepare_rotation_locked(home.path(), &old, &new, &before, &after).unwrap();
            fs::write(crate::paths::vault_file(home.path()), after).unwrap();
            fs::remove_file(&stable_file).unwrap();
            fs::create_dir(&stable_file).unwrap(); // benign isolated backend write failure
            let account = recovery_account(home.path()).unwrap().unwrap();
            let record = get_credential(&account).unwrap();
            assert!(record.as_ref().unwrap().len() < 2048);
            assert!(fs::metadata(home.path().join("audit.rotation.json")).unwrap().len() > 65536);
            assert!(recover_rotation_locked(home.path()).is_err());
            assert_eq!(get_credential(&account).unwrap(), record);
            assert!(home.path().join("audit.rotation.json").exists());
            fs::remove_dir(&stable_file).unwrap();
        }
        let recovered = crate::access::unlock(home.path(), "run", "backend-retry").unwrap();
        assert_eq!(recovered.to_public(), new.to_public());
        assert_eq!(decrypt_value(&recovered, &crate::store::Vault::load(home.path()).unwrap().secrets[0].cipher).unwrap(), "synthetic-value");
    }

    #[test]
    fn absent_history_and_identical_empty_vault_rotate_repeatedly() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        store_identity(&generate_identity(), home.path()).unwrap();
        crate::store::Vault::default().save(home.path()).unwrap();
        let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
        for _ in 0..3 {
            let old = load_identity(home.path()).unwrap();
            crate::commands::rotate::rotate_in_place(home.path()).unwrap();
            let current = load_identity(home.path()).unwrap();
            assert_ne!(old.to_public(), current.to_public());
            assert_eq!(fs::read(crate::paths::vault_file(home.path())).unwrap(), before);
            assert!(!home.path().join("audit.log").exists());
            assert!(!home.path().join("audit.key.age").exists());
        }
    }

    #[test]
    fn transactions_recover_rotation_before_insert_metadata_and_delete() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        for activated in [false, true] {
            for action in ["insert", "metadata", "delete"] {
                let home = tempfile::TempDir::new().unwrap();
                let old = generate_identity();
                let new = generate_identity();
                store_identity(&old, home.path()).unwrap();
                seed_vault(home.path(), &old);
                // Keep a second entry to establish decryptability even after deletion.
                crate::store::Vault::transaction(home.path(), |v| {
                    let mut other = v.secrets[0].clone();
                    other.alias = "keep".into();
                    v.insert(other)
                })
                .unwrap();
                let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
                let mut rotated = crate::store::Vault::load(home.path()).unwrap();
                for e in &mut rotated.secrets {
                    e.cipher = encrypt_value(&new.to_public(), "synthetic-value").unwrap();
                }
                let after = serde_json::to_vec_pretty(&rotated).unwrap();
                let target = rotated
                    .secrets
                    .iter()
                    .find(|e| e.alias != "keep")
                    .unwrap()
                    .alias
                    .clone();
                {
                    let _lock = crate::store::lock_generation(home.path()).unwrap();
                    prepare_rotation_locked(home.path(), &old, &new, &before, &after).unwrap();
                    // Deliberately mismatch the active slot and persisted bytes.
                    store_identity_locked(if activated { &old } else { &new }, home.path())
                        .unwrap();
                    fs::write(
                        crate::paths::vault_file(home.path()),
                        if activated { &after } else { &before },
                    )
                    .unwrap();
                }
                let expected = if activated { &new } else { &old };
                crate::store::Vault::transaction_for_recipient(
                    home.path(),
                    &expected.to_public(),
                    |v, recipient| {
                        match action {
                            "insert" => {
                                let mut e = v.secrets[0].clone();
                                e.alias = "inserted".into();
                                e.cipher = encrypt_value(recipient, "synthetic-value")?;
                                v.insert(e)?;
                            }
                            "metadata" => {
                                v.secrets
                                    .iter_mut()
                                    .find(|e| e.alias == target)
                                    .unwrap()
                                    .notes = "edited".into()
                            }
                            "delete" => v.secrets.retain(|e| e.alias != target),
                            _ => unreachable!(),
                        }
                        Ok(())
                    },
                )
                .unwrap();
                let id = load_identity(home.path()).unwrap();
                assert_eq!(id.to_public(), expected.to_public());
                let saved = crate::store::Vault::load(home.path()).unwrap();
                for e in &saved.secrets {
                    assert_eq!(decrypt_value(&id, &e.cipher).unwrap(), "synthetic-value");
                }
                match action {
                    "insert" => assert!(saved.get("inserted").is_some()),
                    "metadata" => assert_eq!(saved.get(&target).unwrap().notes, "edited"),
                    "delete" => assert!(saved.get(&target).is_none()),
                    _ => unreachable!(),
                }
                assert!(
                    get_credential(&recovery_account(home.path()).unwrap().unwrap())
                        .unwrap()
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn transactions_refuse_unknown_recovery_bytes_without_mutation() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        store_identity(&old, home.path()).unwrap();
        seed_vault(home.path(), &old);
        let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
        {
            let _lock = crate::store::lock_generation(home.path()).unwrap();
            prepare_rotation_locked(home.path(), &old, &generate_identity(), &before, b"after")
                .unwrap();
        }
        let account = recovery_account(home.path()).unwrap().unwrap();
        let record = get_credential(&account).unwrap();
        let unknown = b"{\"secrets\":[]}";
        fs::write(crate::paths::vault_file(home.path()), unknown).unwrap();
        let result = crate::store::Vault::transaction_for_recipient(
            home.path(),
            &old.to_public(),
            |_v, _r| -> Result<()> {
                panic!("mutation must not be called before recovery succeeds")
            },
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(crate::paths::vault_file(home.path())).unwrap(),
            unknown
        );
        assert_eq!(get_credential(&account).unwrap(), record);
    }

    #[test]
    fn interrupted_activation_recovers_the_key_for_current_ciphertext() {
        let _env = test_env_lock();
        let creds = SyntheticCredentials::new();
        for activated in [false, true] {
            let home = tempfile::TempDir::new().unwrap();
            let old = generate_identity();
            let new = generate_identity();
            store_identity(&old, home.path()).unwrap();
            seed_vault(home.path(), &old);
            let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
            seed_vault(home.path(), &new);
            let after = fs::read(crate::paths::vault_file(home.path())).unwrap();
            fs::write(crate::paths::vault_file(home.path()), &before).unwrap();
            {
                let _lock = crate::store::lock_generation(home.path()).unwrap();
                prepare_rotation_locked(home.path(), &old, &new, &before, &after).unwrap();
                delete_identity(home.path(), &old).unwrap();
                if activated {
                    store_identity_locked(&new, home.path()).unwrap();
                    fs::write(crate::paths::vault_file(home.path()), &after).unwrap();
                } else {
                    // Simulate a backend that cannot recreate the deleted slot.
                    let stable =
                        stable_identity_account(&read_vault_id(home.path()).unwrap().unwrap());
                    fs::create_dir(creds.0.path().join(&stable)).unwrap();
                    assert!(recover_rotation_locked(home.path()).is_err());
                    assert!(
                        get_credential(&recovery_account(home.path()).unwrap().unwrap())
                            .unwrap()
                            .is_some()
                    );
                    fs::remove_dir(creds.0.path().join(stable)).unwrap();
                }
            }
            let active = load_identity(home.path()).unwrap();
            assert_eq!(
                active.to_public(),
                if activated {
                    new.to_public()
                } else {
                    old.to_public()
                }
            );
            let vault = crate::store::Vault::load(home.path()).unwrap();
            assert_eq!(
                decrypt_value(&active, &vault.secrets[0].cipher).unwrap(),
                "synthetic-value"
            );
            assert!(
                get_credential(&recovery_account(home.path()).unwrap().unwrap())
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn recovery_rejects_unknown_vault_bytes_without_erasing_keys() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        store_identity(&old, home.path()).unwrap();
        let _lock = crate::store::lock_generation(home.path()).unwrap();
        prepare_rotation_locked(home.path(), &old, &generate_identity(), b"before", b"after")
            .unwrap();
        fs::write(crate::paths::vault_file(home.path()), b"unrecognized").unwrap();
        let account = recovery_account(home.path()).unwrap().unwrap();
        let record = get_credential(&account).unwrap();
        assert!(recover_rotation_locked(home.path()).is_err());
        assert_eq!(get_credential(&account).unwrap(), record);
        let stable = stable_identity_account(&read_vault_id(home.path()).unwrap().unwrap());
        assert_eq!(
            parse_identity(&get_credential(&stable).unwrap().unwrap())
                .unwrap()
                .to_public(),
            old.to_public()
        );
    }

    #[test]
    fn empty_vault_rotation_activates_new_key() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        store_identity(&old, home.path()).unwrap();
        crate::store::Vault::default().save(home.path()).unwrap();
        let result = crate::commands::rotate::rotate_in_place(home.path()).unwrap();
        assert_ne!(result.recipient, old.to_public());
        assert_eq!(
            load_identity(home.path()).unwrap().to_public(),
            result.recipient
        );
    }

    #[test]
    fn delayed_first_access_cannot_replay_legacy_key_after_rotation() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        let home = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        seed_vault(home.path(), &old);
        set_credential(LEGACY_KEYCHAIN_ACCOUNT, old.to_string().expose_secret()).unwrap();
        let lock = crate::store::lock_generation(home.path()).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter_home = home.path().to_owned();
        let waiter = std::thread::spawn(move || {
            let probe = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(waiter_home.join("vault.lock"))
                .unwrap();
            assert!(matches!(
                probe.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            ready_tx.send(()).unwrap();
            load_identity(&waiter_home).unwrap().to_public()
        });
        ready_rx.recv().unwrap();
        // Another first access migrates and rotates while the waiter is blocked.
        let authorized = load_identity_locked(home.path()).unwrap();
        let result =
            crate::commands::rotate::rotate_authorized_locked(home.path(), &authorized).unwrap();
        drop(lock);
        assert_eq!(waiter.join().unwrap(), result.recipient);
        assert_eq!(
            load_identity(home.path()).unwrap().to_public(),
            result.recipient
        );
    }

    #[test]
    fn rotating_one_migrated_legacy_vault_retains_other_vault_and_history() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        let first = tempfile::TempDir::new().unwrap();
        let second = tempfile::TempDir::new().unwrap();
        let old = generate_identity();
        let historical = seed_vault(first.path(), &old);
        seed_vault(second.path(), &old);
        set_credential(LEGACY_KEYCHAIN_ACCOUNT, old.to_string().expose_secret()).unwrap();
        load_identity(first.path()).unwrap();
        load_identity(second.path()).unwrap();
        crate::commands::rotate::rotate_in_place(first.path()).unwrap();
        let remaining = load_identity(second.path()).unwrap();
        assert_eq!(remaining.to_public(), old.to_public());
        assert_eq!(
            decrypt_value(&remaining, &historical).unwrap(),
            "synthetic-value"
        );
        let current = crate::store::Vault::load(first.path()).unwrap();
        assert!(decrypt_value(&remaining, &current.secrets[0].cipher).is_err());
        assert!(get_credential(LEGACY_KEYCHAIN_ACCOUNT).unwrap().is_none());
    }
    #[test]
    fn empty_legacy_backend_failure_is_retryable() {
        let _env = test_env_lock();
        let _creds = SyntheticCredentials::new();
        for partial in [false, true] {
            let home = tempfile::TempDir::new().unwrap();
            crate::store::Vault::default().save(home.path()).unwrap();
            let before = fs::read(crate::paths::vault_file(home.path())).unwrap();
            let old = generate_identity();
            set_credential(LEGACY_KEYCHAIN_ACCOUNT, old.to_string().expose_secret()).unwrap();
            let result = initialize_empty_legacy_using(home.path(), |account, raw| {
                // Includes a partial-success failure: the backend persisted the key
                // but reported an error. No association may be published yet.
                if partial {
                    set_credential(account, raw)?;
                }
                anyhow::bail!("synthetic credential-write failure")
            });
            assert!(result.is_err());
            assert!(!crate::paths::identity_id_file(home.path()).exists());
            assert_eq!(
                fs::read(crate::paths::vault_file(home.path())).unwrap(),
                before
            );
            initialize_empty_legacy(home.path()).unwrap();
            assert_ne!(
                load_identity(home.path()).unwrap().to_public(),
                old.to_public()
            );
            assert_eq!(
                get_credential(LEGACY_KEYCHAIN_ACCOUNT)
                    .unwrap()
                    .unwrap()
                    .trim(),
                old.to_string().expose_secret()
            );
        }
    }
}
