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
    let recipient = load_recipient(home)?;
    if identity.to_public().to_string() != recipient.to_string() {
        anyhow::bail!(
            "no matching envault identity for {} — restore its original identity or backup",
            home.display()
        );
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

pub fn store_identity(identity: &age::x25519::Identity, home: &Path) -> Result<()> {
    let key = identity.to_string(); // SecretString
    let id = ensure_vault_id(home)?;
    set_credential(&stable_identity_account(&id), key.expose_secret())
}

pub fn load_identity(home: &Path) -> Result<age::x25519::Identity> {
    if let Some(id) = read_vault_id(home)? {
        let account = stable_identity_account(&id);
        if let Some(raw) = get_credential(&account)? {
            let identity = parse_matching_identity(&raw, home)?;
            // A failed cleanup during path-to-stable migration is retried on
            // later access rather than leaving an obsolete credential forever.
            if fixed_identity_file().is_none() {
                let path_account = path_identity_account(home)?;
                remove_if_matching(&path_account, &identity)?;
            }
            return Ok(identity);
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
    // unmigrated vault may still need it. Rotation removes every matching copy.
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
        let parsed = parse_identity(&raw)?;
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
    let stored = parse_matching_identity(&raw, home)?;
    if stored.to_string().expose_secret() != expected.to_string().expose_secret() {
        anyhow::bail!("refusing to delete an unexpected vault identity");
    }
    remove_credential(&stable)?;

    let path_account = path_identity_account(home)?;
    remove_if_matching(&path_account, expected)?;
    remove_if_matching(LEGACY_KEYCHAIN_ACCOUNT, expected)
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

pub fn store_recipient(identity: &age::x25519::Identity, home: &Path) -> Result<()> {
    fs::create_dir_all(home)?;
    fs::write(
        crate::paths::recipient_file(home),
        format!("{}\n", identity.to_public()),
    )?;
    Ok(())
}

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
    fn identity_must_match_the_vault_recipient() {
        let home = tempfile::TempDir::new().unwrap();
        let identity = generate_identity();
        let other = generate_identity();
        store_recipient(&identity, home.path()).unwrap();

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
        store_recipient(&identity, home.path()).unwrap();
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
        store_recipient(&identity, home.path()).unwrap();
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
}
