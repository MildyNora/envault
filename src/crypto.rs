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
use std::path::Path;
use std::str::FromStr;

const KEYCHAIN_SERVICE: &str = "envault";
const LEGACY_KEYCHAIN_ACCOUNT: &str = "age-identity";

fn identity_account(home: &Path) -> Result<String> {
    let home = fs::canonicalize(home)
        .with_context(|| format!("resolving envault home {}", home.display()))?;
    let digest = Sha256::digest(home.as_os_str().as_encoded_bytes());
    Ok(format!("age-identity-{digest:x}"))
}

/// Test-only escape hatch to store the identity in a file instead of the
/// Keychain. Honored ONLY in debug/test builds; a release binary (what
/// `cargo install` produces) ignores it, so a malicious agent cannot redirect
/// the private key to an attacker-named plaintext file. (H5)
fn identity_file_override(home: &Path) -> Result<Option<std::path::PathBuf>> {
    #[cfg(debug_assertions)]
    {
        if let Ok(dir) = std::env::var("ENVAULT_IDENTITY_DIR") {
            return Ok(Some(
                std::path::PathBuf::from(dir).join(identity_account(home)?),
            ));
        }
        Ok(std::env::var("ENVAULT_IDENTITY_FILE").ok().map(Into::into))
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = home;
        Ok(None)
    }
}

fn parse_identity(raw: &str) -> Result<age::x25519::Identity> {
    age::x25519::Identity::from_str(raw.trim())
        .map_err(|e| anyhow::anyhow!("invalid age identity: {e}"))
}

fn parse_matching_legacy_identity(raw: &str, home: &Path) -> Result<age::x25519::Identity> {
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

pub fn store_identity(identity: &age::x25519::Identity, home: &Path) -> Result<()> {
    let key = identity.to_string(); // SecretString
    if let Some(path) = identity_file_override(home)? {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, format!("{}\n", key.expose_secret()))?;
        crate::platform::set_mode(&path, 0o600)?;
        return Ok(());
    }
    let account = identity_account(home)?;
    let entry =
        keyring::Entry::new(KEYCHAIN_SERVICE, &account).context("opening Keychain entry")?;
    entry
        .set_password(key.expose_secret())
        .context("storing identity in the macOS Keychain")
}

pub fn load_identity(home: &Path) -> Result<age::x25519::Identity> {
    if let Some(path) = identity_file_override(home)? {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("reading identity file {}", path.display()))?;
        return parse_identity(&raw);
    }

    let account = identity_account(home)?;
    let entry =
        keyring::Entry::new(KEYCHAIN_SERVICE, &account).context("opening Keychain entry")?;
    let raw = match entry.get_password() {
        Ok(raw) => raw,
        Err(keyring::Error::NoEntry) => {
            // Pre-scoping releases stored one global identity. Accept it only
            // when its public key matches this vault, so a different home can
            // never inherit unrelated key material.
            let legacy = keyring::Entry::new(KEYCHAIN_SERVICE, LEGACY_KEYCHAIN_ACCOUNT)
                .context("opening legacy Keychain entry")?;
            let raw = legacy.get_password().context(
                "no envault identity in the Keychain — run `envault init` (or grant Keychain access)",
            )?;
            return parse_matching_legacy_identity(&raw, home);
        }
        Err(e) => return Err(e).context("reading identity from the Keychain"),
    };
    parse_identity(&raw)
}

pub fn delete_identity(home: &Path) -> Result<()> {
    if let Some(path) = identity_file_override(home)? {
        if path.exists() {
            fs::remove_file(&path)?;
        }
        return Ok(());
    }
    let account = identity_account(home)?;
    let entry =
        keyring::Entry::new(KEYCHAIN_SERVICE, &account).context("opening Keychain entry")?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("deleting the old identity from the Keychain"),
    }
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
    fn legacy_identity_must_match_the_vault_recipient() {
        let home = tempfile::TempDir::new().unwrap();
        let identity = generate_identity();
        let other = generate_identity();
        store_recipient(&identity, home.path()).unwrap();

        let raw = identity.to_string();
        assert!(parse_matching_legacy_identity(raw.expose_secret(), home.path()).is_ok());

        let raw = other.to_string();
        let err = match parse_matching_legacy_identity(raw.expose_secret(), home.path()) {
            Ok(_) => panic!("unrelated legacy identity was accepted"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("no matching envault identity"));
    }

    #[test]
    fn missing_recipient_mentions_init() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = load_recipient(dir.path()).unwrap_err().to_string();
        assert!(err.contains("envault init"), "got: {err}");
    }
}
