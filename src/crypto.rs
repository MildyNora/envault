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
use std::fs;
use std::path::Path;
use std::str::FromStr;

const KEYCHAIN_SERVICE: &str = "envault";
const KEYCHAIN_ACCOUNT: &str = "age-identity";

fn identity_file_override() -> Option<std::path::PathBuf> {
    std::env::var("ENVAULT_IDENTITY_FILE").ok().map(Into::into)
}

pub fn store_identity(identity: &age::x25519::Identity, _home: &Path) -> Result<()> {
    let key = identity.to_string(); // SecretString
    if let Some(path) = identity_file_override() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, format!("{}\n", key.expose_secret()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .context("opening Keychain entry")?;
    entry
        .set_password(key.expose_secret())
        .context("storing identity in the macOS Keychain")
}

pub fn load_identity() -> Result<age::x25519::Identity> {
    let raw = if let Some(path) = identity_file_override() {
        fs::read_to_string(&path)
            .with_context(|| format!("reading identity file {}", path.display()))?
    } else {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
            .context("opening Keychain entry")?;
        entry.get_password().context(
            "no envault identity in the Keychain — run `envault init` (or grant Keychain access)",
        )?
    };
    age::x25519::Identity::from_str(raw.trim())
        .map_err(|e| anyhow::anyhow!("invalid age identity: {e}"))
}

pub fn delete_identity() -> Result<()> {
    if let Some(path) = identity_file_override() {
        if path.exists() {
            fs::remove_file(&path)?;
        }
        return Ok(());
    }
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .context("opening Keychain entry")?;
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
        let dir = tempfile::TempDir::new().unwrap();
        let id_path = dir.path().join("identity.txt");
        // Only unit test that mutates process env; keep it that way to stay parallel-safe.
        std::env::set_var("ENVAULT_IDENTITY_FILE", &id_path);
        let id = generate_identity();
        store_identity(&id, dir.path()).unwrap();
        store_recipient(&id, dir.path()).unwrap();
        let loaded = load_identity().unwrap();
        std::env::remove_var("ENVAULT_IDENTITY_FILE");

        let cipher = encrypt_value(&load_recipient(dir.path()).unwrap(), "roundtrip").unwrap();
        assert_eq!(decrypt_value(&loaded, &cipher).unwrap(), "roundtrip");

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&id_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn missing_recipient_mentions_init() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = load_recipient(dir.path()).unwrap_err().to_string();
        assert!(err.contains("envault init"), "got: {err}");
    }
}
