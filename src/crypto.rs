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
    let bytes = B64.decode(cipher_b64.trim()).context("cipher is not valid base64")?;
    let plain = age::decrypt(identity, &bytes)
        .context("decryption failed (wrong key or corrupt cipher)")?;
    String::from_utf8(plain).context("decrypted value is not UTF-8")
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
}
