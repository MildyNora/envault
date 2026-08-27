use anyhow::{Context, Result};
use std::fs;

use crate::crypto;
use crate::paths;
use crate::store::Vault;

pub fn cmd_rotate() -> Result<()> {
    let home = paths::envault_home();
    let mut vault = Vault::load(&home)?;
    let old_identity = crypto::load_identity()?;

    // Decrypt everything up front: any failure aborts before any state changes.
    let mut values: Vec<String> = Vec::with_capacity(vault.secrets.len());
    for entry in &vault.secrets {
        values.push(
            crypto::decrypt_value(&old_identity, &entry.cipher)
                .with_context(|| format!("decrypting '{}' with the current key", entry.alias))?,
        );
    }

    let new_identity = crypto::generate_identity();
    let new_recipient = new_identity.to_public();
    for (entry, value) in vault.secrets.iter_mut().zip(&values) {
        entry.cipher = crypto::encrypt_value(&new_recipient, value)?;
    }

    // Stage the re-encrypted vault first: if the identity swap below fails,
    // nothing has changed; the lockout window is just the rename.
    let staged = home.join("vault.json.new");
    fs::write(&staged, serde_json::to_string_pretty(&vault)?)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;

    // Delete-then-create gives the new Keychain item a fresh ACL, so macOS
    // asks for authorization again: rotation revokes every prior grant.
    crypto::delete_identity()?;
    crypto::store_identity(&new_identity, &home)?;
    fs::rename(&staged, paths::vault_file(&home)).context("activating the rotated vault")?;
    crypto::store_recipient(&new_identity, &home)?;

    println!("Rotated {} secret(s) to a new keypair", values.len());
    println!("  new public key: {new_recipient}");
    println!(
        "\nmacOS will ask for Keychain authorization again on next use — intentional:\n\
         rotation revokes every previously granted 'Always Allow'."
    );
    Ok(())
}
