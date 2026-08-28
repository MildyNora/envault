use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::crypto;
use crate::paths;
use crate::store::Vault;

pub struct RotateOutcome {
    pub count: usize,
    pub recipient: age::x25519::Recipient,
}

/// Re-encrypt every secret to a brand-new keypair. Shared by the CLI command
/// and the TUI's `:rotate`.
pub fn rotate_in_place(home: &Path) -> Result<RotateOutcome> {
    let mut vault = Vault::load(home)?;
    let old_identity = crate::access::unlock(home, "rotate", "re-key vault")?;

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
    crate::platform::set_mode(&staged, 0o600)?;

    // Delete-then-create gives the new Keychain item a fresh ACL, so macOS
    // asks for authorization again: rotation revokes every prior grant.
    crypto::delete_identity()?;
    crypto::store_identity(&new_identity, home)?;
    fs::rename(&staged, paths::vault_file(home)).context("activating the rotated vault")?;
    crypto::store_recipient(&new_identity, home)?;

    Ok(RotateOutcome {
        count: values.len(),
        recipient: new_recipient,
    })
}

pub fn cmd_rotate() -> Result<()> {
    // In-binary human-only enforcement (not just the bypassable guard hook): an
    // agent's non-interactive shell can't trigger destructive re-keying. Scoped
    // to release so the non-TTY integration test still exercises rotation. (M3)
    #[cfg(not(debug_assertions))]
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!(
            "`envault rotate` re-keys the whole vault and must be run interactively — \
             run it yourself in a terminal."
        );
    }
    let outcome = rotate_in_place(&paths::envault_home())?;
    println!("Rotated {} secret(s) to a new keypair", outcome.count);
    println!("  new public key: {}", outcome.recipient);
    println!(
        "\nmacOS will ask for Keychain authorization again on next use — intentional:\n\
         rotation revokes every previously granted 'Always Allow'."
    );
    Ok(())
}
