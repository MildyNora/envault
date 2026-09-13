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
    let old_identity = crate::access::unlock(home, "rotate", "re-key vault")?;
    // Never hold the storage lock across the interactive authorization gate.
    // Once acquired, reject an identity changed by a competing rotation.
    let _generation = crate::store::lock_generation(home)?;
    rotate_authorized_locked(home, &old_identity)
}

/// Caller holds the generation lock after authorization.
pub(crate) fn rotate_authorized_locked(
    home: &Path,
    old_identity: &age::x25519::Identity,
) -> Result<RotateOutcome> {
    anyhow::ensure!(
        crypto::load_identity_locked(home)?.to_public() == old_identity.to_public(),
        "identity changed during authorization — retry rotation"
    );
    let before = fs::read(paths::vault_file(home))?;
    let mut vault: Vault = serde_json::from_slice(&before)?;

    // Decrypt everything up front: any failure aborts before any state changes.
    let mut values: Vec<String> = Vec::with_capacity(vault.secrets.len());
    for entry in &vault.secrets {
        values.push(
            crypto::decrypt_value(old_identity, &entry.cipher)
                .with_context(|| format!("decrypting '{}' with the current key", entry.alias))?,
        );
    }

    let new_identity = crypto::generate_identity();
    let new_recipient = new_identity.to_public();
    for (entry, value) in vault.secrets.iter_mut().zip(&values) {
        entry.cipher = crypto::encrypt_value(&new_recipient, value)?;
    }

    // Stage the re-encrypted vault first: if the identity swap below fails,
    // keep both keys in protected recovery storage until activation is verified.
    let staged = home.join("vault.json.new");
    let after = serde_json::to_vec_pretty(&vault)?;
    fs::write(&staged, &after)?;
    crate::platform::set_mode(&staged, 0o600)?;
    fs::File::open(&staged)?.sync_all()?;
    crate::audit::sync_rotation_directory(home)?;

    // Delete-then-create gives the new Keychain item a fresh ACL, so macOS
    // asks for authorization again: this vault gets a new credential item.
    crypto::prepare_rotation_locked(home, old_identity, &new_identity, &before, &after)?;
    let activation = (|| -> Result<()> {
        crypto::delete_identity(home, old_identity)?;
        crypto::store_identity_locked(&new_identity, home)?;
        fs::rename(&staged, paths::vault_file(home)).context("activating the rotated vault")?;
        crate::audit::sync_rotation_directory(home)?;
        Ok(())
    })();
    // Keep the protected recovery record if backend recovery itself fails.
    // A later load retries it before returning an identity.
    crypto::recover_rotation_locked(home).context("recovering/finishing identity rotation")?;
    activation?;
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
         this vault receives a fresh credential item; other vaults retain their grants."
    );
    Ok(())
}
