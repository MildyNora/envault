use anyhow::{bail, Result};
use std::fs;

use crate::crypto;
use crate::paths;
use crate::store::Vault;

pub fn cmd_init(if_needed: bool, empty_legacy: bool) -> Result<()> {
    let home = paths::envault_home();
    if empty_legacy {
        crypto::initialize_empty_legacy(&home)?;
        println!(
            "Initialized a fresh identity for the empty legacy vault; legacy credentials preserved"
        );
        println!("Next: add a secret with `envault add <alias>`");
        return Ok(());
    }
    if paths::vault_file(&home).exists() {
        if if_needed {
            // Installers call `init --if-needed`: a pre-existing vault is fine.
            // Never re-init — that would replace the keypair and orphan every
            // secret already encrypted to the old one.
            println!("envault already initialized at {}", home.display());
            return Ok(());
        }
        bail!("already initialized at {}", home.display());
    }
    fs::create_dir_all(&home)?;
    crate::platform::set_mode(&home, 0o700)?;
    if crypto::identity_recovery_present(&home)? {
        bail!(
            "vault recovery required at {}: identity metadata exists but vault.json is missing; \
             refusing to replace the private key. Restore vault.json from backup before retrying",
            home.display()
        );
    }

    let identity = crypto::generate_identity();
    crypto::store_identity(&identity, &home)?;
    crypto::store_recipient(&identity, &home)?;
    Vault::default().save(&home)?;

    println!("Initialized envault at {}", home.display());
    println!("  public key : {}", identity.to_public());
    println!("  private key: stored in the macOS Keychain (service 'envault')");
    println!("\nNext: add a secret with `envault add <alias>`");
    Ok(())
}
