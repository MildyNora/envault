use anyhow::{bail, Result};
use std::fs;

use crate::crypto;
use crate::paths;
use crate::store::Vault;

pub fn cmd_init() -> Result<()> {
    let home = paths::envault_home();
    if paths::vault_file(&home).exists() {
        bail!("already initialized at {}", home.display());
    }
    fs::create_dir_all(&home)?;
    crate::platform::set_mode(&home, 0o700)?;

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
