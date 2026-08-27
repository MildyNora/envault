use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::crypto;
use crate::manifest::{find_manifest, Manifest, MANIFEST_NAME};
use crate::paths;
use crate::store::{is_valid_alias, now_rfc3339, SecretEntry, Vault};

fn to_alias(var: &str) -> String {
    var.to_lowercase().replace('_', "-")
}

pub fn cmd_import(file: PathBuf) -> Result<()> {
    let home = paths::envault_home();
    let mut vault = Vault::load(&home)?;
    let recipient = crypto::load_recipient(&home)?;

    let cwd = std::env::current_dir()?;
    let mut manifest = match find_manifest(&cwd) {
        Some(path) => Manifest::load(&path)?,
        None => Manifest {
            path: cwd.join(MANIFEST_NAME),
            mappings: Default::default(),
        },
    };

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for item in
        dotenvy::from_path_iter(&file).with_context(|| format!("reading {}", file.display()))?
    {
        let (var, value) = item.context("parsing dotenv entry")?;
        let alias = to_alias(&var);
        if !is_valid_alias(&alias) {
            eprintln!("skipping {var}: derived alias '{alias}' is invalid");
            skipped += 1;
            continue;
        }
        if vault.get(&alias).is_some() {
            eprintln!("skipping {var}: alias '{alias}' already exists");
            skipped += 1;
        } else {
            let now = now_rfc3339();
            vault.insert(SecretEntry {
                label: var.clone(),
                alias: alias.clone(),
                cipher: crypto::encrypt_value(&recipient, &value)?,
                url: None,
                created_at: now.clone(),
                updated_at: now,
                notes: format!("imported from {}", file.display()),
            })?;
            imported += 1;
        }
        manifest.mappings.insert(var, alias);
    }
    vault.save(&home)?;
    manifest.save()?;

    println!("Imported {imported} secret(s) (skipped {skipped}) into the vault");
    println!("Manifest updated: {}", manifest.path.display());
    println!(
        "\nThe plaintext file was NOT deleted. Do it now:\n  rm {}",
        file.display()
    );
    Ok(())
}
