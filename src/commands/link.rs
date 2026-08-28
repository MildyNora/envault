use anyhow::{bail, Result};

use crate::manifest::{find_manifest, Manifest, MANIFEST_NAME};
use crate::paths;
use crate::store::Vault;

pub fn cmd_link(env_var: String, alias: String) -> Result<()> {
    // Restrict to a real env-var identifier so nothing (e.g. a quote) can be
    // injected into envault.toml. (L5)
    if !crate::manifest::is_valid_env_var(&env_var) {
        bail!("'{env_var}' is not a valid environment variable name (use A-Z, 0-9, _; not starting with a digit)");
    }
    let vault = Vault::load(&paths::envault_home())?;
    if vault.get(&alias).is_none() {
        bail!("alias '{alias}' is not in the vault — create it with `envault add {alias}`");
    }
    let cwd = std::env::current_dir()?;
    let mut manifest = match find_manifest(&cwd) {
        Some(path) => Manifest::load(&path)?,
        None => Manifest {
            path: cwd.join(MANIFEST_NAME),
            mappings: Default::default(),
        },
    };
    manifest.mappings.insert(env_var.clone(), alias.clone());
    manifest.save()?;
    println!("Linked {env_var} -> {alias} in {}", manifest.path.display());
    Ok(())
}
