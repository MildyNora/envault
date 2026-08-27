use anyhow::{bail, Context, Result};

use crate::cdp;
use crate::crypto;
use crate::paths;
use crate::store::Vault;

pub fn cmd_fill(alias: String, selector: Option<String>, cdp_base: String) -> Result<()> {
    let home = paths::envault_home();
    let vault = Vault::load(&home)?;
    let entry = vault
        .get(&alias)
        .with_context(|| format!("alias '{alias}' is not in the vault (see `envault ls`)"))?
        .clone();

    let targets = cdp::list_targets(&cdp_base).with_context(|| {
        format!(
            "no browser CDP endpoint at {cdp_base} — launch the browser with \
             --remote-debugging-port=9222 (or pass --cdp)"
        )
    })?;
    let target = cdp::pick_page_target(&targets)
        .context("no page tab found in the browser (open the login page first)")?;

    if let Some(secret_url) = &entry.url {
        if !cdp::host_matches(secret_url, &target.url) {
            bail!(
                "refusing to fill: '{alias}' is registered for {secret_url}, \
                 but the active page is {}",
                target.url
            );
        }
    }

    let identity = crypto::load_identity()?;
    let value = crypto::decrypt_value(&identity, &entry.cipher)?;
    let ws_url = target.ws_url.clone().expect("picked target has ws url");
    let place = cdp::fill_via_cdp(&ws_url, selector.as_deref(), &value)?;
    println!("Filled '{alias}' {place} on {}", target.url);
    Ok(())
}
