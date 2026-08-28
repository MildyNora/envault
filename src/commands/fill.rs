use anyhow::{bail, Context, Result};

use crate::cdp;
use crate::crypto;
use crate::paths;
use crate::store::Vault;

pub fn cmd_fill(alias: String, selector: Option<String>, cdp_base: String) -> Result<()> {
    let home = paths::envault_home();

    // Disabled by default: the origin guard below can't be trusted against a
    // same-user process that runs its own loopback CDP endpoint, so `fill` is
    // opt-in. (H1)
    if !crate::settings::Settings::load(&home).fill {
        bail!(
            "`envault fill` is disabled. Enable it with `envault config set fill on` \
             — but only if you understand it: fill CANNOT guarantee the secret goes \
             to the intended site, because a local process can impersonate the \
             browser's DevTools endpoint. Prefer `envault run` when possible."
        );
    }

    // Only ever talk to a loopback DevTools endpoint.
    if !cdp::is_loopback(&cdp_base) {
        bail!(
            "refusing: --cdp must be a loopback endpoint (127.0.0.1 / localhost), got {cdp_base}"
        );
    }

    let vault = Vault::load(&home)?;
    let entry = vault
        .get(&alias)
        .with_context(|| format!("alias '{alias}' is not in the vault (see `envault ls`)"))?
        .clone();

    // A secret registered for a site must not be filled into an unknown one.
    let secret_url = entry.url.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "'{alias}' has no registered url, so fill can't check the destination — \
             refusing. Re-add it with --url <origin>."
        )
    })?;

    let targets = cdp::list_targets(&cdp_base).with_context(|| {
        format!(
            "no browser CDP endpoint at {cdp_base} — launch the browser with \
             --remote-debugging-port=9222 (or pass --cdp)"
        )
    })?;
    let target = cdp::pick_page_target(&targets)
        .context("no page tab found in the browser (open the login page first)")?;

    let ws_url = target.ws_url.clone().expect("picked target has ws url");
    // The target's own websocket must stay on loopback — a fake /json/list
    // can't redirect the plaintext to a remote collector.
    if !cdp::is_loopback(&ws_url) {
        bail!("refusing: the target's debugger websocket is not loopback ({ws_url})");
    }
    if !cdp::host_matches(&secret_url, &target.url) {
        bail!(
            "refusing to fill: '{alias}' is registered for {secret_url}, \
             but the active page is {}",
            target.url
        );
    }

    let identity = crate::access::unlock(&home, "fill", &alias)?;
    let value = crypto::decrypt_value(&identity, &entry.cipher)?;
    let place = cdp::fill_via_cdp(&ws_url, selector.as_deref(), &value)?;
    println!("Filled '{alias}' {place} on {}", target.url);
    Ok(())
}
