use anyhow::{bail, Context, Result};
use std::io::Read;

use crate::crypto;
use crate::paths;
use crate::store::{is_valid_alias, now_rfc3339, SecretEntry, Vault};

pub fn cmd_add(
    alias: String,
    label: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    stdin: bool,
) -> Result<()> {
    if !is_valid_alias(&alias) {
        bail!("alias '{alias}' is invalid — use kebab-case: lowercase letters, digits, '-'");
    }
    let home = paths::envault_home();
    let mut vault = Vault::load(&home)?;
    if vault.get(&alias).is_some() {
        bail!("alias '{alias}' already exists");
    }

    let value = if stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading value from stdin")?;
        buf.trim_end_matches(['\n', '\r']).to_string()
    } else {
        rpassword::prompt_password(format!("Value for '{alias}' (input hidden): "))
            .context("reading value (use --stdin when piping)")?
    };
    if value.is_empty() {
        bail!("empty value");
    }

    let recipient = crypto::load_recipient(&home)?;
    let cipher = crypto::encrypt_value(&recipient, &value)?;
    let now = now_rfc3339();
    vault.insert(SecretEntry {
        label: label.unwrap_or_else(|| alias.clone()),
        alias: alias.clone(),
        cipher,
        url,
        created_at: now.clone(),
        updated_at: now,
        notes: notes.unwrap_or_default(),
    })?;
    vault.save(&home)?;
    println!("Added '{alias}' (encrypted; value not shown)");
    Ok(())
}
