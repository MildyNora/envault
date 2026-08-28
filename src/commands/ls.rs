use anyhow::Result;
use serde::Serialize;

use crate::paths;
use crate::store::Vault;

#[derive(Serialize)]
struct LsRow<'a> {
    alias: &'a str,
    label: &'a str,
    created_at: &'a str,
}

pub fn cmd_ls(json: bool) -> Result<()> {
    let vault = Vault::load(&paths::envault_home())?;
    let rows: Vec<LsRow> = vault
        .secrets
        .iter()
        .map(|s| LsRow {
            alias: &s.alias,
            label: &s.label,
            created_at: &s.created_at,
        })
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else if rows.is_empty() {
        println!("vault is empty — add one with `envault add <alias>`");
    } else {
        println!("{:<24} {:<32} CREATED", "ALIAS", "LABEL");
        for r in rows {
            println!("{:<24} {:<32} {}", r.alias, r.label, r.created_at);
        }
    }
    Ok(())
}
