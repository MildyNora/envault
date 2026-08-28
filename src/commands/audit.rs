use anyhow::Result;

use crate::audit;
use crate::biometric;
use crate::paths;

/// Human-only: view the audit log. Always gated behind a system prompt so an
/// agent can't silently read who accessed what.
pub fn cmd_audit(json: bool) -> Result<()> {
    let home = paths::envault_home();
    biometric::require("View the envault audit log")?;

    let entries = audit::read(&home)?;
    if entries.is_empty() {
        println!("audit log is empty (enable it with `envault config set audit-log on`)");
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        println!("{:<26} {:<8} DETAIL", "WHEN", "ACTION");
        for e in &entries {
            println!("{:<26} {:<8} {}", e.ts, e.action, e.detail);
        }
    }
    match audit::first_tamper(&entries) {
        None => println!("\n✔ chain intact ({} entries)", entries.len()),
        Some(i) => {
            println!("\n✖ TAMPERING DETECTED at entry {i} — the log was edited or truncated")
        }
    }
    Ok(())
}
