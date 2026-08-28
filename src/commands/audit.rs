use age::secrecy::ExposeSecret;
use anyhow::Result;

use crate::audit::{self, Integrity};
use crate::biometric;
use crate::crypto;
use crate::paths;

/// Human-only: view the audit log. Always gated behind a system prompt so an
/// agent can't silently read who accessed what.
pub fn cmd_audit(json: bool) -> Result<()> {
    let home = paths::envault_home();
    biometric::require("View the envault audit log")?;

    // Loading the identity both proves human presence again and gives the HMAC
    // key needed to verify the chain.
    let identity = crypto::load_identity()?;
    let secret = identity.to_string();
    let key = secret.expose_secret().as_bytes();

    let entries = audit::read(&home)?;
    if entries.is_empty() && matches!(audit::verify(&home, key, &entries), Integrity::Ok) {
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
    match audit::verify(&home, key, &entries) {
        Integrity::Ok => println!("\n✔ chain intact and anchored ({} entries)", entries.len()),
        Integrity::Broken(i) => {
            println!("\n✖ TAMPERING: entry {i} was edited or an entry before it was removed")
        }
        Integrity::HeadMismatch => {
            println!("\n✖ TAMPERING: the log was truncated or deleted (head anchor mismatch)")
        }
    }
    Ok(())
}
