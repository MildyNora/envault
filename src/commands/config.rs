use anyhow::{bail, Result};

use crate::biometric;
use crate::paths;
use crate::settings::Settings;

/// `envault config` — show settings. Reading is unguarded (no secrets here).
pub fn cmd_config_show() -> Result<()> {
    let s = Settings::load(&paths::envault_home());
    println!("audit-log : {}", on_off(s.audit_log));
    println!("touch-id  : {}", on_off(s.touch_id));
    Ok(())
}

/// `envault config set <key> <on|off>` — changing a setting is gated, so an
/// agent can't silently disable the audit log or the Touch ID requirement.
pub fn cmd_config_set(key: String, value: String) -> Result<()> {
    let home = paths::envault_home();
    let on = match value.to_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => true,
        "off" | "false" | "no" | "0" => false,
        other => bail!("value must be on/off, got '{other}'"),
    };

    biometric::require(&format!("Change envault setting '{key}'"))?;

    let mut s = Settings::load(&home);
    match key.as_str() {
        "audit-log" | "audit_log" | "audit" => s.audit_log = on,
        "touch-id" | "touch_id" | "touchid" => s.touch_id = on,
        other => bail!("unknown setting '{other}' (try audit-log or touch-id)"),
    }
    s.save(&home)?;
    println!("set {key} = {}", on_off(on));
    Ok(())
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}
