use anyhow::Result;
use std::io::Read;

use crate::paths;

fn collect_strings<'a>(v: &'a serde_json::Value, out: &mut Vec<&'a str>) {
    match v {
        serde_json::Value::String(s) => out.push(s),
        serde_json::Value::Array(a) => a.iter().for_each(|v| collect_strings(v, out)),
        serde_json::Value::Object(o) => o.values().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}

pub fn guard_decision(
    tool_name: &str,
    tool_input: &serde_json::Value,
    home: &str,
) -> Option<String> {
    let mut strings = Vec::new();
    collect_strings(tool_input, &mut strings);

    let vault_markers = ["~/.envault", "$HOME/.envault"];
    for s in &strings {
        if s.contains(home) || vault_markers.iter().any(|m| s.contains(m)) {
            return Some(
                "envault guard: the vault directory is off-limits to agents \
                 (it holds only ciphers, but defense in depth). \
                 Use `envault ls --json` to list secret names instead."
                    .to_string(),
            );
        }
    }

    if tool_name == "Bash" {
        if let Some(cmd) = tool_input.get("command").and_then(|c| c.as_str()) {
            let bare_tui = cmd
                .split([';', '&', '|', '\n'])
                .any(|seg| seg.trim() == "envault");
            if bare_tui {
                return Some(
                    "envault guard: the envault TUI dashboard is human-only. \
                     Ask the user to run `envault` in their own terminal instead."
                        .to_string(),
                );
            }
        }
    }
    None
}

pub fn cmd_guard_check() -> Result<i32> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("envault guard: unparseable hook input ({e}); allowing");
            return Ok(0);
        }
    };
    let tool_name = parsed
        .get("tool_name")
        .and_then(|t| t.as_str())
        .unwrap_or("");
    let empty = serde_json::Value::Object(Default::default());
    let tool_input = parsed.get("tool_input").unwrap_or(&empty);
    let home = paths::envault_home();
    match guard_decision(tool_name, tool_input, &home.to_string_lossy()) {
        Some(reason) => {
            eprintln!("{reason}");
            Ok(2)
        }
        None => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOME: &str = "/Users/tester/.envault";

    #[test]
    fn blocks_reads_of_vault_dir() {
        for tool in ["Read", "Edit", "Write", "Glob", "Grep"] {
            let input = json!({"file_path": "/Users/tester/.envault/vault.json"});
            assert!(
                guard_decision(tool, &input, HOME).is_some(),
                "{tool} should block"
            );
        }
        let tilde = json!({"file_path": "~/.envault/vault.json"});
        assert!(guard_decision("Read", &tilde, HOME).is_some());
    }

    #[test]
    fn blocks_bash_touching_vault_dir_or_bare_tui() {
        let cat = json!({"command": "cat ~/.envault/vault.json"});
        assert!(guard_decision("Bash", &cat, HOME).is_some());
        let bare = json!({"command": "envault"});
        assert!(guard_decision("Bash", &bare, HOME).is_some());
        let chained = json!({"command": "cd /tmp && envault"});
        assert!(guard_decision("Bash", &chained, HOME).is_some());
    }

    #[test]
    fn allows_normal_envault_usage_and_other_tools() {
        for cmd in [
            "envault ls --json",
            "envault run -- npm test",
            "envault link OPENROUTER_API_KEY openrouter",
            "envault import .env",
            "ls -la",
        ] {
            let input = json!({"command": cmd});
            assert!(
                guard_decision("Bash", &input, HOME).is_none(),
                "{cmd} should be allowed"
            );
        }
        let read = json!({"file_path": "/Users/tester/project/src/main.rs"});
        assert!(guard_decision("Read", &read, HOME).is_none());
    }

    #[test]
    fn nested_strings_are_scanned() {
        let input =
            json!({"edits": [{"old_string": "x", "new_string": "see ~/.envault/recipient.txt"}]});
        assert!(guard_decision("Edit", &input, HOME).is_some());
    }
}
