# envault Claude Code Plugin (Milestone 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the Claude Code plugin: a skill that teaches agents the aliases-only workflow, plus PreToolUse guardrails backed by a new `envault guard-check` subcommand.

**Architecture:** The guard logic lives in the Rust binary (testable, single source of truth); the plugin's hook script pipes Claude Code's PreToolUse JSON into `envault guard-check`, which exits 2 (block, reason on stderr) or 0 (allow). The plugin directory (`plugin/`) holds `.claude-plugin/plugin.json`, the skill, and the hook config; a repo-root `.claude-plugin/marketplace.json` makes the repo installable as a marketplace.

**Tech Stack:** Rust (existing crate), Claude Code plugin format (plugin.json, SKILL.md, hooks.json, `${CLAUDE_PLUGIN_ROOT}`), `claude plugin validate` as the verification gate.

**Spec:** `docs/superpowers/specs/2026-08-26-envault-design.md` §8 (and §6's `guard-check` row)

## Global Constraints

- Guard blocks agent access to the vault dir and the human-only TUI; it must NEVER block normal `envault ls/link/run/import/add/init` usage — smoothness is the product.
- Hook must fail open if the `envault` binary is missing (exit 0), so a half-installed plugin can't brick a session.
- Exit codes: 0 = allow, 2 = block with the reason on stderr (Claude Code's PreToolUse contract).
- All Milestone 1 constraints still apply (fmt, clippy -D warnings, TDD).

---

### Task 1: `envault guard-check` subcommand

**Files:**
- Create: `src/commands/guard.rs`
- Modify: `src/commands/mod.rs`, `src/main.rs`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `paths::envault_home()`
- Produces:
  - `commands::guard::guard_decision(tool_name: &str, tool_input: &serde_json::Value, home: &str) -> Option<String>` — `Some(reason)` = block
  - `commands::guard::cmd_guard_check() -> Result<i32>` — reads `{"tool_name": ..., "tool_input": {...}}` JSON from stdin, prints reason to stderr, returns 2 to block / 0 to allow
  - CLI: `envault guard-check` (reads stdin; exit code is the verdict). `main` dispatches it like `run` (exits with the returned code).

**Blocking rules (exact):**
1. Any tool: if any string value anywhere in `tool_input` contains `~/.envault`, `$HOME/.envault`, or the absolute `envault_home()` path → block (vault dir is agent-off-limits; defense in depth).
2. `Bash` only: split `command` on `;`, `&`, `|`, and newlines; if any trimmed segment equals `envault` → block (bare TUI is human-only). `envault ls --json`, `envault run -- ...` etc. stay allowed.
3. Everything else → allow. Unparseable stdin → allow (fail open) but print a warning to stderr.

- [ ] **Step 1: Write failing unit tests** in `src/commands/guard.rs` (test module below the future implementation):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOME: &str = "/Users/tester/.envault";

    #[test]
    fn blocks_reads_of_vault_dir() {
        for tool in ["Read", "Edit", "Write", "Glob", "Grep"] {
            let input = json!({"file_path": "/Users/tester/.envault/vault.json"});
            assert!(guard_decision(tool, &input, HOME).is_some(), "{tool} should block");
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
            assert!(guard_decision("Bash", &input, HOME).is_none(), "{cmd} should be allowed");
        }
        let read = json!({"file_path": "/Users/tester/project/src/main.rs"});
        assert!(guard_decision("Read", &read, HOME).is_none());
    }

    #[test]
    fn nested_strings_are_scanned() {
        let input = json!({"edits": [{"old_string": "x", "new_string": "see ~/.envault/recipient.txt"}]});
        assert!(guard_decision("Edit", &input, HOME).is_some());
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test guard` → compile errors (functions missing).

- [ ] **Step 3: Implement** above the tests in `src/commands/guard.rs`:

```rust
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
            return Some(format!(
                "envault guard: the vault directory is off-limits to agents \
                 (it holds only ciphers, but defense in depth). \
                 Use `envault ls --json` to list secret names instead."
            ));
        }
    }

    if tool_name == "Bash" {
        if let Some(cmd) = tool_input.get("command").and_then(|c| c.as_str()) {
            let bare_tui = cmd
                .split(['；', ';', '&', '|', '\n'])
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
    let tool_name = parsed.get("tool_name").and_then(|t| t.as_str()).unwrap_or("");
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
```

Wire `pub mod guard;` into `src/commands/mod.rs`; in `src/main.rs` add a hidden subcommand and exit-with-code dispatch:

```rust
    /// Internal: PreToolUse hook helper (reads hook JSON on stdin)
    #[command(hide = true)]
    GuardCheck,
```

```rust
        Some(Cmd::GuardCheck) => match commands::guard::cmd_guard_check() {
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
```

- [ ] **Step 4: Add integration tests** to `tests/cli.rs` (stdin → exit code):

```rust
#[test]
fn guard_check_blocks_vault_reads_and_allows_normal() {
    let te = TestEnv::new();
    te.envault()
        .arg("guard-check")
        .write_stdin(format!(
            "{{\"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":\"{}/vault.json\"}}}}",
            te.home.path().display()
        ))
        .assert()
        .code(2)
        .stderr(predicates::str::contains("off-limits"));

    te.envault()
        .arg("guard-check")
        .write_stdin("{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"envault ls --json\"}}")
        .assert()
        .code(0);

    te.envault()
        .arg("guard-check")
        .write_stdin("not json at all")
        .assert()
        .code(0); // fail open
}
```

- [ ] **Step 5: Verify green** — `cargo test` all pass.
- [ ] **Step 6: Commit** — `feat: guard-check subcommand for PreToolUse hook`

---

### Task 2: Plugin directory + marketplace manifest

**Files:**
- Create: `plugin/.claude-plugin/plugin.json`
- Create: `plugin/skills/envault/SKILL.md`
- Create: `plugin/hooks/hooks.json`
- Create: `plugin/hooks/guard.sh` (mode 755)
- Create: `.claude-plugin/marketplace.json` (repo root)

**Interfaces:**
- Consumes: `envault guard-check` (Task 1)
- Produces: an installable plugin named `envault`; validation via `claude plugin validate`.

- [ ] **Step 1: Write `plugin/.claude-plugin/plugin.json`:**

```json
{
  "name": "envault",
  "description": "Secrets vault workflow for agents: aliases and ciphers only, never plaintext. Pairs with the envault CLI.",
  "version": "0.1.0",
  "author": { "name": "purifido" }
}
```

- [ ] **Step 2: Write `plugin/skills/envault/SKILL.md`** — frontmatter `name` + `description` (description must carry the trigger conditions), body = the workflow rules from spec §8:

```markdown
---
name: envault
description: Use when a project needs an API key, token, password, or other secret — before asking the user for a value, before writing any .env file, and whenever a command needs credentials injected (e.g. OPENROUTER_API_KEY). Also use when a plaintext .env file is spotted in the repo. Teaches the envault aliases-only workflow: agents handle names and ciphers, never plaintext secrets.
---

# envault: secrets without plaintext

envault is a local vault. You (the agent) work only with **aliases** (names)
and **ciphers** (encrypted blobs). Plaintext values exist solely inside
processes launched by `envault run`. Follow these rules exactly.

## Never do
- Never ask the user to paste a secret value into the chat.
- Never write a plaintext secret into any file (.env, config, code, docs).
- Never try to read `~/.envault/` or open the bare `envault` TUI — both are
  human-only and blocked by hooks.
- Never try to unmask `[envault:<alias>]` text in command output. That marker
  means injection WORKED; it is not an error.

## Workflow
1. **Discover** what exists: `envault ls --json` (names and labels only).
2. **Wire the project**: `envault link ENV_VAR alias` writes the mapping into
   `envault.toml` (safe to read, edit, and commit — names only). Code then
   reads ordinary environment variables (e.g. `process.env.OPENROUTER_API_KEY`).
3. **Run things through the wrapper**: `envault run -- <command>` for anything
   that needs the secrets (dev servers, tests, scripts). Output is masked:
   injected values print as `[envault:<alias>]`.
4. **Missing secret?** If the alias you need is not in `envault ls`, STOP and
   ask the user to add it: they run `envault add <alias>` (hidden prompt) or
   the `envault` dashboard in their own terminal. Wait for their go-ahead,
   then re-check `envault ls --json` and continue.
5. **Plaintext .env in the repo?** Offer to run `envault import .env` (it
   encrypts every entry into the vault and links the manifest), then suggest
   the user delete the file.
6. **envault not installed?** (`command -v envault` fails) Ask the user to
   install it (from this repo: `cargo install --path .`), then `envault init`.

## Command cheat sheet (all agent-safe)
| Need | Command |
|---|---|
| List secret names | `envault ls --json` |
| Map env var to alias | `envault link OPENROUTER_API_KEY openrouter` |
| Run with secrets | `envault run -- npm start` |
| Extra one-off mapping | `envault run --env VAR=alias -- <cmd>` |
| Encrypt an existing .env | `envault import .env` |
```

- [ ] **Step 3: Write `plugin/hooks/hooks.json` and `plugin/hooks/guard.sh`:**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|Glob|Grep",
        "hooks": [
          {
            "type": "command",
            "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/guard.sh\""
          }
        ]
      }
    ]
  }
}
```

```bash
#!/bin/bash
# envault PreToolUse guard: pipes hook JSON to `envault guard-check`.
# Fail open if envault isn't installed — a half-installed plugin must not
# block the session.
command -v envault >/dev/null 2>&1 || exit 0
exec envault guard-check
```

`chmod 755 plugin/hooks/guard.sh`

- [ ] **Step 4: Write repo-root `.claude-plugin/marketplace.json`:**

```json
{
  "name": "envault",
  "owner": { "name": "purifido" },
  "plugins": [
    {
      "name": "envault",
      "source": "./plugin",
      "description": "Secrets vault workflow for agents: aliases and ciphers only, never plaintext."
    }
  ]
}
```

- [ ] **Step 5: Validate** — run `claude plugin validate plugin` and `claude plugin validate .`; both must report success. Fix any schema complaints (the validator's messages are authoritative over this plan).
- [ ] **Step 6: Manual hook rehearsal** — pipe a Read-vault event through guard.sh exactly as Claude Code would:
  `echo '{"tool_name":"Read","tool_input":{"file_path":"~/.envault/vault.json"}}' | PATH="$PWD/target/debug:$PATH" plugin/hooks/guard.sh; echo "exit=$?"` → expect the off-limits message and `exit=2`.
- [ ] **Step 7: Commit** — `feat: Claude Code plugin — skill, guard hooks, marketplace manifest`

---

### Task 3: README install section

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Append an "Agent integration (Claude Code plugin)" section** to README.md covering: `claude plugin marketplace add <path-or-repo>`, `claude plugin install envault@envault`, what the skill does, what the hooks block, and the fail-open behavior.
- [ ] **Step 2: Full gate** — `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test` all green.
- [ ] **Step 3: Commit** — `docs: plugin install instructions`
