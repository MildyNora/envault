# envault Core (Milestone 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `envault` Rust binary's core: encrypted vault, Keychain-held identity, and the `run` wrapper that injects secrets into child processes while masking them out of all output.

**Architecture:** One Rust binary. Secrets are individually encrypted to an age X25519 public key and stored with plaintext metadata in `~/.envault/vault.json`; the private key lives in the macOS Keychain (file override for tests). `envault run` resolves a repo-local `envault.toml` manifest (ENV_VAR → alias), decrypts, spawns the command in a PTY, and streams its output through a masking engine. No CLI path ever prints a decrypted value.

**Tech Stack:** Rust (stable ≥1.75, edition 2021), clap 4 (derive), age 0.11, keyring 3, portable-pty 0.8, crossterm 0.28, serde/serde_json/toml, base64 0.22, urlencoding 2, dotenvy 0.15, rpassword 7, chrono 0.4, anyhow 1. Dev: assert_cmd 2, predicates 3, tempfile 3.

**Spec:** `docs/superpowers/specs/2026-08-26-envault-design.md` (this plan implements §4–§7, §11–§12 and the Milestone-1 row of §13; `guard-check`, TUI, and `fill` belong to later plans)

## Global Constraints

- Target platform: macOS (Unix-only code like file modes is fine).
- **Never add a code path that prints a decrypted value** (spec §6). `run` injects+masks; `ls` emits names only.
- Masking skips values shorter than 6 characters (spec §7).
- Aliases must match `^[a-z0-9][a-z0-9-]*$` (kebab-case, spec §5).
- Cipher storage format: base64 (STANDARD alphabet) of the binary age ciphertext.
- Vault dir mode `0o700`, `vault.json` mode `0o600`.
- Keychain item: service `envault`, account `age-identity`. Env override `ENVAULT_IDENTITY_FILE` (tests/CI). Vault root override: `ENVAULT_HOME`.
- Keep `run`'s startup light — no work before arg parsing besides what clap needs (spec §7 latency budget ~50 ms).
- TDD for every task; conventional commit messages (`feat:`, `test:`, `chore:`).
- All commands are run from the repo root.

---

### Task 1: Cargo scaffold + CLI skeleton

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `.gitignore`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `Cli`/`Cmd` clap types in `src/main.rs` that later tasks extend with subcommands; a compiling binary named `envault`.

- [ ] **Step 1: Write the failing test**

Create `tests/cli.rs`:

```rust
use assert_cmd::Command;

#[test]
fn version_flag_works() {
    Command::cargo_bin("envault")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("envault"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli 2>&1 | tail -5`
Expected: FAIL — the project doesn't exist yet / no binary `envault`.

- [ ] **Step 3: Write minimal implementation**

Create `Cargo.toml`:

```toml
[package]
name = "envault"
version = "0.1.0"
edition = "2021"
description = "Local secrets vault for agentic coding: agents see aliases and ciphers, never plaintext"
license = "MIT"

[dependencies]
age = { version = "0.11", features = ["armor"] }
anyhow = "1"
base64 = "0.22"
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4", features = ["derive"] }
crossterm = "0.28"
dirs = "5"
dotenvy = "0.15"
keyring = { version = "3", features = ["apple-native"] }
portable-pty = "0.8"
rpassword = "7"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
urlencoding = "2"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

Create `.gitignore`:

```
/target
```

Create `src/main.rs` (no subcommands yet — Task 5 replaces this with the real `Cmd` enum and dispatch; an empty `#[derive(Subcommand)]` enum is not worth the derive-macro risk):

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "envault", version, about = "Local secrets vault: agents see aliases and ciphers, never plaintext")]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    // Bare `envault` opens the TUI in Milestone 3; until then, --help/--version only.
    use clap::CommandFactory;
    Cli::command().print_help().ok();
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test cli`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore src/main.rs tests/cli.rs
git commit -m "feat: scaffold envault binary with clap skeleton"
```

---

### Task 2: Paths + vault store

**Files:**
- Create: `src/paths.rs`
- Create: `src/store.rs`
- Modify: `src/main.rs` (add `mod paths; mod store;`)

**Interfaces:**
- Consumes: nothing
- Produces:
  - `paths::envault_home() -> PathBuf` (honors `ENVAULT_HOME`, else `~/.envault`)
  - `paths::vault_file(home: &Path) -> PathBuf`, `paths::recipient_file(home: &Path) -> PathBuf`
  - `store::SecretEntry { alias, label, cipher, url: Option<String>, created_at, updated_at, notes }` (all `String` unless noted, serde Serialize/Deserialize)
  - `store::Vault { secrets: Vec<SecretEntry> }` with `Vault::load(home: &Path) -> Result<Vault>`, `save(&self, home: &Path) -> Result<()>`, `get(&self, alias: &str) -> Option<&SecretEntry>`, `insert(&mut self, e: SecretEntry) -> Result<()>` (errors on duplicate alias)
  - `store::now_rfc3339() -> String`
  - `store::is_valid_alias(s: &str) -> bool` (`^[a-z0-9][a-z0-9-]*$`)

- [ ] **Step 1: Write the failing tests**

Create `src/store.rs` with tests only for now (module body comes in Step 3). Put this test module at the bottom of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn entry(alias: &str) -> SecretEntry {
        SecretEntry {
            alias: alias.into(),
            label: format!("{alias} label"),
            cipher: "Y2lwaGVy".into(),
            url: None,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            notes: String::new(),
        }
    }

    #[test]
    fn save_load_roundtrip() {
        let home = TempDir::new().unwrap();
        let mut v = Vault::default();
        v.insert(entry("openrouter")).unwrap();
        v.save(home.path()).unwrap();
        let loaded = Vault::load(home.path()).unwrap();
        assert_eq!(loaded.secrets.len(), 1);
        assert_eq!(loaded.get("openrouter").unwrap().label, "openrouter label");
    }

    #[test]
    fn load_without_vault_mentions_init() {
        let home = TempDir::new().unwrap();
        let err = Vault::load(home.path()).unwrap_err().to_string();
        assert!(err.contains("envault init"), "got: {err}");
    }

    #[test]
    fn duplicate_alias_rejected() {
        let mut v = Vault::default();
        v.insert(entry("a-key")).unwrap();
        let err = v.insert(entry("a-key")).unwrap_err().to_string();
        assert!(err.contains("already exists"), "got: {err}");
    }

    #[test]
    fn vault_json_is_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().unwrap();
        Vault::default().save(home.path()).unwrap();
        let mode = std::fs::metadata(crate::paths::vault_file(home.path()))
            .unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn alias_validation() {
        assert!(is_valid_alias("openrouter"));
        assert!(is_valid_alias("my-key-2"));
        assert!(!is_valid_alias("My-Key"));
        assert!(!is_valid_alias("-lead"));
        assert!(!is_valid_alias(""));
        assert!(!is_valid_alias("has_underscore"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test store 2>&1 | tail -5`
Expected: FAIL to compile — types not defined yet.

- [ ] **Step 3: Write minimal implementation**

Create `src/paths.rs`:

```rust
use std::path::{Path, PathBuf};

pub fn envault_home() -> PathBuf {
    if let Ok(h) = std::env::var("ENVAULT_HOME") {
        return PathBuf::from(h);
    }
    dirs::home_dir().expect("no home directory").join(".envault")
}

pub fn vault_file(home: &Path) -> PathBuf {
    home.join("vault.json")
}

pub fn recipient_file(home: &Path) -> PathBuf {
    home.join("recipient.txt")
}
```

At the top of `src/store.rs` (above the test module from Step 1):

```rust
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::paths::vault_file;

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretEntry {
    pub alias: String,
    pub label: String,
    pub cipher: String, // base64 of binary age ciphertext
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
    pub created_at: String, // RFC3339
    pub updated_at: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    pub secrets: Vec<SecretEntry>,
}

impl Vault {
    pub fn load(home: &Path) -> Result<Vault> {
        let path = vault_file(home);
        if !path.exists() {
            bail!("no vault found at {} — run `envault init` first", path.display());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(home)?;
        let path = vault_file(home);
        fs::write(&path, serde_json::to_string_pretty(self)?)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    pub fn get(&self, alias: &str) -> Option<&SecretEntry> {
        self.secrets.iter().find(|s| s.alias == alias)
    }

    pub fn insert(&mut self, e: SecretEntry) -> Result<()> {
        if self.get(&e.alias).is_some() {
            bail!("alias '{}' already exists", e.alias);
        }
        self.secrets.push(e);
        self.secrets.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(())
    }
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn is_valid_alias(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
```

In `src/main.rs`, after the `use` lines add:

```rust
mod paths;
mod store;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test store`
Expected: PASS (5 tests). Warnings about unused items are fine at this stage.

- [ ] **Step 5: Commit**

```bash
git add src/paths.rs src/store.rs src/main.rs
git commit -m "feat: vault store with 0600 perms, alias validation, ENVAULT_HOME paths"
```

---

### Task 3: Crypto — age encrypt/decrypt

**Files:**
- Create: `src/crypto.rs`
- Modify: `src/main.rs` (add `mod crypto;`)

**Interfaces:**
- Consumes: nothing
- Produces:
  - `crypto::generate_identity() -> age::x25519::Identity`
  - `crypto::encrypt_value(recipient: &age::x25519::Recipient, plaintext: &str) -> Result<String>` — returns base64 ciphertext
  - `crypto::decrypt_value(identity: &age::x25519::Identity, cipher_b64: &str) -> Result<String>`

- [ ] **Step 1: Write the failing tests**

Create `src/crypto.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let id = generate_identity();
        let cipher = encrypt_value(&id.to_public(), "sk-or-v1-secret").unwrap();
        assert_ne!(cipher, "sk-or-v1-secret");
        assert!(!cipher.contains("secret"));
        let plain = decrypt_value(&id, &cipher).unwrap();
        assert_eq!(plain, "sk-or-v1-secret");
    }

    #[test]
    fn wrong_identity_fails() {
        let id = generate_identity();
        let other = generate_identity();
        let cipher = encrypt_value(&id.to_public(), "value-123").unwrap();
        assert!(decrypt_value(&other, &cipher).is_err());
    }

    #[test]
    fn garbage_cipher_fails() {
        let id = generate_identity();
        assert!(decrypt_value(&id, "not base64 !!!").is_err());
        assert!(decrypt_value(&id, "aGVsbG8=").is_err()); // valid b64, not age data
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test crypto 2>&1 | tail -5`
Expected: FAIL to compile — functions not defined. (Remember to add `mod crypto;` to `src/main.rs` first, or the test module won't even be discovered.)

- [ ] **Step 3: Write minimal implementation**

Add above the test module in `src/crypto.rs`:

```rust
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

pub fn generate_identity() -> age::x25519::Identity {
    age::x25519::Identity::generate()
}

pub fn encrypt_value(recipient: &age::x25519::Recipient, plaintext: &str) -> Result<String> {
    let bytes = age::encrypt(recipient, plaintext.as_bytes()).context("age encryption failed")?;
    Ok(B64.encode(bytes))
}

pub fn decrypt_value(identity: &age::x25519::Identity, cipher_b64: &str) -> Result<String> {
    let bytes = B64.decode(cipher_b64.trim()).context("cipher is not valid base64")?;
    let plain = age::decrypt(identity, &bytes).context("decryption failed (wrong key or corrupt cipher)")?;
    String::from_utf8(plain).context("decrypted value is not UTF-8")
}
```

And `mod crypto;` in `src/main.rs`.

Note: `age::encrypt` / `age::decrypt` are the top-level convenience functions in the age 0.11 crate. If the resolved version exposes them under different arity, check `cargo doc --open -p age` — the Encryptor/Decryptor streaming API is the lower-level equivalent, but the convenience functions are the intended path here.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test crypto`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/crypto.rs src/main.rs
git commit -m "feat: age X25519 encrypt/decrypt with base64 cipher format"
```

---

### Task 4: Identity source — Keychain with file override

**Files:**
- Modify: `src/crypto.rs`

**Interfaces:**
- Consumes: `paths::recipient_file`, Task 3 functions
- Produces:
  - `crypto::store_identity(identity: &age::x25519::Identity, home: &Path) -> Result<()>` — writes to `$ENVAULT_IDENTITY_FILE` if set (mode 0600), else macOS Keychain (`envault` / `age-identity`)
  - `crypto::load_identity() -> Result<age::x25519::Identity>` — same resolution order
  - `crypto::load_recipient(home: &Path) -> Result<age::x25519::Recipient>` — parses `recipient.txt`
  - `crypto::store_recipient(identity: &age::x25519::Identity, home: &Path) -> Result<()>`

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `src/crypto.rs`:

```rust
    #[test]
    fn identity_file_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let id_path = dir.path().join("identity.txt");
        // Serialize env-var access: cargo runs tests in threads sharing the process env.
        std::env::set_var("ENVAULT_IDENTITY_FILE", &id_path);
        let id = generate_identity();
        store_identity(&id, dir.path()).unwrap();
        store_recipient(&id, dir.path()).unwrap();
        let loaded = load_identity().unwrap();
        std::env::remove_var("ENVAULT_IDENTITY_FILE");

        let cipher = encrypt_value(&load_recipient(dir.path()).unwrap(), "roundtrip").unwrap();
        assert_eq!(decrypt_value(&loaded, &cipher).unwrap(), "roundtrip");

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&id_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn missing_recipient_mentions_init() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = load_recipient(dir.path()).unwrap_err().to_string();
        assert!(err.contains("envault init"), "got: {err}");
    }
```

Note: `identity_file_roundtrip` mutates process env; if you later see cross-test flakiness, mark it `#[serial]` via the `serial_test` crate — for this suite it is the only env-mutating unit test, so it is fine as-is.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test crypto 2>&1 | tail -5`
Expected: FAIL to compile — new functions not defined.

- [ ] **Step 3: Write minimal implementation**

Add to `src/crypto.rs`:

```rust
use age::secrecy::ExposeSecret;
use std::fs;
use std::path::Path;
use std::str::FromStr;

const KEYCHAIN_SERVICE: &str = "envault";
const KEYCHAIN_ACCOUNT: &str = "age-identity";

fn identity_file_override() -> Option<std::path::PathBuf> {
    std::env::var("ENVAULT_IDENTITY_FILE").ok().map(Into::into)
}

pub fn store_identity(identity: &age::x25519::Identity, _home: &Path) -> Result<()> {
    let key = identity.to_string(); // SecretString
    if let Some(path) = identity_file_override() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, format!("{}\n", key.expose_secret()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .context("opening Keychain entry")?;
    entry
        .set_password(key.expose_secret())
        .context("storing identity in the macOS Keychain")
}

pub fn load_identity() -> Result<age::x25519::Identity> {
    let raw = if let Some(path) = identity_file_override() {
        fs::read_to_string(&path)
            .with_context(|| format!("reading identity file {}", path.display()))?
    } else {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
            .context("opening Keychain entry")?;
        entry.get_password().context(
            "no envault identity in the Keychain — run `envault init` (or grant Keychain access)",
        )?
    };
    age::x25519::Identity::from_str(raw.trim())
        .map_err(|e| anyhow::anyhow!("invalid age identity: {e}"))
}

pub fn store_recipient(identity: &age::x25519::Identity, home: &Path) -> Result<()> {
    fs::create_dir_all(home)?;
    fs::write(
        crate::paths::recipient_file(home),
        format!("{}\n", identity.to_public()),
    )?;
    Ok(())
}

pub fn load_recipient(home: &Path) -> Result<age::x25519::Recipient> {
    let path = crate::paths::recipient_file(home);
    if !path.exists() {
        anyhow::bail!("no recipient at {} — run `envault init` first", path.display());
    }
    let raw = fs::read_to_string(&path)?;
    age::x25519::Recipient::from_str(raw.trim())
        .map_err(|e| anyhow::anyhow!("invalid recipient: {e}"))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test crypto`
Expected: PASS (5 tests). The Keychain branch is exercised manually in Task 5 — unit tests always use the file override so CI never touches the real Keychain.

- [ ] **Step 5: Commit**

```bash
git add src/crypto.rs
git commit -m "feat: identity storage in Keychain with ENVAULT_IDENTITY_FILE override"
```

---

### Task 5: `envault init`

**Files:**
- Create: `src/commands/mod.rs`
- Create: `src/commands/init.rs`
- Modify: `src/main.rs`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `crypto::{generate_identity, store_identity, store_recipient}`, `store::Vault`, `paths::*`
- Produces: `commands::init::cmd_init() -> Result<()>`; `Cmd::Init` variant. Also the shared integration-test helper `TestEnv` in `tests/cli.rs` that every later task's integration tests use.

- [ ] **Step 1: Write the failing test**

Replace the contents of `tests/cli.rs` with:

```rust
use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn version_flag_works() {
    Command::cargo_bin("envault")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("envault"));
}

/// Isolated envault home + project dir. Every Command gets ENVAULT_HOME and
/// ENVAULT_IDENTITY_FILE pointed inside a tempdir, so tests never touch the
/// real vault or the macOS Keychain, and are parallel-safe (env is set
/// per-child-process, not on the test process).
pub struct TestEnv {
    pub home: TempDir,
    pub project: TempDir,
}

impl TestEnv {
    pub fn new() -> TestEnv {
        TestEnv { home: TempDir::new().unwrap(), project: TempDir::new().unwrap() }
    }

    pub fn identity_file(&self) -> PathBuf {
        self.home.path().join("test-identity.txt")
    }

    pub fn envault(&self) -> Command {
        let mut c = Command::cargo_bin("envault").unwrap();
        c.env("ENVAULT_HOME", self.home.path())
            .env("ENVAULT_IDENTITY_FILE", self.identity_file())
            .current_dir(self.project.path());
        c
    }

    pub fn init(&self) {
        self.envault().arg("init").assert().success();
    }
}

#[test]
fn init_creates_vault_recipient_and_identity() {
    let te = TestEnv::new();
    te.envault()
        .arg("init")
        .assert()
        .success()
        .stdout(predicates::str::contains("Initialized"));
    assert!(te.home.path().join("vault.json").exists());
    assert!(te.home.path().join("recipient.txt").exists());
    assert!(te.identity_file().exists());
}

#[test]
fn init_twice_fails() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .arg("init")
        .assert()
        .failure()
        .stderr(predicates::str::contains("already initialized"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli 2>&1 | tail -5`
Expected: FAIL — `init` is not a recognized subcommand.

- [ ] **Step 3: Write minimal implementation**

Create `src/commands/mod.rs`:

```rust
pub mod init;
```

Create `src/commands/init.rs`:

```rust
use anyhow::{bail, Result};
use std::fs;

use crate::crypto;
use crate::paths;
use crate::store::Vault;

pub fn cmd_init() -> Result<()> {
    let home = paths::envault_home();
    if paths::vault_file(&home).exists() {
        bail!("already initialized at {}", home.display());
    }
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(&home)?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;

    let identity = crypto::generate_identity();
    crypto::store_identity(&identity, &home)?;
    crypto::store_recipient(&identity, &home)?;
    Vault::default().save(&home)?;

    println!("Initialized envault at {}", home.display());
    println!("  public key : {}", identity.to_public());
    println!("  private key: stored in the macOS Keychain (service 'envault')");
    println!("\nNext: add a secret with `envault add <alias>`");
    Ok(())
}
```

In `src/main.rs`: add `mod commands;`, add the variant and dispatch. The full updated dispatch (this exact shape is extended by every later task):

```rust
#[derive(Subcommand)]
enum Cmd {
    /// Create the vault and generate the keypair
    Init,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.cmd {
        None => {
            use clap::CommandFactory;
            Cli::command().print_help().ok();
            Ok(())
        }
        Some(Cmd::Init) => commands::init::cmd_init(),
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test cli`
Expected: PASS (3 tests).

- [ ] **Step 5: Manually verify the real Keychain branch (one-time)**

Run: `cargo run -- init` (with no `ENVAULT_IDENTITY_FILE` set), then `security find-generic-password -s envault -a age-identity >/dev/null && echo "keychain OK"`
Expected: `keychain OK`. (macOS may show a Keychain prompt — approve it. This leaves a real `~/.envault`; that's your actual vault going forward. If you want to redo it later: `rm -rf ~/.envault` and `security delete-generic-password -s envault -a age-identity`.)

- [ ] **Step 6: Commit**

```bash
git add src/commands src/main.rs tests/cli.rs
git commit -m "feat: envault init creates vault, keypair, and Keychain identity"
```

---

### Task 6: `envault add` + `envault ls`

**Files:**
- Create: `src/commands/add.rs`
- Create: `src/commands/ls.rs`
- Modify: `src/commands/mod.rs`, `src/main.rs`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `TestEnv` (Task 5), `crypto::{load_recipient, encrypt_value}`, `store::*`
- Produces:
  - `commands::add::cmd_add(alias: String, label: Option<String>, url: Option<String>, notes: Option<String>, stdin: bool) -> Result<()>`
  - `commands::ls::cmd_ls(json: bool) -> Result<()>` — JSON shape: `[{"alias": "...", "label": "...", "created_at": "..."}]`
  - CLI: `envault add <alias> [--label L] [--url U] [--notes N] [--stdin]`, `envault ls [--json]`

- [ ] **Step 1: Write the failing tests**

Append to `tests/cli.rs`:

```rust
#[test]
fn add_then_ls_shows_alias_but_never_value() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "openrouter", "--label", "OpenRouter key", "--stdin"])
        .write_stdin("sk-or-v1-abcdef123456\n")
        .assert()
        .success();

    // ls --json lists it
    let out = te.envault().args(["ls", "--json"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let rows: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(rows[0]["alias"], "openrouter");
    assert_eq!(rows[0]["label"], "OpenRouter key");
    assert!(rows[0].get("cipher").is_none(), "ls must not expose ciphers");

    // the plaintext value exists nowhere on disk
    let vault_raw = std::fs::read_to_string(te.home.path().join("vault.json")).unwrap();
    assert!(!vault_raw.contains("sk-or-v1-abcdef123456"));
    // and never in ls output
    assert!(!stdout.contains("sk-or-v1-abcdef123456"));
}

#[test]
fn add_rejects_bad_alias_and_duplicates() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "Bad_Alias", "--stdin"])
        .write_stdin("value-123456\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("kebab-case"));

    te.envault().args(["add", "dup", "--stdin"]).write_stdin("value-123456\n")
        .assert().success();
    te.envault().args(["add", "dup", "--stdin"]).write_stdin("value-123456\n")
        .assert().failure()
        .stderr(predicates::str::contains("already exists"));
}
```

Add `serde_json = "1"` under `[dev-dependencies]` in `Cargo.toml`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test cli 2>&1 | tail -5`
Expected: FAIL — `add` not a recognized subcommand.

- [ ] **Step 3: Write minimal implementation**

Create `src/commands/add.rs`:

```rust
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
        std::io::stdin().read_to_string(&mut buf).context("reading value from stdin")?;
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
```

Create `src/commands/ls.rs`:

```rust
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
        .map(|s| LsRow { alias: &s.alias, label: &s.label, created_at: &s.created_at })
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
```

In `src/commands/mod.rs` add `pub mod add; pub mod ls;`. In `src/main.rs` extend:

```rust
    /// Add a secret (value via hidden prompt, or --stdin)
    Add {
        alias: String,
        #[arg(long)] label: Option<String>,
        #[arg(long)] url: Option<String>,
        #[arg(long)] notes: Option<String>,
        /// Read the value from stdin (for piping); otherwise prompts on the TTY
        #[arg(long)] stdin: bool,
    },
    /// List secret names (never values)
    Ls {
        #[arg(long)] json: bool,
    },
```

and dispatch arms:

```rust
        Some(Cmd::Add { alias, label, url, notes, stdin }) => {
            commands::add::cmd_add(alias, label, url, notes, stdin)
        }
        Some(Cmd::Ls { json }) => commands::ls::cmd_ls(json),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test cli`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/commands tests/cli.rs src/main.rs
git commit -m "feat: add and ls commands — names out, values only ever in"
```

---

### Task 7: Masking engine

**Files:**
- Create: `src/masker.rs`
- Modify: `src/main.rs` (add `mod masker;`)

**Interfaces:**
- Consumes: nothing (pure module)
- Produces:
  - `masker::Masker::new(secrets: &[(String, String)]) -> Masker` — input pairs are `(alias, plaintext_value)`
  - `Masker::feed(&mut self, chunk: &[u8]) -> Vec<u8>` — streaming; may hold back bytes
  - `Masker::flush(&mut self) -> Vec<u8>` — emits held-back tail at EOF
  - Replacement text: `[envault:<alias>]`. Patterns per secret: raw value, base64(value), url-encoded value (when different). Values `< 6` chars are not masked (Global Constraints).

- [ ] **Step 1: Write the failing tests**

Create `src/masker.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn mask_all(m: &mut Masker, input: &[u8]) -> String {
        let mut out = m.feed(input);
        out.extend(m.flush());
        String::from_utf8(out).unwrap()
    }

    fn one(alias: &str, value: &str) -> Masker {
        Masker::new(&[(alias.to_string(), value.to_string())])
    }

    #[test]
    fn masks_exact_value() {
        let mut m = one("openrouter", "sk-or-v1-abc123");
        assert_eq!(
            mask_all(&mut m, b"key is sk-or-v1-abc123 ok"),
            "key is [envault:openrouter] ok"
        );
    }

    #[test]
    fn masks_across_chunk_boundary() {
        let mut m = one("openrouter", "sk-or-v1-abc123");
        let mut out = m.feed(b"key is sk-or-v1");
        out.extend(m.feed(b"-abc123 ok"));
        out.extend(m.flush());
        assert_eq!(String::from_utf8(out).unwrap(), "key is [envault:openrouter] ok");
    }

    #[test]
    fn masks_base64_form() {
        // echo -n 'sk-or-v1-abc123' | base64  ->  c2stb3ItdjEtYWJjMTIz
        let mut m = one("openrouter", "sk-or-v1-abc123");
        assert_eq!(
            mask_all(&mut m, b"b64: c2stb3ItdjEtYWJjMTIz."),
            "b64: [envault:openrouter]."
        );
    }

    #[test]
    fn masks_url_encoded_form() {
        let mut m = one("weird", "p@ss word+1");
        assert_eq!(
            mask_all(&mut m, b"q=p%40ss%20word%2B1&x=1"),
            "q=[envault:weird]&x=1"
        );
    }

    #[test]
    fn short_values_not_masked() {
        let mut m = one("pin", "1234");
        assert_eq!(mask_all(&mut m, b"pin is 1234"), "pin is 1234");
    }

    #[test]
    fn multiple_secrets_and_repeats() {
        let mut m = Masker::new(&[
            ("a-key".to_string(), "AAAAAA".to_string()),
            ("b-key".to_string(), "BBBBBB".to_string()),
        ]);
        assert_eq!(
            mask_all(&mut m, b"AAAAAA BBBBBB AAAAAA"),
            "[envault:a-key] [envault:b-key] [envault:a-key]"
        );
    }

    #[test]
    fn no_secrets_passthrough_without_holdback() {
        let mut m = Masker::new(&[]);
        assert_eq!(m.feed(b"hello"), b"hello".to_vec());
        assert!(m.flush().is_empty());
    }

    #[test]
    fn partial_match_at_eof_is_emitted_by_flush() {
        let mut m = one("openrouter", "sk-or-v1-abc123");
        let mut out = m.feed(b"tail sk-or-v1");
        out.extend(m.flush());
        assert_eq!(String::from_utf8(out).unwrap(), "tail sk-or-v1");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test masker 2>&1 | tail -5`
Expected: FAIL to compile — `Masker` not defined. (Add `mod masker;` to `src/main.rs`.)

- [ ] **Step 3: Write minimal implementation**

Add above the test module in `src/masker.rs`:

```rust
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

const MIN_MASK_LEN: usize = 6;

pub struct Masker {
    /// (pattern bytes, replacement bytes), longest pattern first
    patterns: Vec<(Vec<u8>, Vec<u8>)>,
    buf: Vec<u8>,
    holdback: usize,
}

impl Masker {
    pub fn new(secrets: &[(String, String)]) -> Masker {
        let mut patterns: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (alias, value) in secrets {
            if value.len() < MIN_MASK_LEN {
                continue;
            }
            let replacement = format!("[envault:{alias}]").into_bytes();
            let mut forms = vec![value.clone().into_bytes(), B64.encode(value).into_bytes()];
            let url = urlencoding::encode(value).into_owned().into_bytes();
            if url != value.as_bytes() {
                forms.push(url);
            }
            for f in forms {
                patterns.push((f, replacement.clone()));
            }
        }
        // longest first, so a longer form wins when forms overlap
        patterns.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let holdback = patterns.iter().map(|(p, _)| p.len()).max().map_or(0, |m| m - 1);
        Masker { patterns, buf: Vec::new(), holdback }
    }

    fn replace_in_buf(&mut self) {
        let mut i = 0;
        'outer: while i < self.buf.len() {
            for (pat, rep) in &self.patterns {
                if self.buf[i..].starts_with(pat) {
                    self.buf.splice(i..i + pat.len(), rep.iter().copied());
                    i += rep.len();
                    continue 'outer;
                }
            }
            i += 1;
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        self.replace_in_buf();
        if self.buf.len() <= self.holdback {
            return Vec::new();
        }
        let emit_len = self.buf.len() - self.holdback;
        let out: Vec<u8> = self.buf.drain(..emit_len).collect();
        out
    }

    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}
```

Note a deliberate simplification: `replace_in_buf` may re-scan replacement text it just inserted only by skipping past it (`i += rep.len()`), so replacements are never themselves re-replaced, and a pattern spanning the emit boundary is impossible because `holdback` ≥ every pattern length − 1.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test masker`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add src/masker.rs src/main.rs
git commit -m "feat: streaming output masker with base64/url-encoded forms"
```

---

### Task 8: Manifest + `envault link`

**Files:**
- Create: `src/manifest.rs`
- Create: `src/commands/link.rs`
- Modify: `src/commands/mod.rs`, `src/main.rs`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `store::Vault`, `paths`, `TestEnv`
- Produces:
  - `manifest::MANIFEST_NAME: &str = "envault.toml"`
  - `manifest::find_manifest(start: &Path) -> Option<PathBuf>` — walks up parent dirs
  - `manifest::Manifest { path: PathBuf, mappings: BTreeMap<String, String> }` with `Manifest::load(path: &Path) -> Result<Manifest>`, `save(&self) -> Result<()>`
  - `commands::link::cmd_link(env_var: String, alias: String) -> Result<()>`
  - CLI: `envault link <ENV_VAR> <alias>`

- [ ] **Step 1: Write the failing tests**

Create `src/manifest.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn find_walks_up() {
        let root = TempDir::new().unwrap();
        std::fs::write(root.path().join(MANIFEST_NAME), "").unwrap();
        let nested = root.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let found = find_manifest(&nested).unwrap();
        assert_eq!(found, root.path().join(MANIFEST_NAME));
        let elsewhere = TempDir::new().unwrap();
        assert!(find_manifest(elsewhere.path()).is_none());
    }

    #[test]
    fn load_save_roundtrip_flat_pairs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(MANIFEST_NAME);
        std::fs::write(&path, "OPENROUTER_API_KEY = \"openrouter\"\n").unwrap();
        let mut m = Manifest::load(&path).unwrap();
        assert_eq!(m.mappings["OPENROUTER_API_KEY"], "openrouter");
        m.mappings.insert("OTHER_KEY".into(), "other".into());
        m.save().unwrap();
        let re = Manifest::load(&path).unwrap();
        assert_eq!(re.mappings.len(), 2);
        assert_eq!(re.mappings["OTHER_KEY"], "other");
    }

    #[test]
    fn non_flat_manifest_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(MANIFEST_NAME);
        std::fs::write(&path, "[table]\nkey = \"x\"\n").unwrap();
        let err = Manifest::load(&path).unwrap_err().to_string();
        assert!(err.contains("flat"), "got: {err}");
    }
}
```

Append to `tests/cli.rs`:

```rust
#[test]
fn link_writes_manifest_and_validates_alias() {
    let te = TestEnv::new();
    te.init();
    te.envault().args(["add", "openrouter", "--stdin"]).write_stdin("sk-or-value-1\n")
        .assert().success();

    te.envault().args(["link", "OPENROUTER_API_KEY", "openrouter"]).assert().success();
    let manifest = std::fs::read_to_string(te.project.path().join("envault.toml")).unwrap();
    assert!(manifest.contains("OPENROUTER_API_KEY = \"openrouter\""));

    te.envault().args(["link", "X_KEY", "does-not-exist"]).assert().failure()
        .stderr(predicates::str::contains("envault add"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test 2>&1 | tail -5`
Expected: FAIL to compile — manifest types not defined. (Add `mod manifest;` to `src/main.rs`.)

- [ ] **Step 3: Write minimal implementation**

Add above the test module in `src/manifest.rs`:

```rust
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const MANIFEST_NAME: &str = "envault.toml";

pub fn find_manifest(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(MANIFEST_NAME);
        if candidate.exists() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

pub struct Manifest {
    pub path: PathBuf,
    pub mappings: BTreeMap<String, String>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Manifest> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let value: toml::Value = raw.parse()
            .with_context(|| format!("parsing {}", path.display()))?;
        let table = value.as_table()
            .context("envault.toml must be a TOML table")?;
        let mut mappings = BTreeMap::new();
        for (k, v) in table {
            match v.as_str() {
                Some(alias) => { mappings.insert(k.clone(), alias.to_string()); }
                None => bail!(
                    "envault.toml must contain only flat ENV_VAR = \"alias\" pairs (offending key: {k})"
                ),
            }
        }
        Ok(Manifest { path: path.to_path_buf(), mappings })
    }

    pub fn save(&self) -> Result<()> {
        let mut out = String::from("# envault manifest: ENV_VAR = \"vault alias\" (names only, no secrets)\n");
        for (k, v) in &self.mappings {
            out.push_str(&format!("{k} = \"{v}\"\n"));
        }
        std::fs::write(&self.path, out)
            .with_context(|| format!("writing {}", self.path.display()))
    }
}
```

Create `src/commands/link.rs`:

```rust
use anyhow::{bail, Result};

use crate::manifest::{find_manifest, Manifest, MANIFEST_NAME};
use crate::paths;
use crate::store::Vault;

pub fn cmd_link(env_var: String, alias: String) -> Result<()> {
    if env_var.is_empty() || env_var.contains('=') || env_var.contains(char::is_whitespace) {
        bail!("'{env_var}' is not a valid environment variable name");
    }
    let vault = Vault::load(&paths::envault_home())?;
    if vault.get(&alias).is_none() {
        bail!("alias '{alias}' is not in the vault — create it with `envault add {alias}`");
    }
    let cwd = std::env::current_dir()?;
    let mut manifest = match find_manifest(&cwd) {
        Some(path) => Manifest::load(&path)?,
        None => Manifest { path: cwd.join(MANIFEST_NAME), mappings: Default::default() },
    };
    manifest.mappings.insert(env_var.clone(), alias.clone());
    manifest.save()?;
    println!("Linked {env_var} -> {alias} in {}", manifest.path.display());
    Ok(())
}
```

In `src/commands/mod.rs` add `pub mod link;`. In `src/main.rs` add `mod manifest;`, the variant, and the dispatch arm:

```rust
    /// Map a project env var to a vault alias in envault.toml
    Link { env_var: String, alias: String },
```

```rust
        Some(Cmd::Link { env_var, alias }) => commands::link::cmd_link(env_var, alias),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS (all unit + integration tests so far).

- [ ] **Step 5: Commit**

```bash
git add src/manifest.rs src/commands src/main.rs tests/cli.rs
git commit -m "feat: envault.toml manifest with link command"
```

---

### Task 9: `envault run` — inject + mask

**Files:**
- Create: `src/commands/run.rs`
- Modify: `src/commands/mod.rs`, `src/main.rs`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `manifest::*`, `store::Vault`, `crypto::{load_identity, decrypt_value}`, `masker::Masker`, `TestEnv`
- Produces:
  - `commands::run::cmd_run(args: RunArgs) -> Result<i32>` (returns child exit code; `main` passes it to `std::process::exit`)
  - `commands::run::RunArgs { manifest: Option<PathBuf>, env: Vec<String>, allow_missing: bool, command: Vec<String> }`
  - CLI: `envault run [--manifest PATH] [--env VAR=alias ...] [--allow-missing] -- <cmd> [args...]`

- [ ] **Step 1: Write the failing tests**

Append to `tests/cli.rs`:

```rust
#[test]
fn run_injects_and_masks_output() {
    let te = TestEnv::new();
    te.init();
    te.envault().args(["add", "my-key", "--stdin"]).write_stdin("supersecret-value-9\n")
        .assert().success();
    te.envault().args(["link", "MY_KEY", "my-key"]).assert().success();

    let out = te.envault()
        .args(["run", "--", "sh", "-c", "echo got: $MY_KEY"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("got: [envault:my-key]"), "stdout was: {stdout}");
    assert!(!stdout.contains("supersecret-value-9"));
}

#[test]
fn run_passes_exit_code_through() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["run", "--allow-missing", "--", "sh", "-c", "exit 3"])
        .assert()
        .code(3);
}

#[test]
fn run_fails_listing_all_missing_aliases() {
    let te = TestEnv::new();
    te.init();
    std::fs::write(
        te.project.path().join("envault.toml"),
        "A_KEY = \"nope-a\"\nB_KEY = \"nope-b\"\n",
    )
    .unwrap();
    te.envault()
        .args(["run", "--", "true"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("nope-a"))
        .stderr(predicates::str::contains("nope-b"));
}

#[test]
fn run_extra_env_flag_maps_alias() {
    let te = TestEnv::new();
    te.init();
    te.envault().args(["add", "extra", "--stdin"]).write_stdin("extra-value-123\n")
        .assert().success();
    let out = te.envault()
        .args(["run", "--env", "EXTRA=extra", "--", "sh", "-c", "echo e=$EXTRA"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("e=[envault:extra]"), "stdout was: {stdout}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test cli 2>&1 | tail -5`
Expected: FAIL — `run` not a recognized subcommand.

- [ ] **Step 3: Write minimal implementation**

Create `src/commands/run.rs`:

```rust
use anyhow::{bail, Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use crate::crypto;
use crate::manifest::find_manifest;
use crate::masker::Masker;
use crate::paths;
use crate::store::Vault;

pub struct RunArgs {
    pub manifest: Option<PathBuf>,
    pub env: Vec<String>,
    pub allow_missing: bool,
    pub command: Vec<String>,
}

/// Restores cooked mode even on early return / panic.
struct RawGuard(bool);
impl RawGuard {
    fn enable() -> RawGuard {
        if std::io::stdin().is_terminal() {
            crossterm::terminal::enable_raw_mode().ok();
            RawGuard(true)
        } else {
            RawGuard(false)
        }
    }
}
impl Drop for RawGuard {
    fn drop(&mut self) {
        if self.0 {
            crossterm::terminal::disable_raw_mode().ok();
        }
    }
}

pub fn cmd_run(args: RunArgs) -> Result<i32> {
    if args.command.is_empty() {
        bail!("no command given — usage: envault run -- <cmd> [args...]");
    }

    // 1. Collect ENV_VAR -> alias mappings: manifest (optional) + --env flags.
    let cwd = std::env::current_dir()?;
    let mut mappings: Vec<(String, String)> = Vec::new();
    let manifest_path = args.manifest.clone().or_else(|| find_manifest(&cwd));
    if let Some(path) = &manifest_path {
        let m = crate::manifest::Manifest::load(path)?;
        mappings.extend(m.mappings.into_iter());
    }
    for spec in &args.env {
        let (var, alias) = spec
            .split_once('=')
            .with_context(|| format!("--env expects VAR=alias, got '{spec}'"))?;
        mappings.push((var.to_string(), alias.to_string()));
    }
    if mappings.is_empty() && manifest_path.is_none() && !args.allow_missing {
        bail!(
            "no envault.toml found (searched {} upward) and no --env mappings; \
             use --allow-missing to run without injection",
            cwd.display()
        );
    }

    // 2. Resolve aliases against the vault; report ALL missing at once.
    let home = paths::envault_home();
    let vault = if mappings.is_empty() { Vault::default() } else { Vault::load(&home)? };
    let missing: Vec<&(String, String)> =
        mappings.iter().filter(|(_, a)| vault.get(a).is_none()).collect();
    if !missing.is_empty() && !args.allow_missing {
        let list = missing
            .iter()
            .map(|(v, a)| format!("  {v} -> {a}"))
            .collect::<Vec<_>>()
            .join("\n");
        bail!("aliases missing from the vault:\n{list}\nadd them with `envault add <alias>`");
    }

    // 3. Decrypt.
    let mut injected: Vec<(String, String, String)> = Vec::new(); // (var, alias, value)
    if mappings.iter().any(|(_, a)| vault.get(a).is_some()) {
        let identity = crypto::load_identity()?;
        for (var, alias) in &mappings {
            if let Some(entry) = vault.get(alias) {
                let value = crypto::decrypt_value(&identity, &entry.cipher)?;
                injected.push((var.clone(), alias.clone(), value));
            }
        }
    }
    let masker_input: Vec<(String, String)> =
        injected.iter().map(|(_, a, v)| (a.clone(), v.clone())).collect();

    // 4. Spawn in a PTY.
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let pair = native_pty_system()
        .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .context("opening pty")?;
    let mut cmd = CommandBuilder::new(&args.command[0]);
    cmd.args(&args.command[1..]);
    cmd.cwd(&cwd);
    for (k, v) in std::env::vars() {
        cmd.env(k, v);
    }
    for (var, _, value) in &injected {
        cmd.env(var, value); // injected wins on collision
    }
    let mut child = pair.slave.spawn_command(cmd).context("spawning command")?;
    drop(pair.slave);

    // 5. Pump stdin -> child, and child -> masked stdout.
    let mut writer = pair.master.take_writer().context("pty writer")?;
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || writer.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });

    let _raw = RawGuard::enable();
    let mut reader = pair.master.try_clone_reader().context("pty reader")?;
    let mut masker = Masker::new(&masker_input);
    let mut stdout = std::io::stdout();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break, // EOF or pty closed
            Ok(n) => {
                stdout.write_all(&masker.feed(&buf[..n]))?;
                stdout.flush()?;
            }
        }
    }
    stdout.write_all(&masker.flush())?;
    stdout.flush()?;

    let status = child.wait().context("waiting for command")?;
    Ok(status.exit_code() as i32)
}
```

In `src/commands/mod.rs` add `pub mod run;`. In `src/main.rs` add the variant:

```rust
    /// Run a command with secrets injected and masked out of its output
    Run {
        #[arg(long)] manifest: Option<std::path::PathBuf>,
        /// Extra VAR=alias mappings (repeatable)
        #[arg(long)] env: Vec<String>,
        #[arg(long)] allow_missing: bool,
        /// Everything after `--` is the command to run
        #[arg(last = true)] command: Vec<String>,
    },
```

and the dispatch arm — note `run` exits with the child's code, so handle it before the generic error block:

```rust
        Some(Cmd::Run { manifest, env, allow_missing, command }) => {
            match commands::run::cmd_run(commands::run::RunArgs { manifest, env, allow_missing, command }) {
                Ok(code) => std::process::exit(code),
                Err(e) => Err(e),
            }
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test cli`
Expected: PASS. PTY output normalizes `\n` to `\r\n` — that's why the tests use `contains`, not `eq`.

- [ ] **Step 5: Manual smoke test**

Run: `cargo run -- run --allow-missing -- ls` (should list files normally), then with your real vault from Task 5 Step 5: `cargo run -- add smoke-test --stdin <<< "smoke-value-123"`, `cargo run -- run --env SMOKE=smoke-test -- sh -c 'echo $SMOKE'`
Expected: prints `[envault:smoke-test]`, never `smoke-value-123`. (First decryption may trigger a Keychain prompt — approve.)

- [ ] **Step 6: Commit**

```bash
git add src/commands src/main.rs tests/cli.rs
git commit -m "feat: envault run — pty injection with masked output and exit passthrough"
```

---

### Task 10: `envault import`

**Files:**
- Create: `src/commands/import.rs`
- Modify: `src/commands/mod.rs`, `src/main.rs`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `crypto`, `store`, `manifest`, `TestEnv`
- Produces:
  - `commands::import::cmd_import(file: PathBuf) -> Result<()>`
  - CLI: `envault import <file>`
  - Alias derivation rule: `VAR_NAME` → lowercase, `_` → `-` (e.g. `OPENROUTER_API_KEY` → `openrouter-api-key`)

- [ ] **Step 1: Write the failing test**

Append to `tests/cli.rs`:

```rust
#[test]
fn import_dotenv_encrypts_links_and_reports() {
    let te = TestEnv::new();
    te.init();
    let env_file = te.project.path().join(".env");
    std::fs::write(&env_file, "OPENROUTER_API_KEY=sk-or-import-1\nDB_PASSWORD=hunter22222\n").unwrap();

    te.envault()
        .args(["import", ".env"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Imported 2"))
        .stdout(predicates::str::contains("rm .env"));

    // aliases created (kebab-case of var names)
    let out = te.envault().args(["ls", "--json"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("openrouter-api-key"));
    assert!(stdout.contains("db-password"));

    // manifest linked
    let manifest = std::fs::read_to_string(te.project.path().join("envault.toml")).unwrap();
    assert!(manifest.contains("OPENROUTER_API_KEY = \"openrouter-api-key\""));
    assert!(manifest.contains("DB_PASSWORD = \"db-password\""));

    // plaintext not in the vault; original file untouched (user deletes it)
    let vault_raw = std::fs::read_to_string(te.home.path().join("vault.json")).unwrap();
    assert!(!vault_raw.contains("sk-or-import-1"));
    assert!(env_file.exists());

    // second import skips existing aliases instead of failing
    te.envault().args(["import", ".env"]).assert().success()
        .stdout(predicates::str::contains("skipped 2"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli 2>&1 | tail -5`
Expected: FAIL — `import` not a recognized subcommand.

- [ ] **Step 3: Write minimal implementation**

Create `src/commands/import.rs`:

```rust
use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::crypto;
use crate::manifest::{find_manifest, Manifest, MANIFEST_NAME};
use crate::paths;
use crate::store::{is_valid_alias, now_rfc3339, SecretEntry, Vault};

fn to_alias(var: &str) -> String {
    var.to_lowercase().replace('_', "-")
}

pub fn cmd_import(file: PathBuf) -> Result<()> {
    let home = paths::envault_home();
    let mut vault = Vault::load(&home)?;
    let recipient = crypto::load_recipient(&home)?;

    let cwd = std::env::current_dir()?;
    let mut manifest = match find_manifest(&cwd) {
        Some(path) => Manifest::load(&path)?,
        None => Manifest { path: cwd.join(MANIFEST_NAME), mappings: Default::default() },
    };

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for item in dotenvy::from_path_iter(&file)
        .with_context(|| format!("reading {}", file.display()))?
    {
        let (var, value) = item.context("parsing dotenv entry")?;
        let alias = to_alias(&var);
        if !is_valid_alias(&alias) {
            eprintln!("skipping {var}: derived alias '{alias}' is invalid");
            skipped += 1;
            continue;
        }
        if vault.get(&alias).is_some() {
            eprintln!("skipping {var}: alias '{alias}' already exists");
            skipped += 1;
        } else {
            let now = now_rfc3339();
            vault.insert(SecretEntry {
                label: var.clone(),
                alias: alias.clone(),
                cipher: crypto::encrypt_value(&recipient, &value)?,
                url: None,
                created_at: now.clone(),
                updated_at: now,
                notes: format!("imported from {}", file.display()),
            })?;
            imported += 1;
        }
        manifest.mappings.insert(var, alias);
    }
    vault.save(&home)?;
    manifest.save()?;

    println!("Imported {imported} secret(s) (skipped {skipped}) into the vault");
    println!("Manifest updated: {}", manifest.path.display());
    println!("\nThe plaintext file was NOT deleted. Do it now:\n  rm {}", file.display());
    Ok(())
}
```

In `src/commands/mod.rs` add `pub mod import;`. In `src/main.rs`:

```rust
    /// Encrypt every entry of a dotenv file into the vault and link it
    Import { file: std::path::PathBuf },
```

```rust
        Some(Cmd::Import { file }) => commands::import::cmd_import(file),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test cli`
Expected: PASS (all integration tests).

- [ ] **Step 5: Commit**

```bash
git add src/commands src/main.rs tests/cli.rs
git commit -m "feat: import dotenv files into the vault with auto-linking"
```

---

### Task 11: Lint, docs, full-suite gate

**Files:**
- Create: `README.md`
- Modify: anything clippy flags

**Interfaces:**
- Consumes: everything
- Produces: a clean `cargo fmt` / `cargo clippy -D warnings` / `cargo test` gate and a quickstart README.

- [ ] **Step 1: Run the full gate**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: clippy may flag small things (e.g. needless clones) — fix each one, re-run until everything passes. Do not `#[allow]` anything without a comment saying why.

- [ ] **Step 2: Write README**

Create `README.md`:

```markdown
# envault

Local secrets vault for agentic coding. Agents see **aliases** and **ciphers** —
plaintext exists only inside the process that needs it.

## Quickstart

    envault init                          # keypair -> macOS Keychain
    envault add openrouter                # value typed at a hidden prompt
    envault link OPENROUTER_API_KEY openrouter
    envault run -- npm start              # injected + masked

- `envault ls --json` — names only; the only read an agent needs.
- `envault import .env` — encrypt an existing dotenv file, then delete it.
- Output of `envault run` is masked: injected values (and their base64/URL
  forms) print as `[envault:<alias>]`.

## Security model (short form)

Protects against secrets entering an agent's context, transcripts, files, or
logs. Does **not** protect against code that deliberately exfiltrates its own
environment over the network at runtime. Values shorter than 6 characters are
injected but not masked. Full spec: `docs/superpowers/specs/2026-08-26-envault-design.md`.
```

- [ ] **Step 3: Verify the suite one final time**

Run: `cargo test 2>&1 | tail -3`
Expected: all tests pass, 0 failed.

- [ ] **Step 4: Commit**

```bash
git add README.md .
git commit -m "chore: clippy clean, quickstart README"
```
