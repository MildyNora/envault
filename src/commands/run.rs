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
        mappings.extend(m.mappings);
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
    let vault = if mappings.is_empty() {
        Vault::default()
    } else {
        Vault::load(&home)?
    };
    let missing: Vec<&(String, String)> = mappings
        .iter()
        .filter(|(_, a)| vault.get(a).is_none())
        .collect();
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
    let masker_input: Vec<(String, String)> = injected
        .iter()
        .map(|(_, a, v)| (a.clone(), v.clone()))
        .collect();

    // 4. Spawn in a PTY.
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let pair = native_pty_system()
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
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
