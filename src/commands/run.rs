use anyhow::{anyhow, bail, Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::Stdio;

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

fn pump_masked<R: Read>(
    mut reader: R,
    secrets: &[(String, String)],
    read_error_is_eof: bool,
) -> Result<()> {
    let mut masker = Masker::new(secrets);
    let mut stdout = std::io::stdout();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                stdout.write_all(&masker.feed(&buf[..n]))?;
                stdout.flush()?;
            }
            Err(_) if read_error_is_eof => break,
            Err(error) => return Err(error.into()),
        }
    }
    stdout.write_all(&masker.flush())?;
    stdout.flush()?;
    Ok(())
}

fn run_with_piped_stdin(
    args: &RunArgs,
    cwd: &std::path::Path,
    injected: &[(String, String, String)],
    masker_input: &[(String, String)],
) -> Result<i32> {
    let mut cmd = std::process::Command::new(&args.command[0]);
    cmd.args(&args.command[1..])
        .current_dir(cwd)
        // Inheriting the pipe gives the child the caller's exact byte stream.
        // A PTY would echo and line-buffer it, then add a newline before EOF.
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (var, _, value) in injected {
        cmd.env(var, value);
    }

    let mut child = cmd.spawn().context("spawning command")?;
    let child_stdout = child.stdout.take().context("child stdout")?;
    let child_stderr = child.stderr.take().context("child stderr")?;
    let stdout_secrets = masker_input.to_vec();
    let stderr_secrets = masker_input.to_vec();
    let stdout_pump = std::thread::spawn(move || pump_masked(child_stdout, &stdout_secrets, false));
    let stderr_pump = std::thread::spawn(move || pump_masked(child_stderr, &stderr_secrets, false));

    let status = child.wait().context("waiting for command")?;
    stdout_pump
        .join()
        .map_err(|_| anyhow!("stdout pump panicked"))??;
    stderr_pump
        .join()
        .map_err(|_| anyhow!("stderr pump panicked"))??;
    Ok(status.code().unwrap_or(1))
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

    // 3. Decrypt (gated + audited via the access choke point).
    let mut injected: Vec<(String, String, String)> = Vec::new(); // (var, alias, value)
    if mappings.iter().any(|(_, a)| vault.get(a).is_some()) {
        let identity = crate::access::unlock(&home, "run", &args.command.join(" "))?;
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

    // A pipe has byte-stream semantics, which a terminal cannot preserve.
    // Keep the PTY only for genuinely interactive commands; both paths mask
    // child output before forwarding it.
    if !std::io::stdin().is_terminal() {
        return run_with_piped_stdin(&args, &cwd, &injected, &masker_input);
    }

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
    let reader = pair.master.try_clone_reader().context("pty reader")?;
    // PTY readers report an I/O error when the slave closes; preserve that
    // established EOF behavior for interactive commands.
    pump_masked(reader, &masker_input, true)?;

    let status = child.wait().context("waiting for command")?;
    Ok(status.exit_code() as i32)
}
