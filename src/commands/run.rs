use anyhow::{bail, Context, Result};
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

fn pump_masked<R: Read, W: Write>(
    mut reader: R,
    mut output: W,
    secrets: &[(String, String)],
    read_error_is_eof: bool,
) -> Result<()> {
    let mut masker = Masker::new(secrets);
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                output.write_all(&masker.feed(&buf[..n]))?;
                output.flush()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) if read_error_is_eof => break,
            Err(error) => return Err(error.into()),
        }
    }
    output.write_all(&masker.flush())?;
    output.flush()?;
    Ok(())
}

fn run_with_piped_stdin<W: Write>(
    args: &RunArgs,
    cwd: &std::path::Path,
    injected: &[(String, String, String)],
    masker_input: &[(String, String)],
    output: W,
) -> Result<i32> {
    let (reader, writer) = std::io::pipe().context("creating merged output pipe")?;
    let stderr = writer.try_clone().context("cloning output pipe")?;
    let mut cmd = std::process::Command::new(&args.command[0]);
    cmd.args(&args.command[1..])
        .current_dir(cwd)
        // Inheriting the pipe gives the child the caller's exact byte stream.
        // A PTY would echo and line-buffer it, then add a newline before EOF.
        .stdin(Stdio::inherit())
        .stdout(writer)
        .stderr(stderr);
    for (var, _, value) in injected {
        cmd.env(var, value);
    }

    let mut child = cmd.spawn().context("spawning command")?;
    // Command retains its handles after spawn. Close our copies so EOF means
    // every child output handle has closed, not just stdout or stderr alone.
    drop(cmd);
    // One bounded OS pipe merges raw bytes before a single masker/output owner.
    // Drain while the child runs; waiting first could fill the pipe and deadlock.
    if let Err(error) = pump_masked(reader, output, masker_input, false) {
        // The consumed reader has already closed. Never wait for a live child
        // after an output failure: it may be blocked on output or waiting on input.
        match child.kill() {
            Ok(()) => {
                let _ = child.wait();
            }
            Err(_) => {
                let _ = child.try_wait();
            }
        }
        return Err(error.context("pumping command output"));
    }
    let status = child.wait().context("waiting for command")?;
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
        return run_with_piped_stdin(
            &args,
            &cwd,
            &injected,
            &masker_input,
            std::io::stdout().lock(),
        );
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
    pump_masked(reader, std::io::stdout().lock(), &masker_input, true)?;

    let status = child.wait().context("waiting for command")?;
    Ok(status.exit_code() as i32)
}

#[cfg(test)]
mod pipe_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    struct ObservedOutput {
        bytes: Vec<u8>,
        flushed: mpsc::Sender<Vec<u8>>,
    }

    impl Write for ObservedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushed.send(self.bytes.clone()).unwrap();
            Ok(())
        }
    }

    #[test]
    fn merged_pipe_retains_prefix_until_last_stream_closes() {
        for stderr_first in [false, true] {
            let (reader, stdout) = std::io::pipe().unwrap();
            let stderr = stdout.try_clone().unwrap();
            let (mut first, mut second) = if stderr_first {
                (stderr, stdout)
            } else {
                (stdout, stderr)
            };
            let (tx, rx) = mpsc::channel();
            let pump = std::thread::spawn(move || {
                let mut output = ObservedOutput {
                    bytes: Vec::new(),
                    flushed: tx,
                };
                pump_masked(
                    reader,
                    &mut output,
                    &[("key".into(), "abcdef".into())],
                    false,
                )
                .unwrap();
                output.bytes
            });
            first.write_all(b"ready abc").unwrap();
            drop(first);
            // Output acknowledgement, not a timing guess: the prefix was fed
            // and safe output flushed before the surviving stream continues.
            let mut observed = Vec::new();
            while observed.len() < b"ready ".len() {
                observed = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            assert_eq!(observed, b"ready ");
            second.write_all(b"def ordinary abc").unwrap();
            while observed.len() < b"ready [envault:key] ordinary ".len() {
                observed = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            assert_eq!(observed, b"ready [envault:key] ordinary ");
            drop(second);
            // Only the last close may release the genuine incomplete suffix.
            let expected = b"ready [envault:key] ordinary abc";
            while observed.len() < expected.len() {
                observed = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            assert_eq!(observed, expected);
            assert_eq!(pump.join().unwrap(), expected);
        }
    }

    #[test]
    fn ordinary_pipe_read_errors_propagate_without_finalizing_prefix() {
        struct FailedRead(bool);
        impl Read for FailedRead {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    buf[..3].copy_from_slice(b"abc");
                    return Ok(3);
                }
                Err(std::io::Error::other("synthetic pipe read failure"))
            }
        }
        let mut output = Vec::new();
        assert!(pump_masked(
            FailedRead(false),
            &mut output,
            &[("key".into(), "abcdef".into())],
            false
        )
        .is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn output_failure_stops_the_pump() {
        struct FailedWrite;
        impl Write for FailedWrite {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic closed output",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(pump_masked(b"ordinary".as_slice(), FailedWrite, &[], false).is_err());
    }
}

#[cfg(all(test, unix))]
mod pipe_child_tests {
    use super::*;

    #[test]
    fn closed_output_does_not_wait_for_live_child() {
        struct ClosedOutput;
        impl Write for ClosedOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic output closed",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let home = tempfile::TempDir::new().unwrap();
            let args = RunArgs {
                manifest: None,
                env: Vec::new(),
                allow_missing: true,
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "while :; do printf ordinary; done".into(),
                ],
            };
            // Exercise the actual child/pump cleanup without vault access.
            tx.send(run_with_piped_stdin(&args, home.path(), &[], &[], ClosedOutput).is_err())
                .unwrap();
        });
        assert!(rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap());
        worker.join().unwrap();
    }
}
