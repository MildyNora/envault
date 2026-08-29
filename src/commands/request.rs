//! `envault request` — the agent-facing channel for asking the human to add a
//! secret. The agent side spawns a human-only window and waits for the outcome;
//! the window side runs the request TUI, encrypts a granted value into the
//! vault, and reports back through a small session file. The agent only ever
//! learns granted / declined+note / cancelled — never the value.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
// Only the debug-gated inline fallback below uses this; release never does (M4).
#[cfg(debug_assertions)]
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::paths;
use crate::store::{is_valid_alias, now_rfc3339, SecretEntry, Vault};
use crate::tui::request::{Outcome, RequestApp, RequestMeta};

#[derive(Serialize, Deserialize)]
struct RequestFile {
    name: String,
    label: String,
    reason: String,
    agent: String,
    caller: String,
}

#[derive(Serialize, Deserialize)]
struct ResultFile {
    outcome: String,      // granted | declined | cancelled
    note: Option<String>, // only for declined
}

/// Agent side: `envault request <name> --reason ... [--label ...] [--agent ...]`.
pub fn cmd_request(
    name: String,
    label: Option<String>,
    reason: Option<String>,
    agent: Option<String>,
) -> Result<i32> {
    if !is_valid_alias(&name) {
        bail!("name '{name}' must be kebab-case: lowercase letters, digits, '-'");
    }
    let home = paths::envault_home();
    // If it already exists, the agent is done — no need to bother the human.
    if Vault::load(&home)
        .ok()
        .and_then(|v| v.get(&name).map(|_| ()))
        .is_some()
    {
        println!("'{name}' is already in the vault — use it via `envault run`.");
        return Ok(0);
    }

    let meta = RequestFile {
        name: name.clone(),
        label: label.unwrap_or_default(),
        reason: reason.unwrap_or_default(),
        agent: agent.unwrap_or_else(|| std::env::var("ENVAULT_AGENT").unwrap_or_default()),
        caller: caller_description(),
    };

    // Always open a FRESH window — even when run from a terminal — so the
    // request UI is its own popup and never takes over the current terminal.
    let session = new_session_dir(&home)?;
    std::fs::write(session.join("request.json"), serde_json::to_string(&meta)?)?;

    let exe = std::env::current_exe().context("locating the envault binary")?;
    // Tests (and headless runs) can force the no-window fallback path.
    let spawn = if std::env::var_os("ENVAULT_NO_WINDOW").is_some() {
        Err(anyhow::anyhow!("window disabled"))
    } else {
        spawn_window(&exe, &session)
    };
    if let Err(e) = spawn {
        let _ = std::fs::remove_dir_all(&session);
        // Fall back to inline entry only in debug/test builds. In release we
        // never render the secret-entry TUI in the caller's terminal, since a
        // malicious agent could force spawn failure (ENVAULT_NO_WINDOW-style)
        // and read the keystrokes from a PTY it controls. (M4)
        #[cfg(debug_assertions)]
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            let outcome = run_window(&meta_to_request(&meta))?;
            return finish(&home, &meta, outcome, None);
        }
        eprintln!(
            "envault: couldn't open a request window ({e}). Ask the user to run:\n  \
             {} request-window {}",
            exe.display(),
            session.display()
        );
        return Ok(6);
    }
    eprintln!("envault: waiting for the user to respond to the secret request for '{name}'…");

    let result = wait_for_result(&session.join("result.json"), 600)?;
    // Close the spawned window from here — the parent runs OUTSIDE that window,
    // so once the window's process has exited it's an idle login shell and
    // Terminal closes it with no "terminate the running process?" dialog.
    close_spawned_window(&session);
    let _ = std::fs::remove_dir_all(&session);
    match result {
        Some(r) if r.outcome == "granted" => {
            println!("granted: '{name}' was added to the vault — use it via `envault run`.");
            Ok(0)
        }
        Some(r) if r.outcome == "declined" => {
            eprintln!(
                "declined by user: {}",
                r.note
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| "(no reason given)".into())
            );
            Ok(3)
        }
        Some(_) => {
            eprintln!("request cancelled by user.");
            Ok(4)
        }
        None => {
            eprintln!("request timed out with no response.");
            Ok(5)
        }
    }
}

/// Window side (hidden): `envault request-window <session-dir>`. Runs in the
/// spawned terminal, encrypts a granted value, writes the result, self-closes.
pub fn cmd_request_window(session: PathBuf) -> Result<()> {
    let raw = std::fs::read_to_string(session.join("request.json"))
        .with_context(|| format!("reading {}", session.join("request.json").display()))?;
    let meta: RequestFile = serde_json::from_str(&raw)?;

    // Record our window's tty so the parent (outside this window) can close us.
    if let Some(tty) = current_tty() {
        let _ = std::fs::write(session.join("window.tty"), &tty);
    }

    let outcome = run_window(&meta_to_request(&meta))?;
    let home = paths::envault_home();
    finish(&home, &meta, outcome, Some(&session))?;
    // The parent closes the window; just exit so it becomes an idle shell.
    Ok(())
}

fn meta_to_request(m: &RequestFile) -> RequestMeta {
    RequestMeta {
        name: m.name.clone(),
        label: m.label.clone(),
        reason: m.reason.clone(),
        agent: if m.agent.is_empty() {
            "an unidentified agent".into()
        } else {
            m.agent.clone()
        },
        caller: m.caller.clone(),
    }
}

/// Apply the outcome: encrypt+store on grant, and report into `session`
/// (the spawned-window path) when one is given.
fn finish(
    home: &Path,
    meta: &RequestFile,
    outcome: Outcome,
    session: Option<&Path>,
) -> Result<i32> {
    let (result, code) = match outcome {
        Outcome::Granted(value) => {
            let recipient = crypto::recipient_from_identity()?;
            let cipher = crypto::encrypt_value(&recipient, &value)?;
            let mut vault = Vault::load(home)?;
            if vault.get(&meta.name).is_none() {
                let now = now_rfc3339();
                vault.insert(SecretEntry {
                    label: if meta.label.is_empty() {
                        meta.name.clone()
                    } else {
                        meta.label.clone()
                    },
                    alias: meta.name.clone(),
                    cipher,
                    url: None,
                    created_at: now.clone(),
                    updated_at: now,
                    notes: if meta.reason.is_empty() {
                        String::new()
                    } else {
                        format!("requested by {}: {}", meta.agent, meta.reason)
                    },
                })?;
                vault.save(home)?;
            }
            println!("✔ added '{}' to the vault.", meta.name);
            (
                ResultFile {
                    outcome: "granted".into(),
                    note: None,
                },
                0,
            )
        }
        Outcome::Declined(note) => {
            println!("declined — the agent has been told.");
            (
                ResultFile {
                    outcome: "declined".into(),
                    note: Some(note),
                },
                3,
            )
        }
        Outcome::Cancelled => (
            ResultFile {
                outcome: "cancelled".into(),
                note: None,
            },
            4,
        ),
    };
    // Only the spawned-window path has a session to report into.
    if let Some(dir) = session {
        std::fs::write(dir.join("result.json"), serde_json::to_string(&result)?).ok();
    }
    Ok(code)
}

// ── plumbing ────────────────────────────────────────────────────────────────

fn new_session_dir(home: &Path) -> Result<PathBuf> {
    let base = home.join("requests");
    std::fs::create_dir_all(&base)?;
    // Unique without randomness: pid + monotonic-ish counter via nanos-free time
    // is unavailable here, so pid + a scan suffices for a single user.
    let mut n = 0u32;
    loop {
        let dir = base.join(format!("{}-{n}", std::process::id()));
        if !dir.exists() {
            std::fs::create_dir(&dir)?;
            crate::platform::set_mode(&dir, 0o700)?;
            return Ok(dir);
        }
        n += 1;
    }
}

/// macOS: open a small centered Terminal.app window running the request TUI.
#[cfg(target_os = "macos")]
fn spawn_window(exe: &Path, session: &Path) -> Result<()> {
    use std::process::Stdio;
    // Carry the caller's vault selection into the fresh login shell that
    // `do script` spawns, so the window writes to the same vault we checked.
    let mut env_prefix = String::new();
    for key in ["ENVAULT_HOME", "ENVAULT_IDENTITY_FILE"] {
        if let Ok(val) = std::env::var(key) {
            env_prefix.push_str(&format!("{key}={} ", shell_quote(&val)));
        }
    }
    let cmd = format!(
        "{env_prefix}{exe} request-window {session}",
        session = shell_quote(&session.to_string_lossy()),
        exe = shell_quote(&exe.to_string_lossy()),
    );
    let script = format!(
        "tell application \"Finder\" to set sb to bounds of window of desktop\n\
         set sw to item 3 of sb\n\
         set sh to item 4 of sb\n\
         set ww to 660\n\
         set wh to 460\n\
         set x1 to (sw - ww) / 2 as integer\n\
         set y1 to (sh - wh) / 2 as integer\n\
         tell application \"Terminal\"\n\
         activate\n\
         do script \"{}\"\n\
         delay 0.2\n\
         try\n\
         set bounds of front window to {{x1, y1, x1 + ww, y1 + wh}}\n\
         end try\n\
         end tell",
        applescript_escape(&cmd),
    );
    // Suppress osascript's own output so it never pollutes our stdout.
    let status = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("launching osascript")?;
    if !status.success() {
        bail!("osascript exited with {status}");
    }
    Ok(())
}

/// Windows: open a fresh window running the request TUI — Windows Terminal
/// (`wt`) if present for a nicer look, else a PowerShell console. Either way
/// the window closes on its own when the process exits. The child inherits our
/// environment, so ENVAULT_HOME/ENVAULT_IDENTITY_FILE carry over.
#[cfg(target_os = "windows")]
fn spawn_window(exe: &Path, session: &Path) -> Result<()> {
    use std::process::Stdio;
    let exe = exe.to_string_lossy().to_string();
    let session = session.to_string_lossy().to_string();

    // Prefer Windows Terminal, sized to a small popup.
    let wt = std::process::Command::new("wt")
        .args([
            "--size",
            "84,26",
            "new-tab",
            "--title",
            "envault - secret request",
        ])
        .arg(&exe)
        .arg("request-window")
        .arg(&session)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if wt.is_ok() {
        return Ok(());
    }

    // Fallback: a plain PowerShell console window via Start-Process.
    let ps = format!(
        "Start-Process -FilePath {} -ArgumentList @('request-window', {})",
        ps_quote(&exe),
        ps_quote(&session),
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("launching powershell")?;
    if !status.success() {
        bail!("could not open a PowerShell window");
    }
    Ok(())
}

/// Linux/BSD: try a few common terminal emulators; each runs our command and
/// closes when it exits. Returns Err if none are found (caller falls back to
/// running inline).
#[cfg(all(unix, not(target_os = "macos")))]
fn spawn_window(exe: &Path, session: &Path) -> Result<()> {
    use std::process::Stdio;
    let inner = format!(
        "{} request-window {}",
        shell_quote(&exe.to_string_lossy()),
        shell_quote(&session.to_string_lossy()),
    );
    // (program, args) — most emulators take `-e <cmd...>`.
    let attempts: [(&str, Vec<String>); 5] = [
        (
            "x-terminal-emulator",
            vec!["-e".into(), "sh".into(), "-c".into(), inner.clone()],
        ),
        (
            "gnome-terminal",
            vec!["--".into(), "sh".into(), "-c".into(), inner.clone()],
        ),
        (
            "konsole",
            vec!["-e".into(), "sh".into(), "-c".into(), inner.clone()],
        ),
        (
            "xterm",
            vec!["-e".into(), "sh".into(), "-c".into(), inner.clone()],
        ),
        (
            "alacritty",
            vec!["-e".into(), "sh".into(), "-c".into(), inner.clone()],
        ),
    ];
    for (term, args) in attempts {
        let spawned = std::process::Command::new(term)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_ok() {
            return Ok(());
        }
    }
    bail!("no supported terminal emulator found (tried gnome-terminal, konsole, xterm, alacritty)");
}

fn wait_for_result(result_path: &Path, timeout_secs: u64) -> Result<Option<ResultFile>> {
    let deadline = timeout_secs * 10; // 100ms ticks
    for _ in 0..deadline {
        if result_path.exists() {
            let raw = std::fs::read_to_string(result_path)?;
            if let Ok(r) = serde_json::from_str::<ResultFile>(&raw) {
                return Ok(Some(r));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(None)
}

/// Run the request TUI to completion in the current terminal.
fn run_window(meta: &RequestMeta) -> Result<Outcome> {
    use crossterm::event::{self, Event, KeyEventKind};
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;

    let mut app = RequestApp::new(meta.clone());
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let outcome = loop {
        terminal.draw(|f| crate::tui::request::draw(f, &app))?;
        if let Event::Key(k) = event::read()? {
            if k.kind == KeyEventKind::Press {
                if let Some(o) = app.handle_key(k) {
                    break o;
                }
            }
        }
    };
    crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen).ok();
    crossterm::terminal::disable_raw_mode().ok();
    Ok(outcome)
}

/// The controlling terminal device of this process, e.g. `/dev/ttys003`.
/// `tty` must inherit our real stdin (fd 0) — `Command::output()` nulls stdin
/// by default, which would make `tty` report "not a tty" and return None.
/// Only macOS needs it (to close its Terminal window by tty).
#[cfg(target_os = "macos")]
fn current_tty() -> Option<String> {
    let out = std::process::Command::new("tty")
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.starts_with("/dev/") {
        Some(s)
    } else {
        None
    }
}

/// Non-macOS: no tty tracking needed — Windows consoles and Linux terminal
/// emulators close on their own when the launched process exits.
#[cfg(not(target_os = "macos"))]
fn current_tty() -> Option<String> {
    None
}

/// macOS: close the spawned Terminal window from the parent (which is outside
/// it). The window's process has written its result and is exiting; a short
/// wait lets it become an idle login shell, which Terminal closes with no
/// confirmation dialog. `saving no` suppresses any save prompt.
#[cfg(target_os = "macos")]
fn close_spawned_window(session: &Path) {
    let Ok(tty) = std::fs::read_to_string(session.join("window.tty")) else {
        return;
    };
    let tty = tty.trim();
    if tty.is_empty() {
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    let script = format!(
        "tell application \"Terminal\" to close (every window whose tty is \"{}\") saving no",
        applescript_escape(tty),
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Non-macOS: nothing to do — the window closes itself when its process exits.
#[cfg(not(target_os = "macos"))]
fn close_spawned_window(_session: &Path) {}

/// A short, human-meaningful description of the process that launched us, for
/// cross-checking the agent's claimed `--agent` identity. Unix uses `ps`.
#[cfg(unix)]
fn caller_description() -> String {
    let ppid = parent_pid();
    let comm = ppid
        .and_then(|p| {
            std::process::Command::new("ps")
                .args(["-o", "comm=", "-p", &p.to_string()])
                .output()
                .ok()
        })
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    match ppid {
        Some(p) => format!("{comm} (pid {p})"),
        None => comm,
    }
}

#[cfg(unix)]
fn parent_pid() -> Option<u32> {
    let out = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Windows: look up our parent process via PowerShell/CIM (best effort).
#[cfg(windows)]
fn caller_description() -> String {
    let pid = std::process::id();
    let ps = format!(
        "$pp=(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').ParentProcessId; \
         $n=(Get-Process -Id $pp -ErrorAction SilentlyContinue).ProcessName; \
         if ($n) {{ \"$n (pid $pp)\" }} else {{ \"pid $pp\" }}"
    );
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "a local process".into())
}

#[cfg(unix)]
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(windows)]
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(target_os = "macos")]
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_value, generate_identity, store_recipient};

    fn meta(name: &str) -> RequestFile {
        RequestFile {
            name: name.into(),
            label: "My Label".into(),
            reason: "the demo".into(),
            agent: "Test Agent".into(),
            caller: "bash (pid 1)".into(),
        }
    }

    #[test]
    fn grant_encrypts_into_vault_and_reports() {
        // finish() derives the recipient from the (Keychain) identity; in tests
        // that resolves through ENVAULT_IDENTITY_FILE, so set one up.
        let _guard = crate::crypto::test_env_lock();
        let home = tempfile::TempDir::new().unwrap();
        let session = tempfile::TempDir::new().unwrap();
        let id_path = home.path().join("id.txt");
        std::env::set_var("ENVAULT_IDENTITY_FILE", &id_path);
        let id = generate_identity();
        crate::crypto::store_identity(&id, home.path()).unwrap();
        store_recipient(&id, home.path()).unwrap();
        Vault::default().save(home.path()).unwrap();

        let code = finish(
            home.path(),
            &meta("newkey"),
            Outcome::Granted("granted-secret-42".into()),
            Some(session.path()),
        )
        .unwrap();
        std::env::remove_var("ENVAULT_IDENTITY_FILE");
        assert_eq!(code, 0);

        // stored + decrypts to exactly the granted bytes; reason recorded
        let vault = Vault::load(home.path()).unwrap();
        let entry = vault.get("newkey").expect("added");
        assert_eq!(entry.label, "My Label");
        assert_eq!(
            decrypt_value(&id, &entry.cipher).unwrap(),
            "granted-secret-42"
        );
        assert!(entry.notes.contains("Test Agent") && entry.notes.contains("the demo"));

        // plaintext never lands on disk
        let raw = std::fs::read_to_string(crate::paths::vault_file(home.path())).unwrap();
        assert!(!raw.contains("granted-secret-42"));

        // the agent-facing result says granted, no value
        let result = std::fs::read_to_string(session.path().join("result.json")).unwrap();
        assert!(result.contains("granted"));
        assert!(!result.contains("granted-secret-42"));
    }

    #[test]
    fn command_escaping_is_safe() {
        // shell_quote keeps a value with spaces/quotes as one safe argument
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        // applescript_escape neutralizes quotes and backslashes
        assert_eq!(applescript_escape("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn decline_writes_note_and_adds_nothing() {
        let home = tempfile::TempDir::new().unwrap();
        let session = tempfile::TempDir::new().unwrap();
        let id = generate_identity();
        store_recipient(&id, home.path()).unwrap();
        Vault::default().save(home.path()).unwrap();

        let code = finish(
            home.path(),
            &meta("newkey"),
            Outcome::Declined("use deepseek instead".into()),
            Some(session.path()),
        )
        .unwrap();
        assert_eq!(code, 3);
        assert!(Vault::load(home.path()).unwrap().get("newkey").is_none());
        let result = std::fs::read_to_string(session.path().join("result.json")).unwrap();
        assert!(result.contains("declined") && result.contains("use deepseek instead"));
    }
}
