pub mod app;
pub mod request;
pub mod theme;
pub mod ui;

use anyhow::{bail, Context, Result};
use crossterm::event::{self, Event};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{IsTerminal, Write};

use crate::crypto;
use crate::paths;
use crate::store::Vault;
use app::{App, Effect};

pub fn run_tui() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!(
            "the envault dashboard needs an interactive terminal (agents: use `envault ls --json`)"
        );
    }
    let home = paths::envault_home();
    if !paths::vault_file(&home).exists() {
        print!("No vault at {} — initialize now? [y/N] ", home.display());
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if line.trim().eq_ignore_ascii_case("y") {
            crate::commands::init::cmd_init()?;
        } else {
            bail!("no vault — nothing to show");
        }
    }
    let vault = Vault::load(&home)?;
    let recipient = crypto::load_recipient(&home)?;
    let mut app = App::new(vault, recipient);

    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let result = event_loop(&mut app, &home);
    crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen).ok();
    crossterm::terminal::disable_raw_mode().ok();
    result
}

fn vault_mtime(home: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(crate::paths::vault_file(home))
        .and_then(|m| m.modified())
        .ok()
}

fn event_loop(app: &mut App, home: &std::path::Path) -> Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut last_mtime = vault_mtime(home);

    // Read input on a dedicated thread and deliver it over a channel. This lets
    // the main loop wake on a real timer (recv_timeout) to watch the vault file,
    // independent of any terminal-specific quirks in crossterm's own poll().
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if tx.send(ev).is_err() {
                break;
            }
        }
    });

    loop {
        // Watch the vault file for external changes (e.g. a granted
        // `envault request` while this is open).
        let now = vault_mtime(home);
        if now != last_mtime {
            // Only commit the new mtime once the load actually succeeds, so a
            // read that lands mid-write (partial JSON) is retried next tick.
            if let Ok(v) = Vault::load(home) {
                last_mtime = now;
                app.reload_vault(v);
                app.set_info("vault updated");
            }
        }

        terminal.draw(|f| ui::draw(f, app))?;

        // Wait for input, but wake at least twice a second to re-check the file.
        let key = match rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(Event::Key(k)) => k,
            Ok(_) => continue, // resize/focus/etc.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        };
        if key.kind != event::KeyEventKind::Press {
            continue;
        }
        let effect = app.handle_key(key);
        match effect {
            None => {}
            Some(Effect::Quit) => return Ok(()),
            Some(Effect::Save) => {
                if let Err(e) = app.vault.save(home) {
                    app.set_error(format!("save failed: {e:#}"));
                }
            }
            Some(Effect::Decrypt { alias }) => match decrypt(app, home, "reveal", &alias) {
                Ok(value) => app.provide_plaintext(value),
                Err(e) => app.set_error(format!("decrypt failed: {e:#}")),
            },
            Some(Effect::Copy { alias }) => match decrypt(app, home, "copy", &alias) {
                Ok(value) => match copy_with_autoclear(value) {
                    Ok(()) => {
                        app.set_success(format!("'{alias}' copied — clipboard clears in 15s"));
                    }
                    Err(e) => app.set_error(format!("clipboard failed: {e:#}")),
                },
                Err(e) => app.set_error(format!("decrypt failed: {e:#}")),
            },
            Some(Effect::Rotate) => match crate::commands::rotate::rotate_in_place(home) {
                Ok(outcome) => match Vault::load(home) {
                    Ok(v) => app.after_rotate(outcome.count, v, outcome.recipient),
                    Err(e) => app.set_error(format!("vault reload failed: {e:#}")),
                },
                Err(e) => app.set_error(format!("rotate failed: {e:#}")),
            },
        }
        // Our own writes (save/rotate) just changed the file; adopt the new
        // mtime so the watcher above doesn't treat them as an external change.
        last_mtime = vault_mtime(home);
    }
}

fn decrypt(app: &App, home: &std::path::Path, action: &str, alias: &str) -> Result<String> {
    let entry = app.vault.get(alias).context("entry vanished")?.clone();
    let identity = crate::access::unlock(home, action, alias)?;
    crypto::decrypt_value(&identity, &entry.cipher)
}

fn copy_with_autoclear(value: String) -> Result<()> {
    let mut cb = arboard::Clipboard::new().context("opening clipboard")?;
    cb.set_text(value)?;
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(15));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            cb.set_text(String::new()).ok();
        }
    });
    Ok(())
}
