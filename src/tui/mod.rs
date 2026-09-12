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
            crate::commands::init::cmd_init(false)?;
        } else {
            bail!("no vault — nothing to show");
        }
    }
    let (vault, recipient) = load_snapshot(&home)?;
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

/// Pair the vault with the authoritative identity, never recipient.txt, while
/// excluding rotation's identity/vault swap.
fn load_snapshot(home: &std::path::Path) -> Result<(Vault, age::x25519::Recipient)> {
    let _generation = crate::store::lock_generation(home)?;
    Ok((Vault::load(home)?, crypto::recipient_from_identity()?))
}

fn revision(vault: &Vault) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(vault)?)
}

/// A key handler can have used a cached recipient while input was pending.
/// Check both that generation and the loaded snapshot under rotation's lock;
/// never write stale ciphertext or a pre-rotation copy of the vault.
fn save_dashboard(app: &App, home: &std::path::Path, expected: &[u8]) -> Result<()> {
    let _generation = crate::store::lock_generation(home)?;
    anyhow::ensure!(
        crypto::recipient_from_identity()? == app.recipient
            && revision(&Vault::load(home)?)? == expected,
        "vault or identity changed — reopen the entry and retry"
    );
    app.vault.save(home)
}

fn event_loop(app: &mut App, home: &std::path::Path) -> Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

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

    drive_events(app, home, &mut terminal, || {
        rx.recv_timeout(std::time::Duration::from_millis(500))
    })
}

fn drive_events<B: ratatui::backend::Backend>(
    app: &mut App,
    home: &std::path::Path,
    terminal: &mut Terminal<B>,
    mut receive: impl FnMut() -> std::result::Result<Event, std::sync::mpsc::RecvTimeoutError>,
) -> Result<()> {
    // Force a first reload: the file could change between startup and entering
    // the event loop. Never stamp an older snapshot with a newer timestamp.
    let mut last_mtime = None;
    let mut loaded_revision = revision(&app.vault)?;
    app.settings = crate::settings::Settings::load(home);

    loop {
        // Watch the vault file for external changes (e.g. a granted
        // `envault request` while this is open).
        let now = vault_mtime(home);
        if now != last_mtime {
            // Only commit the new mtime once the load actually succeeds, so a
            // read that lands mid-write (partial JSON) is retried next tick.
            if let Ok((v, recipient)) = load_snapshot(home) {
                last_mtime = now;
                loaded_revision = revision(&v)?;
                app.reload_vault(v, recipient);
                if app.status_kind == app::StatusKind::Info {
                    app.set_info("vault updated");
                }
            }
        }

        terminal.draw(|f| ui::draw(f, app))?;

        // Wait for input, but wake at least twice a second to re-check the file.
        let key = match receive() {
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
                match save_dashboard(app, home, &loaded_revision) {
                    Ok(()) => loaded_revision = revision(&app.vault)?,
                    Err(e) => {
                        // Discard the unsaved cached mutation; never let a
                        // later edit accidentally commit it after a retry.
                        app.vault = serde_json::from_slice(&loaded_revision)?;
                        if let Ok((v, recipient)) = load_snapshot(home) {
                            loaded_revision = revision(&v)?;
                            app.reload_vault(v, recipient);
                        }
                        app.set_error(format!("save failed: {e:#}"));
                    }
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
                Ok(outcome) => match load_snapshot(home) {
                    Ok((v, recipient)) => {
                        loaded_revision = revision(&v)?;
                        app.after_rotate(outcome.count, v, recipient);
                    }
                    Err(e) => app.set_error(format!("vault reload failed: {e:#}")),
                },
                Err(e) => app.set_error(format!("rotate failed: {e:#}")),
            },
            // Toggling a setting is always gated — including here in the
            // dashboard — so turning the audit log off (or on) requires the
            // system prompt, not just being at the keyboard.
            Some(Effect::ToggleAudit) => {
                match crate::biometric::require("Change the envault audit log setting") {
                    Ok(()) => {
                        app.settings.audit_log = !app.settings.audit_log;
                        persist_settings(app, home, "audit log");
                    }
                    Err(e) => app.set_error(format!("not changed: {e:#}")),
                }
            }
            Some(Effect::ToggleTouchId) => {
                match crate::biometric::require("Change the envault Touch ID setting") {
                    Ok(()) => {
                        app.settings.touch_id = !app.settings.touch_id;
                        persist_settings(app, home, "Touch ID gate");
                    }
                    Err(e) => app.set_error(format!("not changed: {e:#}")),
                }
            }
            Some(Effect::ToggleFill) => {
                match crate::biometric::require("Change the envault browser-fill setting") {
                    Ok(()) => {
                        app.settings.fill = !app.settings.fill;
                        persist_settings(app, home, "browser fill");
                    }
                    Err(e) => app.set_error(format!("not changed: {e:#}")),
                }
            }
        }
        // Do not adopt an unobserved mtime after input: an external rotation
        // can finish while recv_timeout waits, including on a non-saving key.
        // Only a successful snapshot reload above acknowledges a timestamp.
    }
}

fn persist_settings(app: &mut App, home: &std::path::Path, label: &str) {
    let state = if label.contains("audit") {
        app.settings.audit_log
    } else if label.contains("fill") {
        app.settings.fill
    } else {
        app.settings.touch_id
    };
    match app.settings.save(home) {
        Ok(()) => app.set_success(format!("{label} {}", if state { "on" } else { "off" })),
        Err(e) => app.set_error(format!("couldn't save settings: {e:#}")),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;

    struct IsolatedIdentity(tempfile::TempDir);
    impl IsolatedIdentity {
        fn new() -> Self {
            let home = tempfile::TempDir::new().unwrap();
            std::env::set_var("ENVAULT_IDENTITY_FILE", home.path().join("identity.txt"));
            let id = crypto::generate_identity();
            crypto::store_identity(&id, home.path()).unwrap();
            crypto::store_recipient(&id, home.path()).unwrap();
            Vault::default().save(home.path()).unwrap();
            Self(home)
        }
    }
    impl Drop for IsolatedIdentity {
        fn drop(&mut self) {
            std::env::remove_var("ENVAULT_IDENTITY_FILE");
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
    }
    fn open_add(app: &mut App) {
        app.handle_key(key(KeyCode::Char('a')));
        type_text(app, "new-key");
        app.handle_key(key(KeyCode::Tab));
        type_text(app, "synthetic-fresh-value");
    }
    fn app_at(home: &std::path::Path) -> App {
        let (vault, recipient) = load_snapshot(home).unwrap();
        App::new(vault, recipient)
    }
    fn seed(home: &std::path::Path) {
        let mut app = app_at(home);
        let before = revision(&app.vault).unwrap();
        open_add(&mut app);
        app.handle_key(key(KeyCode::Enter));
        save_dashboard(&app, home, &before).unwrap();
    }

    #[test]
    fn dashboard_save_rejects_rotation_during_pending_submit() {
        let _env = crypto::test_env_lock();
        let isolated = IsolatedIdentity::new();
        let home = isolated.0.path();
        seed(home);
        let mut app = app_at(home);
        app.handle_key(key(KeyCode::Char('e')));
        type_text(&mut app, "must-not-save-to-retired-key");
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let mut step = 0;
        let mut rotated_bytes = Vec::new();
        // This callback is the real loop's input-wait boundary: rotation runs
        // after the watcher/draw but before Enter is delivered, with no sleeps.
        drive_events(&mut app, home, &mut terminal, || {
            step += 1;
            if step == 1 {
                crate::commands::rotate::rotate_in_place(home).unwrap();
                rotated_bytes = std::fs::read(paths::vault_file(home)).unwrap();
                Ok(Event::Key(key(KeyCode::Enter)))
            } else {
                Ok(Event::Key(key(KeyCode::Char('q'))))
            }
        })
        .unwrap();
        assert_eq!(
            std::fs::read(paths::vault_file(home)).unwrap(),
            rotated_bytes
        );
        assert!(app.status.contains("save failed"));
        let id = crypto::load_identity().unwrap();
        assert_eq!(
            crypto::decrypt_value(&id, &app.vault.get("new-key").unwrap().cipher).unwrap(),
            "synthetic-fresh-value"
        );
    }

    #[test]
    fn dashboard_nonwriting_key_does_not_acknowledge_unseen_rotation() {
        let _env = crypto::test_env_lock();
        let isolated = IsolatedIdentity::new();
        let home = isolated.0.path();
        let mut app = app_at(home);
        let old_recipient = app.recipient.clone();
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let mut step = 0;
        drive_events(&mut app, home, &mut terminal, || {
            step += 1;
            if step == 1 {
                let old_mtime = vault_mtime(home).unwrap();
                crate::commands::rotate::rotate_in_place(home).unwrap();
                // Ensure observably different metadata even on coarse clocks.
                std::fs::File::options()
                    .write(true)
                    .open(paths::vault_file(home))
                    .unwrap()
                    .set_modified(old_mtime + std::time::Duration::from_secs(2))
                    .unwrap();
                Ok(Event::Key(key(KeyCode::Char('a'))))
            } else {
                // Esc from the add form, then quit.
                Ok(Event::Key(key(if step == 2 {
                    KeyCode::Esc
                } else {
                    KeyCode::Char('q')
                })))
            }
        })
        .unwrap();
        assert_ne!(app.recipient, old_recipient);
        assert_eq!(app.recipient, crypto::recipient_from_identity().unwrap());
        let before = revision(&app.vault).unwrap();
        open_add(&mut app);
        app.handle_key(key(KeyCode::Enter));
        save_dashboard(&app, home, &before).unwrap();
        let id = crypto::load_identity().unwrap();
        let stored = Vault::load(home).unwrap();
        assert_eq!(
            crypto::decrypt_value(&id, &stored.get("new-key").unwrap().cipher).unwrap(),
            "synthetic-fresh-value"
        );
    }

    #[test]
    fn dashboard_checks_identity_even_if_vault_bytes_are_unchanged() {
        let _env = crypto::test_env_lock();
        let isolated = IsolatedIdentity::new();
        let home = isolated.0.path();
        let mut app = app_at(home);
        let before = revision(&app.vault).unwrap();
        open_add(&mut app);
        app.handle_key(key(KeyCode::Enter));
        crypto::store_identity(&crypto::generate_identity(), home).unwrap();
        assert!(save_dashboard(&app, home, &before).is_err());
        assert!(Vault::load(home).unwrap().secrets.is_empty());
    }

    #[test]
    fn dashboard_checks_snapshot_even_if_identity_is_unchanged() {
        let _env = crypto::test_env_lock();
        let isolated = IsolatedIdentity::new();
        let home = isolated.0.path();
        seed(home);
        let mut app = app_at(home);
        let before = revision(&app.vault).unwrap();
        app.handle_key(key(KeyCode::Char('e')));
        // Empty value = metadata-only edit; it must not restore old ciphertext.
        app.handle_key(key(KeyCode::Enter));
        let id = crypto::load_identity().unwrap();
        let mut current = Vault::load(home).unwrap();
        current.secrets[0].cipher =
            crypto::encrypt_value(&id.to_public(), "external-edit").unwrap();
        current.save(home).unwrap();
        let bytes = std::fs::read(paths::vault_file(home)).unwrap();
        assert!(save_dashboard(&app, home, &before).is_err());
        assert_eq!(std::fs::read(paths::vault_file(home)).unwrap(), bytes);
    }
}
