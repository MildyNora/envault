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
use app::{App, Effect, VaultChange};

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
    app.settings = crate::settings::Settings::load(home);

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
            Some(Effect::Save(change)) => persist_vault_change(app, home, *change),
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
        // Our own writes (save/rotate) just changed the file; adopt the new
        // mtime so the watcher above doesn't treat them as an external change.
        last_mtime = vault_mtime(home);
    }
}

fn persist_vault_change(app: &mut App, home: &std::path::Path, change: VaultChange) {
    let saved = Vault::transaction_for_recipient(home, &app.recipient, |vault, _recipient| {
        match change {
            VaultChange::Insert(entry) => vault.insert(entry)?,
            VaultChange::Update {
                expected,
                mut updated,
                replace_cipher,
            } => {
                let stored = vault
                    .secrets
                    .iter_mut()
                    .find(|stored| stored.alias == updated.alias)
                    .context("secret was removed before the edit could be saved")?;
                anyhow::ensure!(
                    *stored == expected,
                    "secret changed after the edit was opened — reopen it and retry"
                );
                if !replace_cipher {
                    updated.cipher.clone_from(&stored.cipher);
                }
                *stored = updated;
            }
            VaultChange::Delete(expected) => {
                let stored = vault
                    .get(&expected.alias)
                    .context("secret was removed before deletion")?;
                anyhow::ensure!(
                    *stored == expected,
                    "secret changed before deletion — review it and retry"
                );
                vault.secrets.retain(|entry| entry.alias != expected.alias);
            }
        }
        Ok(())
    });
    match saved {
        Ok(((), vault)) => app.reload_vault(vault),
        Err(error) => {
            if let Ok(vault) = Vault::load(home) {
                app.reload_vault(vault);
            }
            app.set_error(format!("save failed: {error:#}"));
        }
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
    use crate::store::{now_rfc3339, SecretEntry};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use tempfile::TempDir;

    fn entry(alias: &str) -> SecretEntry {
        SecretEntry {
            alias: alias.into(),
            label: alias.into(),
            cipher: "synthetic-cipher".into(),
            url: None,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            notes: String::new(),
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

    #[test]
    fn dashboard_save_preserves_an_external_addition() {
        let _env = crypto::test_env_lock();
        let home = TempDir::new().unwrap();
        std::env::set_var("ENVAULT_IDENTITY_FILE", home.path().join("identity.txt"));
        let identity = crypto::generate_identity();
        crypto::store_identity(&identity, home.path()).unwrap();
        Vault::default().save(home.path()).unwrap();
        let recipient = identity.to_public();
        let mut app = App::new(Vault::load(home.path()).unwrap(), recipient);

        Vault::transaction(home.path(), |vault| vault.insert(entry("external"))).unwrap();
        persist_vault_change(
            &mut app,
            home.path(),
            VaultChange::Insert(entry("dashboard")),
        );

        let stored = Vault::load(home.path()).unwrap();
        assert!(stored.get("external").is_some());
        assert!(stored.get("dashboard").is_some());
        std::env::remove_var("ENVAULT_IDENTITY_FILE");
    }

    #[test]
    fn dashboard_rejects_a_pending_add_after_identity_rotation() {
        let _env = crypto::test_env_lock();
        let home = TempDir::new().unwrap();
        let identity_file = home.path().join("identity.txt");
        std::env::set_var("ENVAULT_IDENTITY_FILE", &identity_file);
        let old_identity = crypto::generate_identity();
        crypto::store_identity(&old_identity, home.path()).unwrap();
        crypto::store_recipient(&old_identity, home.path()).unwrap();
        Vault::default().save(home.path()).unwrap();

        let mut app = App::new(Vault::load(home.path()).unwrap(), old_identity.to_public());
        app.handle_key(key(KeyCode::Char('a')));
        type_text(&mut app, "queued-key");
        app.handle_key(key(KeyCode::Tab));
        type_text(&mut app, "synthetic-queued-value");

        crate::commands::rotate::rotate_in_place(home.path()).unwrap();
        let change = match app.handle_key(key(KeyCode::Enter)) {
            Some(Effect::Save(change)) => change,
            _ => panic!("expected save effect"),
        };
        persist_vault_change(&mut app, home.path(), *change);

        assert!(app.status.contains("save failed"), "status: {}", app.status);
        assert!(Vault::load(home.path())
            .unwrap()
            .get("queued-key")
            .is_none());
        std::env::remove_var("ENVAULT_IDENTITY_FILE");
    }

    #[test]
    fn dashboard_metadata_edit_does_not_restore_a_stale_cipher() {
        let _env = crypto::test_env_lock();
        let home = TempDir::new().unwrap();
        let identity_file = home.path().join("identity.txt");
        std::env::set_var("ENVAULT_IDENTITY_FILE", &identity_file);
        let identity = crypto::generate_identity();
        crypto::store_identity(&identity, home.path()).unwrap();
        crypto::store_recipient(&identity, home.path()).unwrap();
        let mut initial = Vault::default();
        let mut original = entry("editable");
        original.cipher = crypto::encrypt_value(&identity.to_public(), "original-value").unwrap();
        initial.insert(original).unwrap();
        initial.save(home.path()).unwrap();

        let mut app = App::new(Vault::load(home.path()).unwrap(), identity.to_public());
        app.handle_key(key(KeyCode::Char('e')));
        app.handle_key(key(KeyCode::Tab));
        type_text(&mut app, " updated");

        let external_cipher =
            crypto::encrypt_value(&identity.to_public(), "external-value").unwrap();
        Vault::transaction(home.path(), |vault| {
            let stored = vault.get("editable").unwrap().clone();
            vault.secrets.retain(|entry| entry.alias != "editable");
            vault.insert(SecretEntry {
                cipher: external_cipher.clone(),
                updated_at: now_rfc3339(),
                ..stored
            })
        })
        .unwrap();

        let change = match app.handle_key(key(KeyCode::Enter)) {
            Some(Effect::Save(change)) => change,
            _ => panic!("expected save effect"),
        };
        persist_vault_change(&mut app, home.path(), *change);

        let stored = Vault::load(home.path()).unwrap();
        assert_eq!(stored.get("editable").unwrap().cipher, external_cipher);
        std::env::remove_var("ENVAULT_IDENTITY_FILE");
    }
}
