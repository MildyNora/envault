pub mod app;
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

fn event_loop(app: &mut App, home: &std::path::Path) -> Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    loop {
        terminal.draw(|f| ui::draw(f, app))?;
        let Event::Key(key) = event::read()? else {
            continue;
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
                    app.status = format!("save failed: {e:#}");
                }
            }
            Some(Effect::Decrypt { alias }) => match decrypt(app, &alias) {
                Ok(value) => app.provide_plaintext(value),
                Err(e) => app.status = format!("decrypt failed: {e:#}"),
            },
            Some(Effect::Copy { alias }) => match decrypt(app, &alias) {
                Ok(value) => match copy_with_autoclear(value) {
                    Ok(()) => {
                        app.status = format!("'{alias}' copied — clipboard clears in 15s");
                    }
                    Err(e) => app.status = format!("clipboard failed: {e:#}"),
                },
                Err(e) => app.status = format!("decrypt failed: {e:#}"),
            },
        }
    }
}

fn decrypt(app: &App, alias: &str) -> Result<String> {
    let entry = app.vault.get(alias).context("entry vanished")?;
    let identity = crypto::load_identity()?;
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
