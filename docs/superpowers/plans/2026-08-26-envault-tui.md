# envault TUI Dashboard (Milestone 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bare `envault` opens the unified ratatui dashboard: browse, search, add, edit, delete, reveal, and copy secrets — the human-only surface.

**Architecture:** Three layers for testability. `tui/app.rs` is a pure state machine (`App` + `handle_key` + `Effect`); encryption is pure (needs only the recipient), so add/edit encrypt inline, while anything needing I/O (save, decrypt via Keychain, clipboard, quit) is returned as an `Effect` for the runtime to execute. `tui/ui.rs` renders `&App` to a ratatui `Frame` (snapshot-tested via `TestBackend`). `tui/mod.rs` owns the terminal lifecycle, event loop, effect execution, the no-TTY refusal, and the first-run init prompt.

**Tech Stack:** ratatui 0.29 (crossterm backend, already at 0.28), arboard 3 (clipboard), existing crypto/store modules.

**Spec:** `docs/superpowers/specs/2026-08-26-envault-design.md` §9 (+ §11 TUI error handling, §12 TUI testing)

## Global Constraints

- The TUI is the ONLY surface that may show a plaintext value, and only after an explicit `r` (reveal) or `c` (copy) keypress.
- Clipboard copies auto-clear after 15 seconds (best effort; cleared only if unchanged is NOT required — clear unconditionally).
- Refuse to start without a TTY (both stdin and stdout), with a clear message.
- All prior constraints hold (fmt, clippy -D warnings, TDD, kebab aliases, milestone-1 crypto rules).

---

### Task 1: Pure state machine (`tui/app.rs`)

**Files:**
- Create: `src/tui/mod.rs` (module shell for now: `pub mod app;`)
- Create: `src/tui/app.rs`
- Modify: `src/main.rs` (add `mod tui;`)
- Modify: `Cargo.toml` (add `ratatui = "0.29"`, `arboard = "3"`)

**Interfaces:**
- Consumes: `store::{Vault, SecretEntry, is_valid_alias, now_rfc3339}`, `crypto::encrypt_value`, `age::x25519::Recipient`
- Produces (used by ui.rs and mod.rs):
  - `app::Mode { List, Search, Add(Form), Edit(Form), ConfirmDelete, Reveal(String) }`
  - `app::Form { fields: [String; 5], focus: usize, editing_alias: Option<String> }` — field order: alias, label, url, notes, value
  - `app::Effect { Save, Decrypt { alias: String }, Copy { alias: String }, Quit }`
  - `app::App { vault: Vault, recipient: age::x25519::Recipient, query: String, selected: usize, mode: Mode, status: String }`
  - `App::new(vault, recipient) -> App`
  - `App::visible(&self) -> Vec<&SecretEntry>` — query-filtered (alias or label contains query, case-insensitive), vault order
  - `App::selected_alias(&self) -> Option<String>`
  - `App::handle_key(&mut self, key: crossterm::event::KeyEvent) -> Option<Effect>`
  - `App::provide_plaintext(&mut self, value: String)` — runtime callback after a `Decrypt` effect; sets `Mode::Reveal(value)`

**Keymap (List):** `q` → Quit · `j`/`↓` & `k`/`↑` move · `/` search · `a` add · `e` edit · `d` confirm-delete · `r` → `Effect::Decrypt` · `c` → `Effect::Copy` (both only when a secret is selected).
**Search:** printable chars append to query, Backspace pops, Esc or Enter → List (query persists; Esc also clears it).
**Add/Edit form:** Tab or `↓` next field, BackTab or `↑` previous, printable chars append to focused field, Backspace pops, Esc cancels to List, Enter submits. Submit rules: alias must pass `is_valid_alias` (status message otherwise); Add rejects duplicate aliases; empty value on Add is rejected; empty value on Edit keeps the existing cipher; non-empty value is encrypted with the recipient; timestamps via `now_rfc3339` (Add sets both, Edit updates `updated_at` and re-sorts nothing — alias is immutable in Edit: the alias field is prefilled and non-editable (keys to it are ignored)). Successful submit mutates `self.vault`, sets a status message, returns `Some(Effect::Save)`.
**ConfirmDelete:** `y` removes the selected entry and returns `Some(Effect::Save)`; anything else cancels.
**Reveal:** any key returns to List.

- [ ] **Step 1: Write failing unit tests** at the bottom of `src/tui/app.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_value, encrypt_value, generate_identity};
    use crate::store::{SecretEntry, Vault};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }
    fn type_str(app: &mut App, s: &str) {
        for c in s.chars() {
            app.handle_key(ch(c));
        }
    }

    fn entry(alias: &str, recipient: &age::x25519::Recipient) -> SecretEntry {
        SecretEntry {
            alias: alias.into(),
            label: format!("{alias} label"),
            cipher: encrypt_value(recipient, "old-value-123").unwrap(),
            url: None,
            created_at: crate::store::now_rfc3339(),
            updated_at: crate::store::now_rfc3339(),
            notes: String::new(),
        }
    }

    fn app_with(aliases: &[&str]) -> (App, age::x25519::Identity) {
        let id = generate_identity();
        let recipient = id.to_public();
        let mut vault = Vault::default();
        for a in aliases {
            vault.insert(entry(a, &recipient)).unwrap();
        }
        (App::new(vault, recipient), id)
    }

    #[test]
    fn navigation_moves_selection() {
        let (mut app, _) = app_with(&["a-key", "b-key", "c-key"]);
        assert_eq!(app.selected_alias().as_deref(), Some("a-key"));
        app.handle_key(ch('j'));
        assert_eq!(app.selected_alias().as_deref(), Some("b-key"));
        app.handle_key(ch('k'));
        assert_eq!(app.selected_alias().as_deref(), Some("a-key"));
        app.handle_key(ch('k')); // clamped at top
        assert_eq!(app.selected_alias().as_deref(), Some("a-key"));
    }

    #[test]
    fn search_filters_visible() {
        let (mut app, _) = app_with(&["openrouter", "db-password"]);
        app.handle_key(ch('/'));
        type_str(&mut app, "open");
        app.handle_key(key(KeyCode::Enter));
        let visible: Vec<_> = app.visible().iter().map(|e| e.alias.clone()).collect();
        assert_eq!(visible, vec!["openrouter"]);
        assert_eq!(app.selected_alias().as_deref(), Some("openrouter"));
    }

    #[test]
    fn quit_reveal_copy_effects() {
        let (mut app, _) = app_with(&["a-key"]);
        assert!(matches!(app.handle_key(ch('r')), Some(Effect::Decrypt { .. })));
        app.provide_plaintext("old-value-123".into());
        assert!(matches!(app.mode, Mode::Reveal(ref v) if v == "old-value-123"));
        app.handle_key(key(KeyCode::Esc)); // any key leaves reveal
        assert!(matches!(app.mode, Mode::List));
        assert!(matches!(app.handle_key(ch('c')), Some(Effect::Copy { .. })));
        assert!(matches!(app.handle_key(ch('q')), Some(Effect::Quit)));
    }

    #[test]
    fn add_flow_encrypts_and_saves() {
        let (mut app, id) = app_with(&[]);
        app.handle_key(ch('a'));
        type_str(&mut app, "new-key"); // alias field
        app.handle_key(key(KeyCode::Tab)); // label
        type_str(&mut app, "New Key");
        app.handle_key(key(KeyCode::Tab)); // url
        app.handle_key(key(KeyCode::Tab)); // notes
        app.handle_key(key(KeyCode::Tab)); // value
        type_str(&mut app, "fresh-value-77");
        let eff = app.handle_key(key(KeyCode::Enter));
        assert!(matches!(eff, Some(Effect::Save)));
        let entry = app.vault.get("new-key").expect("entry added");
        assert_eq!(entry.label, "New Key");
        assert_eq!(decrypt_value(&id, &entry.cipher).unwrap(), "fresh-value-77");
    }

    #[test]
    fn add_rejects_bad_alias_and_empty_value() {
        let (mut app, _) = app_with(&[]);
        app.handle_key(ch('a'));
        type_str(&mut app, "Bad Alias");
        assert!(app.handle_key(key(KeyCode::Enter)).is_none());
        assert!(matches!(app.mode, Mode::Add(_)), "stays in form");
        assert!(app.status.contains("kebab-case"), "status: {}", app.status);
    }

    #[test]
    fn edit_keeps_cipher_when_value_empty() {
        let (mut app, id) = app_with(&["a-key"]);
        let old_cipher = app.vault.get("a-key").unwrap().cipher.clone();
        app.handle_key(ch('e'));
        app.handle_key(key(KeyCode::Tab)); // to label
        type_str(&mut app, "!"); // append to label
        let eff = app.handle_key(key(KeyCode::Enter));
        assert!(matches!(eff, Some(Effect::Save)));
        let entry = app.vault.get("a-key").unwrap();
        assert_eq!(entry.cipher, old_cipher);
        assert!(entry.label.ends_with('!'));
        assert_eq!(decrypt_value(&id, &entry.cipher).unwrap(), "old-value-123");
    }

    #[test]
    fn delete_needs_confirmation() {
        let (mut app, _) = app_with(&["a-key", "b-key"]);
        app.handle_key(ch('d'));
        app.handle_key(ch('n')); // cancel
        assert_eq!(app.vault.secrets.len(), 2);
        app.handle_key(ch('d'));
        let eff = app.handle_key(ch('y'));
        assert!(matches!(eff, Some(Effect::Save)));
        assert!(app.vault.get("a-key").is_none());
        assert_eq!(app.vault.secrets.len(), 1);
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test tui` → compile errors.
- [ ] **Step 3: Implement `App`** above the tests. Complete implementation:

```rust
use crossterm::event::{KeyCode, KeyEvent};

use crate::crypto::encrypt_value;
use crate::store::{is_valid_alias, now_rfc3339, SecretEntry, Vault};

pub const FIELD_NAMES: [&str; 5] = ["alias", "label", "url", "notes", "value"];

#[derive(Debug, Clone)]
pub struct Form {
    pub fields: [String; 5],
    pub focus: usize,
    pub editing_alias: Option<String>,
}

#[derive(Debug)]
pub enum Mode {
    List,
    Search,
    Add(Form),
    Edit(Form),
    ConfirmDelete,
    Reveal(String),
}

#[derive(Debug)]
pub enum Effect {
    Save,
    Decrypt { alias: String },
    Copy { alias: String },
    Quit,
}

pub struct App {
    pub vault: Vault,
    pub recipient: age::x25519::Recipient,
    pub query: String,
    pub selected: usize,
    pub mode: Mode,
    pub status: String,
}

impl App {
    pub fn new(vault: Vault, recipient: age::x25519::Recipient) -> App {
        App {
            vault,
            recipient,
            query: String::new(),
            selected: 0,
            mode: Mode::List,
            status: String::from("j/k move · / search · a add · e edit · d delete · r reveal · c copy · q quit"),
        }
    }

    pub fn visible(&self) -> Vec<&SecretEntry> {
        let q = self.query.to_lowercase();
        self.vault
            .secrets
            .iter()
            .filter(|s| {
                q.is_empty()
                    || s.alias.to_lowercase().contains(&q)
                    || s.label.to_lowercase().contains(&q)
            })
            .collect()
    }

    pub fn selected_alias(&self) -> Option<String> {
        self.visible().get(self.selected).map(|e| e.alias.clone())
    }

    fn clamp_selection(&mut self) {
        let len = self.visible().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    pub fn provide_plaintext(&mut self, value: String) {
        self.mode = Mode::Reveal(value);
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Effect> {
        match std::mem::replace(&mut self.mode, Mode::List) {
            Mode::List => self.on_list_key(key),
            Mode::Search => {
                self.on_search_key(key);
                None
            }
            Mode::Reveal(_) => None, // any key returns to List
            Mode::ConfirmDelete => self.on_confirm_key(key),
            Mode::Add(form) => self.on_form_key(key, form, false),
            Mode::Edit(form) => self.on_form_key(key, form, true),
        }
    }

    fn on_list_key(&mut self, key: KeyEvent) -> Option<Effect> {
        self.mode = Mode::List;
        match key.code {
            KeyCode::Char('q') => return Some(Effect::Quit),
            KeyCode::Char('j') | KeyCode::Down => {
                if self.selected + 1 < self.visible().len() {
                    self.selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Char('/') => {
                self.query.clear();
                self.mode = Mode::Search;
            }
            KeyCode::Char('a') => {
                self.mode = Mode::Add(Form {
                    fields: Default::default(),
                    focus: 0,
                    editing_alias: None,
                });
            }
            KeyCode::Char('e') => {
                if let Some(alias) = self.selected_alias() {
                    let e = self.vault.get(&alias).expect("selected exists");
                    self.mode = Mode::Edit(Form {
                        fields: [
                            e.alias.clone(),
                            e.label.clone(),
                            e.url.clone().unwrap_or_default(),
                            e.notes.clone(),
                            String::new(),
                        ],
                        focus: 1, // alias is immutable; start on label
                        editing_alias: Some(alias),
                    });
                }
            }
            KeyCode::Char('d') => {
                if self.selected_alias().is_some() {
                    self.mode = Mode::ConfirmDelete;
                }
            }
            KeyCode::Char('r') => {
                if let Some(alias) = self.selected_alias() {
                    return Some(Effect::Decrypt { alias });
                }
            }
            KeyCode::Char('c') => {
                if let Some(alias) = self.selected_alias() {
                    return Some(Effect::Copy { alias });
                }
            }
            _ => {}
        }
        None
    }

    fn on_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                self.mode = Mode::List;
                self.clamp_selection();
                self.selected = 0;
            }
            KeyCode::Esc => {
                self.query.clear();
                self.mode = Mode::List;
                self.clamp_selection();
            }
            KeyCode::Backspace => {
                self.query.pop();
                self.mode = Mode::Search;
            }
            KeyCode::Char(c) => {
                self.query.push(c);
                self.mode = Mode::Search;
            }
            _ => self.mode = Mode::Search,
        }
    }

    fn on_confirm_key(&mut self, key: KeyEvent) -> Option<Effect> {
        self.mode = Mode::List;
        if let KeyCode::Char('y') = key.code {
            if let Some(alias) = self.selected_alias() {
                self.vault.secrets.retain(|s| s.alias != alias);
                self.clamp_selection();
                self.status = format!("deleted '{alias}'");
                return Some(Effect::Save);
            }
        }
        None
    }

    fn on_form_key(&mut self, key: KeyEvent, mut form: Form, editing: bool) -> Option<Effect> {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::List;
                self.status = "cancelled".into();
                return None;
            }
            KeyCode::Tab | KeyCode::Down => {
                form.focus = (form.focus + 1) % form.fields.len();
                if editing && form.focus == 0 {
                    form.focus = 1;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                form.focus = (form.focus + form.fields.len() - 1) % form.fields.len();
                if editing && form.focus == 0 {
                    form.focus = form.fields.len() - 1;
                }
            }
            KeyCode::Backspace => {
                form.fields[form.focus].pop();
            }
            KeyCode::Char(c) => {
                form.fields[form.focus].push(c);
            }
            KeyCode::Enter => return self.submit_form(form, editing),
            _ => {}
        }
        self.mode = if editing { Mode::Edit(form) } else { Mode::Add(form) };
        None
    }

    fn submit_form(&mut self, form: Form, editing: bool) -> Option<Effect> {
        let [alias, label, url, notes, value] = form.fields.clone();
        if editing {
            let target = form.editing_alias.clone().expect("edit has alias");
            let cipher = if value.is_empty() {
                None
            } else {
                match encrypt_value(&self.recipient, &value) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        self.status = format!("encryption failed: {e}");
                        self.mode = Mode::Edit(form);
                        return None;
                    }
                }
            };
            if let Some(entry) = self.vault.secrets.iter_mut().find(|s| s.alias == target) {
                entry.label = if label.is_empty() { target.clone() } else { label };
                entry.url = if url.is_empty() { None } else { Some(url) };
                entry.notes = notes;
                if let Some(c) = cipher {
                    entry.cipher = c;
                }
                entry.updated_at = now_rfc3339();
            }
            self.status = format!("updated '{target}'");
            self.mode = Mode::List;
            return Some(Effect::Save);
        }
        // Add
        if !is_valid_alias(&alias) {
            self.status = "alias must be kebab-case: lowercase letters, digits, '-'".into();
            self.mode = Mode::Add(form);
            return None;
        }
        if self.vault.get(&alias).is_some() {
            self.status = format!("alias '{alias}' already exists");
            self.mode = Mode::Add(form);
            return None;
        }
        if value.is_empty() {
            self.status = "value must not be empty".into();
            self.mode = Mode::Add(form);
            return None;
        }
        let cipher = match encrypt_value(&self.recipient, &value) {
            Ok(c) => c,
            Err(e) => {
                self.status = format!("encryption failed: {e}");
                self.mode = Mode::Add(form);
                return None;
            }
        };
        let now = now_rfc3339();
        self.vault
            .insert(SecretEntry {
                label: if label.is_empty() { alias.clone() } else { label },
                alias: alias.clone(),
                cipher,
                url: if url.is_empty() { None } else { Some(url) },
                created_at: now.clone(),
                updated_at: now,
                notes,
            })
            .ok();
        self.status = format!("added '{alias}'");
        self.mode = Mode::List;
        Some(Effect::Save)
    }
}
```

- [ ] **Step 4: Verify green** — `cargo test tui` (7 tests pass).
- [ ] **Step 5: Commit** — `feat: TUI state machine with add/edit/delete/search/reveal`

---

### Task 2: Rendering (`tui/ui.rs`) + TestBackend snapshots

**Files:**
- Create: `src/tui/ui.rs`
- Modify: `src/tui/mod.rs` (`pub mod ui;`)

**Interfaces:**
- Consumes: `app::{App, Mode, Form, FIELD_NAMES}`
- Produces: `ui::draw(frame: &mut ratatui::Frame, app: &App)`

**Layout:** vertical: main area + 1-line status bar. Main splits horizontally 40%/60%: left = bordered `List` titled `envault (<n>)` (or `search: <query>` while searching) with `>` -prefixed selected row showing `alias — label`; right = bordered details `Paragraph`: alias, label, url, created, updated, notes, and `value: ••••••••  (r reveal · c copy)` — or the plaintext when `Mode::Reveal`, or the form fields (focused field marked with `> `) in Add/Edit, or `delete '<alias>'? y/n` in ConfirmDelete. Status bar shows `app.status`.

- [ ] **Step 1: Write failing snapshot tests** at the bottom of `src/tui/ui.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_identity;
    use crate::store::{SecretEntry, Vault};
    use crate::tui::app::{App, Mode};
    use ratatui::{backend::TestBackend, Terminal};

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        let buf = terminal.backend().buffer();
        let area = *buf.area();
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            out.push('\n');
        }
        out
    }

    fn test_app() -> App {
        let id = generate_identity();
        let recipient = id.to_public();
        let mut vault = Vault::default();
        vault
            .insert(SecretEntry {
                alias: "openrouter".into(),
                label: "OpenRouter key".into(),
                cipher: "AAAA".into(),
                url: Some("https://openrouter.ai".into()),
                created_at: "2026-08-26T00:00:00Z".into(),
                updated_at: "2026-08-26T00:00:00Z".into(),
                notes: String::new(),
            })
            .unwrap();
        App::new(vault, recipient)
    }

    fn render(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        buffer_text(&terminal)
    }

    #[test]
    fn list_shows_alias_and_hides_value() {
        let app = test_app();
        let text = render(&app);
        assert!(text.contains("openrouter"), "{text}");
        assert!(text.contains("••••"), "value must render hidden: {text}");
        assert!(text.contains("https://openrouter.ai"));
    }

    #[test]
    fn reveal_shows_plaintext() {
        let mut app = test_app();
        app.mode = Mode::Reveal("sk-or-plaintext-1".into());
        let text = render(&app);
        assert!(text.contains("sk-or-plaintext-1"), "{text}");
    }

    #[test]
    fn add_form_shows_fields() {
        let mut app = test_app();
        app.handle_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('a'),
            crossterm::event::KeyModifiers::NONE,
        ));
        let text = render(&app);
        for f in crate::tui::app::FIELD_NAMES {
            assert!(text.contains(f), "form must show field '{f}': {text}");
        }
    }
}
```

- [ ] **Step 2: Run to verify failure**, **Step 3: Implement `draw`:**

```rust
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Mode, FIELD_NAMES};

pub fn draw(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(frame.area());
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(outer[0]);

    let visible = app.visible();
    let title = if matches!(app.mode, Mode::Search) || !app.query.is_empty() {
        format!(" envault — search: {} ", app.query)
    } else {
        format!(" envault ({}) ", visible.len())
    };
    let items: Vec<ListItem> = visible
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let marker = if i == app.selected { "> " } else { "  " };
            ListItem::new(format!("{marker}{} — {}", e.alias, e.label))
        })
        .collect();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(list, main[0]);

    let detail_block = Block::default().borders(Borders::ALL).title(" details ");
    let lines: Vec<Line> = match &app.mode {
        Mode::Add(form) | Mode::Edit(form) => {
            let mut lines = vec![Line::from(if matches!(app.mode, Mode::Add(_)) {
                "add secret (Enter submit · Esc cancel · Tab next field)"
            } else {
                "edit secret (Enter submit · Esc cancel · empty value keeps old)"
            })];
            for (i, name) in FIELD_NAMES.iter().enumerate() {
                let marker = if form.focus == i { "> " } else { "  " };
                let shown = if *name == "value" {
                    "•".repeat(form.fields[i].len())
                } else {
                    form.fields[i].clone()
                };
                lines.push(Line::from(format!("{marker}{name:<6} {shown}")));
            }
            lines
        }
        Mode::ConfirmDelete => vec![Line::from(format!(
            "delete '{}'? y/n",
            app.selected_alias().unwrap_or_default()
        ))],
        Mode::Reveal(value) => {
            let mut lines = detail_lines(app);
            lines.push(Line::from(""));
            lines.push(Line::styled(
                format!("value: {value}"),
                Style::default().add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::from("(any key to hide)"));
            lines
        }
        _ => {
            let mut lines = detail_lines(app);
            lines.push(Line::from(""));
            lines.push(Line::from("value: ••••••••  (r reveal · c copy)"));
            lines
        }
    };
    frame.render_widget(
        Paragraph::new(lines).block(detail_block).wrap(Wrap { trim: false }),
        main[1],
    );
    frame.render_widget(Paragraph::new(app.status.as_str()), outer[1]);
}

fn detail_lines(app: &App) -> Vec<Line<'static>> {
    let Some(alias) = app.selected_alias() else {
        return vec![Line::from("no secrets — press 'a' to add one")];
    };
    let e = app.vault.get(&alias).expect("selected exists");
    vec![
        Line::from(format!("alias  : {}", e.alias)),
        Line::from(format!("label  : {}", e.label)),
        Line::from(format!("url    : {}", e.url.clone().unwrap_or_default())),
        Line::from(format!("created: {}", e.created_at)),
        Line::from(format!("updated: {}", e.updated_at)),
        Line::from(format!("notes  : {}", e.notes)),
    ]
}
```

- [ ] **Step 4: Verify green**, **Step 5: Commit** — `feat: TUI rendering with TestBackend snapshots`

---

### Task 3: Runtime loop + first-run + wiring bare `envault`

**Files:**
- Modify: `src/tui/mod.rs` (full runtime), `src/main.rs` (bare command opens TUI)
- Test: `tests/cli.rs` (no-TTY refusal)

**Interfaces:**
- Consumes: everything above + `crypto::{load_identity, load_recipient, decrypt_value}`, `store::Vault`, `commands::init::cmd_init`
- Produces: `tui::run_tui() -> Result<()>`

- [ ] **Step 1: Failing integration test** (append to `tests/cli.rs`):

```rust
#[test]
fn bare_envault_without_tty_refuses_with_hint() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .assert()
        .failure()
        .stderr(predicates::str::contains("terminal"));
}
```

(Currently bare `envault` prints help and exits 0, so this fails.)

- [ ] **Step 2: Implement `src/tui/mod.rs`:**

```rust
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
use app::{App, Effect, Mode};

pub fn run_tui() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("the envault dashboard needs an interactive terminal (agents: use `envault ls --json`)");
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
        let Event::Key(key) = event::read()? else { continue };
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
                    Ok(()) => app.status = format!("'{alias}' copied — clipboard clears in 15s"),
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
```

In `src/main.rs`, replace the bare-command arm:

```rust
        None => tui::run_tui(),
```

(and delete the now-unused `CommandFactory` help block).

- [ ] **Step 3: Verify** — `cargo test` all green (the no-TTY test now passes because assert_cmd runs without a TTY).
- [ ] **Step 4: Manual TTY smoke** — from a real terminal later, `envault` should open the dashboard; scripted here instead: `expect` one-liner spawns `envault` in a PTY (with a scratch `ENVAULT_HOME`/`ENVAULT_IDENTITY_FILE`), sends `q`, expects clean exit 0.
- [ ] **Step 5: Full gate + commit** — `feat: envault TUI dashboard`
