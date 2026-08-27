use crossterm::event::{KeyCode, KeyEvent};

use crate::crypto::encrypt_value;
use crate::store::{is_valid_alias, now_rfc3339, SecretEntry, Vault};

/// Form field order: the two essentials first, optional annotations below.
pub const FIELD_NAMES: [&str; 5] = ["name", "value", "label", "url", "notes"];
const NAME: usize = 0;
const VALUE: usize = 1;
const LABEL: usize = 2;
const URL: usize = 3;
const NOTES: usize = 4;

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
    ConfirmRotate,
    Reveal(String),
    Command(String),
    Help,
}

#[derive(Debug)]
pub enum Effect {
    Save,
    Decrypt { alias: String },
    Copy { alias: String },
    Rotate,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Success,
    Error,
}

pub struct App {
    pub vault: Vault,
    pub recipient: age::x25519::Recipient,
    pub query: String,
    pub selected: usize,
    pub mode: Mode,
    pub status: String,
    pub status_kind: StatusKind,
}

impl App {
    pub fn new(vault: Vault, recipient: age::x25519::Recipient) -> App {
        App {
            vault,
            recipient,
            query: String::new(),
            selected: 0,
            mode: Mode::List,
            status: String::new(),
            status_kind: StatusKind::Info,
        }
    }

    pub fn set_info(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_kind = StatusKind::Info;
    }

    pub fn set_success(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_kind = StatusKind::Success;
    }

    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_kind = StatusKind::Error;
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

    /// Runtime callback after a successful `Effect::Rotate`.
    pub fn after_rotate(&mut self, count: usize, vault: Vault, recipient: age::x25519::Recipient) {
        self.vault = vault;
        self.recipient = recipient;
        self.clamp_selection();
        self.set_success(format!(
            "rotated {count} secret(s) to a new keypair — Keychain will re-ask authorization"
        ));
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Effect> {
        match std::mem::replace(&mut self.mode, Mode::List) {
            Mode::List => self.on_list_key(key),
            Mode::Search => {
                self.on_search_key(key);
                None
            }
            Mode::Reveal(_) => None, // any key returns to List
            Mode::Help => None,      // any key returns to List
            Mode::ConfirmDelete => self.on_confirm_delete(key),
            Mode::ConfirmRotate => self.on_confirm_rotate(key),
            Mode::Command(input) => self.on_command_key(key, input),
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
            KeyCode::Char('?') => {
                self.mode = Mode::Help;
            }
            KeyCode::Char(':') => {
                self.mode = Mode::Command(String::new());
            }
            KeyCode::Char('a') => {
                self.mode = Mode::Add(Form {
                    fields: Default::default(),
                    focus: NAME,
                    editing_alias: None,
                });
            }
            KeyCode::Char('e') => {
                if let Some(alias) = self.selected_alias() {
                    let e = self.vault.get(&alias).expect("selected exists");
                    self.mode = Mode::Edit(Form {
                        fields: [
                            e.alias.clone(),
                            String::new(), // empty value keeps the old cipher
                            e.label.clone(),
                            e.url.clone().unwrap_or_default(),
                            e.notes.clone(),
                        ],
                        focus: VALUE, // name is locked; start on value
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
            KeyCode::Char(c) if ('1'..='9').contains(&c) => {
                let idx = (c as usize) - ('1' as usize);
                if idx < self.visible().len() {
                    self.selected = idx;
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
                self.selected = 0;
                self.clamp_selection();
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

    fn on_confirm_delete(&mut self, key: KeyEvent) -> Option<Effect> {
        self.mode = Mode::List;
        if let KeyCode::Char('y') = key.code {
            if let Some(alias) = self.selected_alias() {
                self.vault.secrets.retain(|s| s.alias != alias);
                self.clamp_selection();
                self.set_success(format!("deleted '{alias}'"));
                return Some(Effect::Save);
            }
        }
        None
    }

    fn on_confirm_rotate(&mut self, key: KeyEvent) -> Option<Effect> {
        self.mode = Mode::List;
        if let KeyCode::Char('y') = key.code {
            self.set_info("rotating keypair…");
            return Some(Effect::Rotate);
        }
        self.set_info("cancelled");
        None
    }

    fn on_command_key(&mut self, key: KeyEvent, mut input: String) -> Option<Effect> {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::List;
            }
            KeyCode::Enter => {
                self.mode = Mode::List;
                return self.run_command(input.trim());
            }
            KeyCode::Backspace => {
                if input.pop().is_none() {
                    self.mode = Mode::List; // backspace on empty exits
                } else {
                    self.mode = Mode::Command(input);
                }
            }
            KeyCode::Char(c) => {
                input.push(c);
                self.mode = Mode::Command(input);
            }
            _ => self.mode = Mode::Command(input),
        }
        None
    }

    fn run_command(&mut self, cmd: &str) -> Option<Effect> {
        match cmd {
            "" => {}
            "rotate" => self.mode = Mode::ConfirmRotate,
            "help" | "?" => self.mode = Mode::Help,
            "q" | "quit" | "exit" => return Some(Effect::Quit),
            other => {
                self.set_error(format!(
                    "unknown command: {other} (try rotate · help · quit)"
                ));
            }
        }
        None
    }

    fn on_form_key(&mut self, key: KeyEvent, mut form: Form, editing: bool) -> Option<Effect> {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::List;
                self.set_info("cancelled");
                return None;
            }
            KeyCode::Tab | KeyCode::Down => {
                form.focus = (form.focus + 1) % form.fields.len();
                if editing && form.focus == NAME {
                    form.focus = VALUE;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                form.focus = (form.focus + form.fields.len() - 1) % form.fields.len();
                if editing && form.focus == NAME {
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
        self.mode = if editing {
            Mode::Edit(form)
        } else {
            Mode::Add(form)
        };
        None
    }

    fn submit_form(&mut self, form: Form, editing: bool) -> Option<Effect> {
        let name = form.fields[NAME].clone();
        let value = form.fields[VALUE].clone();
        let label = form.fields[LABEL].clone();
        let url = form.fields[URL].clone();
        let notes = form.fields[NOTES].clone();
        if editing {
            let target = form.editing_alias.clone().expect("edit has name");
            let cipher = if value.is_empty() {
                None
            } else {
                match encrypt_value(&self.recipient, &value) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        self.set_error(format!("encryption failed: {e}"));
                        self.mode = Mode::Edit(form);
                        return None;
                    }
                }
            };
            if let Some(entry) = self.vault.secrets.iter_mut().find(|s| s.alias == target) {
                entry.label = if label.is_empty() {
                    target.clone()
                } else {
                    label
                };
                entry.url = if url.is_empty() { None } else { Some(url) };
                entry.notes = notes;
                if let Some(c) = cipher {
                    entry.cipher = c;
                }
                entry.updated_at = now_rfc3339();
            }
            self.set_success(format!("updated '{target}'"));
            self.mode = Mode::List;
            return Some(Effect::Save);
        }
        // Add
        if !is_valid_alias(&name) {
            self.set_error("name must be kebab-case: lowercase letters, digits, '-'");
            self.mode = Mode::Add(form);
            return None;
        }
        if self.vault.get(&name).is_some() {
            self.set_error(format!("name '{name}' already exists"));
            self.mode = Mode::Add(form);
            return None;
        }
        if value.is_empty() {
            self.set_error("value must not be empty");
            self.mode = Mode::Add(form);
            return None;
        }
        let cipher = match encrypt_value(&self.recipient, &value) {
            Ok(c) => c,
            Err(e) => {
                self.set_error(format!("encryption failed: {e}"));
                self.mode = Mode::Add(form);
                return None;
            }
        };
        let now = now_rfc3339();
        self.vault
            .insert(SecretEntry {
                label: if label.is_empty() {
                    name.clone()
                } else {
                    label
                },
                alias: name.clone(),
                cipher,
                url: if url.is_empty() { None } else { Some(url) },
                created_at: now.clone(),
                updated_at: now,
                notes,
            })
            .ok();
        self.set_success(format!("added '{name}'"));
        self.mode = Mode::List;
        Some(Effect::Save)
    }
}

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
        assert!(matches!(
            app.handle_key(ch('r')),
            Some(Effect::Decrypt { .. })
        ));
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
        type_str(&mut app, "new-key"); // name field (0)
        app.handle_key(key(KeyCode::Tab)); // value (1)
        type_str(&mut app, "fresh-value-77");
        app.handle_key(key(KeyCode::Tab)); // label (2)
        type_str(&mut app, "New Key");
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
        // edit form opens focused on value (1); name is locked
        app.handle_key(key(KeyCode::Tab)); // label (2)
        type_str(&mut app, "!"); // append to label
        let eff = app.handle_key(key(KeyCode::Enter));
        assert!(matches!(eff, Some(Effect::Save)));
        let entry = app.vault.get("a-key").unwrap();
        assert_eq!(entry.cipher, old_cipher);
        assert!(entry.label.ends_with('!'));
        assert_eq!(decrypt_value(&id, &entry.cipher).unwrap(), "old-value-123");
    }

    #[test]
    fn edit_never_reaches_locked_name_field() {
        let (mut app, _) = app_with(&["a-key"]);
        app.handle_key(ch('e'));
        // BackTab from value (1) wraps to notes (4), skipping name (0)
        app.handle_key(key(KeyCode::BackTab));
        let Mode::Edit(form) = &app.mode else {
            panic!("expected edit mode")
        };
        assert_eq!(form.focus, 4);
        // Tab from notes (4) skips name (0) and lands on value (1)
        app.handle_key(key(KeyCode::Tab));
        let Mode::Edit(form) = &app.mode else {
            panic!("expected edit mode")
        };
        assert_eq!(form.focus, 1);
    }

    #[test]
    fn number_keys_jump_selection() {
        let (mut app, _) = app_with(&["a-key", "b-key", "c-key"]);
        app.handle_key(ch('3'));
        assert_eq!(app.selected_alias().as_deref(), Some("c-key"));
        app.handle_key(ch('1'));
        assert_eq!(app.selected_alias().as_deref(), Some("a-key"));
        app.handle_key(ch('9')); // out of range: no move
        assert_eq!(app.selected_alias().as_deref(), Some("a-key"));
    }

    #[test]
    fn help_opens_and_any_key_closes() {
        let (mut app, _) = app_with(&["a-key"]);
        app.handle_key(ch('?'));
        assert!(matches!(app.mode, Mode::Help));
        app.handle_key(ch('x'));
        assert!(matches!(app.mode, Mode::List));
    }

    #[test]
    fn command_mode_rotate_flow() {
        let (mut app, _) = app_with(&["a-key"]);
        app.handle_key(ch(':'));
        type_str(&mut app, "rotate");
        assert!(app.handle_key(key(KeyCode::Enter)).is_none());
        assert!(matches!(app.mode, Mode::ConfirmRotate));
        let eff = app.handle_key(ch('y'));
        assert!(matches!(eff, Some(Effect::Rotate)));

        // 'n' cancels the confirm
        app.handle_key(ch(':'));
        type_str(&mut app, "rotate");
        app.handle_key(key(KeyCode::Enter));
        assert!(app.handle_key(ch('n')).is_none());
        assert!(matches!(app.mode, Mode::List));
    }

    #[test]
    fn command_mode_quit_unknown_and_escape() {
        let (mut app, _) = app_with(&[]);
        app.handle_key(ch(':'));
        type_str(&mut app, "quit");
        assert!(matches!(
            app.handle_key(key(KeyCode::Enter)),
            Some(Effect::Quit)
        ));

        app.handle_key(ch(':'));
        type_str(&mut app, "bogus");
        assert!(app.handle_key(key(KeyCode::Enter)).is_none());
        assert!(matches!(app.status_kind, StatusKind::Error));
        assert!(app.status.contains("unknown command"), "{}", app.status);

        app.handle_key(ch(':'));
        app.handle_key(key(KeyCode::Esc));
        assert!(matches!(app.mode, Mode::List));
    }

    #[test]
    fn after_rotate_swaps_key_material_and_reports() {
        let (mut app, _) = app_with(&["a-key"]);
        let new_id = generate_identity();
        let new_vault = Vault::default();
        app.after_rotate(1, new_vault, new_id.to_public());
        assert!(matches!(app.status_kind, StatusKind::Success));
        assert!(app.status.contains("rotated 1"), "{}", app.status);
        assert!(app.vault.secrets.is_empty());
    }
}
