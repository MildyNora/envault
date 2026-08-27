//! The request window: a stripped-down, single-purpose screen an agent pops
//! when it needs a secret it doesn't have. The human grants (pastes a value)
//! or declines (with a note back to the agent). The agent never sees the value.

use crossterm::event::{KeyCode, KeyEvent};

use super::theme::{ACCENT, DIM, DOTS, ERR, KEYCAP, OK};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui::Frame;

/// What the agent asked for (read-only in the window).
#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub name: String,
    pub label: String,
    pub reason: String,
    /// Identity the agent claimed via `--agent` (or a default).
    pub agent: String,
    /// The real calling process, for cross-checking the claim.
    pub caller: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Granted(String),  // the pasted value
    Declined(String), // a note back to the agent
    Cancelled,
}

#[derive(Debug, PartialEq, Eq)]
enum Field {
    Value,
    Note,
}

pub struct RequestApp {
    pub meta: RequestMeta,
    pub value: String,
    pub note: String,
    field: Field,
}

impl RequestApp {
    pub fn new(meta: RequestMeta) -> RequestApp {
        RequestApp {
            meta,
            value: String::new(),
            note: String::new(),
            field: Field::Value,
        }
    }

    pub fn declining(&self) -> bool {
        self.field == Field::Note
    }

    /// Returns Some(outcome) when the window should close.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Outcome> {
        match self.field {
            Field::Value => match key.code {
                KeyCode::Esc => return Some(Outcome::Cancelled),
                KeyCode::Enter => {
                    if !self.value.is_empty() {
                        return Some(Outcome::Granted(self.value.clone()));
                    }
                }
                // `n` decides to decline — but only when the value box is still
                // empty, so it can't hijack a key that begins with 'n'.
                KeyCode::Char('n') if self.value.is_empty() => {
                    self.field = Field::Note;
                }
                KeyCode::Char(c) => self.value.push(c),
                KeyCode::Backspace => {
                    self.value.pop();
                }
                _ => {}
            },
            Field::Note => match key.code {
                KeyCode::Esc => self.field = Field::Value, // back to the value box
                KeyCode::Enter => return Some(Outcome::Declined(self.note.clone())),
                KeyCode::Char(c) => self.note.push(c),
                KeyCode::Backspace => {
                    self.note.pop();
                }
                _ => {}
            },
        }
        None
    }
}

pub fn draw(frame: &mut Frame, app: &RequestApp) {
    let area = centered(frame.area(), 72, 20);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " envault · secret request ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(inner);

    let m = &app.meta;
    let field = |k: &str| Span::styled(format!("  {k:<13}"), Style::default().fg(DIM));
    let mut lines = vec![
        Line::styled(
            "  An agent is asking you to add a secret.",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
        Line::from(vec![
            field("requested by"),
            Span::styled(m.agent.clone(), Style::default().fg(KEYCAP)),
        ]),
        Line::from(vec![
            field("process"),
            Span::styled(m.caller.clone(), Style::default().fg(DIM)),
        ]),
        Line::from(""),
        Line::from(vec![
            field("name"),
            Span::styled(
                m.name.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![field("label"), Span::raw(disp(&m.label))]),
        Line::from(vec![field("reason"), Span::raw(disp(&m.reason))]),
        Line::from(""),
    ];

    if app.declining() {
        lines.push(Line::styled(
            "  Declining — the agent will see this note:",
            Style::default().fg(ERR),
        ));
        lines.push(Line::from(vec![
            field("note"),
            Span::raw(app.note.clone()),
            Span::styled("▏", Style::default().fg(ACCENT)),
        ]));
    } else {
        let dots = "•".repeat(app.value.chars().count());
        lines.push(Line::from(vec![
            field("value"),
            Span::styled("▌", Style::default().fg(ACCENT)),
            Span::styled(dots, Style::default().fg(DOTS)),
            Span::styled(
                format!("  ({} chars)", app.value.chars().count()),
                Style::default().fg(DIM),
            ),
        ]));
        lines.push(Line::styled(
            "                paste the key here, then press Enter",
            Style::default().fg(DIM),
        ));
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), rows[0]);

    // footer hint
    let hint = if app.declining() {
        Line::from(vec![
            keycap("Enter"),
            Span::styled(" send note   ", Style::default().fg(DIM)),
            keycap("Esc"),
            Span::styled(" back to value", Style::default().fg(DIM)),
        ])
    } else {
        Line::from(vec![
            keycap("Enter"),
            Span::styled(" grant   ", Style::default().fg(DIM)),
            keycap("n"),
            Span::styled(" decline   ", Style::default().fg(DIM)),
            keycap("Esc"),
            Span::styled(" cancel", Style::default().fg(DIM)),
            Span::styled(
                "      the agent never sees the value",
                Style::default().fg(OK),
            ),
        ])
    };
    frame.render_widget(Paragraph::new(hint), rows[1]);
}

fn keycap(k: &str) -> Span<'static> {
    Span::styled(
        k.to_string(),
        Style::default().fg(KEYCAP).add_modifier(Modifier::BOLD),
    )
}

fn disp(s: &str) -> String {
    if s.is_empty() {
        "—".into()
    } else {
        s.to_string()
    }
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{backend::TestBackend, Terminal};

    fn meta() -> RequestMeta {
        RequestMeta {
            name: "openrouter".into(),
            label: "OpenRouter API key".into(),
            reason: "needed to call OpenRouter for summaries".into(),
            agent: "Claude Code".into(),
            caller: "node (pid 4242)".into(),
        }
    }
    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }
    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }
    fn typ(app: &mut RequestApp, s: &str) {
        for c in s.chars() {
            app.handle_key(ch(c));
        }
    }

    #[test]
    fn paste_and_enter_grants() {
        let mut app = RequestApp::new(meta());
        typ(&mut app, "sk-or-v1-xyz");
        assert_eq!(
            app.handle_key(key(KeyCode::Enter)),
            Some(Outcome::Granted("sk-or-v1-xyz".into()))
        );
    }

    #[test]
    fn empty_enter_does_nothing() {
        let mut app = RequestApp::new(meta());
        assert_eq!(app.handle_key(key(KeyCode::Enter)), None);
    }

    #[test]
    fn n_on_empty_starts_decline_then_note_sends() {
        let mut app = RequestApp::new(meta());
        assert_eq!(app.handle_key(ch('n')), None);
        assert!(app.declining());
        typ(&mut app, "use OpenAI instead");
        assert_eq!(
            app.handle_key(key(KeyCode::Enter)),
            Some(Outcome::Declined("use OpenAI instead".into()))
        );
    }

    #[test]
    fn n_after_typing_is_a_value_char_not_decline() {
        let mut app = RequestApp::new(meta());
        typ(&mut app, "abc"); // value now non-empty
        app.handle_key(ch('n'));
        assert!(!app.declining(), "n must be literal once value has content");
        assert_eq!(app.value, "abcn");
    }

    #[test]
    fn esc_cancels_and_esc_in_note_returns() {
        let mut app = RequestApp::new(meta());
        app.handle_key(ch('n')); // into note
        app.handle_key(key(KeyCode::Esc)); // back to value
        assert!(!app.declining());
        assert_eq!(app.handle_key(key(KeyCode::Esc)), Some(Outcome::Cancelled));
    }

    #[test]
    fn renders_agent_name_and_masks_value() {
        let mut app = RequestApp::new(meta());
        typ(&mut app, "secret123");
        let mut t = Terminal::new(TestBackend::new(90, 26)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer();
        let area = *buf.area();
        let mut text = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("Claude Code"), "shows agent: {text}");
        assert!(text.contains("openrouter"), "shows name: {text}");
        assert!(text.contains("reason"), "shows reason label: {text}");
        assert!(!text.contains("secret123"), "value must be masked: {text}");
        assert!(text.contains("•"), "masked dots: {text}");
    }
}
