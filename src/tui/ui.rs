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
        Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
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
