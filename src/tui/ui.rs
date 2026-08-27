use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Mode, StatusKind, FIELD_NAMES};

// Adaptive ANSI palette — resolves against the user's terminal theme.
const ACCENT: Color = Color::Cyan;
const KEYCAP: Color = Color::Yellow;
const DIM: Color = Color::DarkGray;
const OK: Color = Color::Green;
const ERR: Color = Color::Red;
const DOTS: Color = Color::Yellow;

// Big block wordmark ("envault"), colored + filled.
const BANNER: &str = r#"
 ███████ ███    ██ ██    ██  █████  ██    ██ ██    ████████
 ██      ████   ██ ██    ██ ██   ██ ██    ██ ██       ██
 █████   ██ ██  ██ ██    ██ ███████ ██    ██ ██       ██
 ██      ██  ██ ██  ██  ██  ██   ██ ██    ██ ██       ██
 ███████ ██   ████   ████   ██   ██  ██████  ███████  ██
"#;

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    // Banner only when there's comfortable vertical room.
    let banner_h: u16 = if area.height >= 20 { 7 } else { 0 };

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_h),
            Constraint::Min(3),
            Constraint::Length(1), // footer key-guide
            Constraint::Length(1), // status / command line
        ])
        .split(area);

    if banner_h > 0 {
        draw_banner(frame, outer[0], app);
    }

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(outer[1]);

    draw_list(frame, main[0], app);
    draw_details(frame, main[1], app);
    draw_footer(frame, outer[2], app);
    draw_status(frame, outer[3], app);

    // Overlays paint on top.
    match &app.mode {
        Mode::Help => draw_help_overlay(frame, area),
        Mode::ConfirmDelete => draw_confirm_popup(
            frame,
            area,
            &format!("Delete '{}'?", app.selected_alias().unwrap_or_default()),
            "This removes the secret permanently.",
        ),
        Mode::ConfirmRotate => draw_confirm_popup(
            frame,
            area,
            "Rotate the vault keypair?",
            "Re-encrypts every secret and revokes Keychain grants.",
        ),
        _ => {}
    }
}

fn draw_banner(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines: Vec<Line> = BANNER
        .lines()
        .skip(1) // leading newline
        .map(|l| {
            Line::styled(
                l.to_string(),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )
        })
        .collect();
    lines.push(Line::from(vec![
        Span::styled(
            format!(" {} secrets", app.vault.secrets.len()),
            Style::default().fg(ACCENT),
        ),
        Span::styled("  ~/.envault", Style::default().fg(DIM)),
    ]));
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_list(frame: &mut Frame, area: Rect, app: &App) {
    let visible = app.visible();
    let searching = matches!(app.mode, Mode::Search);
    let title = if searching || !app.query.is_empty() {
        Line::from(vec![
            Span::styled(" search: ", Style::default().fg(DIM)),
            Span::styled(app.query.clone(), Style::default().fg(KEYCAP)),
            Span::styled(" ", Style::default()),
        ])
    } else {
        Line::styled(
            " secrets ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )
    };

    let items: Vec<ListItem> = if visible.is_empty() {
        vec![ListItem::new(Line::styled(
            "  empty — press 'a' or run `envault add`",
            Style::default().fg(DIM),
        ))]
    } else {
        visible
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let selected = i == app.selected;
                let bar = if selected { "▌" } else { " " };
                let num = i + 1;
                let mut spans = vec![
                    Span::styled(bar, Style::default().fg(ACCENT)),
                    Span::styled(
                        format!("{num} "),
                        Style::default().fg(if selected { KEYCAP } else { DIM }),
                    ),
                ];
                let name_style = if selected {
                    Style::default().add_modifier(Modifier::BOLD).fg(ACCENT)
                } else {
                    Style::default().add_modifier(Modifier::BOLD)
                };
                spans.push(Span::styled(e.alias.clone(), name_style));
                ListItem::new(Line::from(spans))
            })
            .collect()
    };

    let border = if searching { KEYCAP } else { ACCENT };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border))
            .title(title),
    );
    frame.render_widget(list, area);
}

fn draw_details(frame: &mut Frame, area: Rect, app: &App) {
    let (title, lines): (String, Vec<Line>) = match &app.mode {
        Mode::Add(form) | Mode::Edit(form) => {
            let editing = matches!(app.mode, Mode::Edit(_));
            let title = if editing {
                " edit ".into()
            } else {
                " add ".into()
            };
            let mut lines = vec![Line::styled(
                if editing {
                    "Enter save · Esc cancel · empty value keeps old"
                } else {
                    "Enter save · Esc cancel · Tab next field"
                },
                Style::default().fg(DIM),
            )];
            for (i, fname) in FIELD_NAMES.iter().enumerate() {
                if i == LABEL {
                    lines.push(Line::styled("─ optional ─", Style::default().fg(DIM)));
                }
                let focused = form.focus == i;
                let marker = if focused { "▌" } else { " " };
                let locked = editing && i == NAME_IDX;
                let shown = if i == VALUE_IDX {
                    "•".repeat(form.fields[i].len())
                } else {
                    form.fields[i].clone()
                };
                let key_style = if focused {
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(DIM)
                };
                let mut spans = vec![
                    Span::styled(marker, Style::default().fg(ACCENT)),
                    Span::styled(format!("{fname:<7}"), key_style),
                    Span::raw(shown),
                ];
                if locked {
                    spans.push(Span::styled("  (locked)", Style::default().fg(DIM)));
                }
                lines.push(Line::from(spans));
            }
            (title, lines)
        }
        _ => detail_view(app),
    };

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(DIM))
                .title(Span::styled(
                    title,
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

const NAME_IDX: usize = 0;
const VALUE_IDX: usize = 1;
const LABEL: usize = 2;

fn detail_view(app: &App) -> (String, Vec<Line<'static>>) {
    let Some(alias) = app.selected_alias() else {
        return (
            " details ".into(),
            vec![
                Line::styled(
                    "No secrets yet.",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Line::from(""),
                Line::styled("Add one with:", Style::default().fg(DIM)),
                Line::styled("  a", Style::default().fg(KEYCAP)),
                Line::styled("  or `envault add <name>`", Style::default().fg(DIM)),
            ],
        );
    };
    let e = app.vault.get(&alias).expect("selected exists");
    let field = |k: &str| Span::styled(format!("{k:<8}"), Style::default().fg(DIM));

    // name, then value directly below.
    let mut lines = vec![Line::from(vec![
        field("name"),
        Span::styled(
            e.alias.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ])];

    if let Mode::Reveal(value) = &app.mode {
        lines.push(Line::from(vec![
            field("value"),
            Span::styled(
                value.clone(),
                Style::default().fg(KEYCAP).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::styled(
            "         (any key to hide)",
            Style::default().fg(DIM),
        ));
    } else {
        lines.push(Line::from(vec![
            field("value"),
            Span::styled("••••••••", Style::default().fg(DOTS)),
            Span::styled("  age-encrypted", Style::default().fg(DIM)),
        ]));
        lines.push(Line::from(vec![
            Span::raw("         "),
            Span::styled("r", Style::default().fg(KEYCAP)),
            Span::styled(" reveal · ", Style::default().fg(DIM)),
            Span::styled("c", Style::default().fg(KEYCAP)),
            Span::styled(" copy (15s)", Style::default().fg(DIM)),
        ]));
    }

    lines.push(Line::styled("─ optional ─", Style::default().fg(DIM)));
    lines.push(Line::from(vec![
        field("label"),
        Span::raw(if e.label.is_empty() {
            "—".into()
        } else {
            e.label.clone()
        }),
    ]));
    let mut url_spans = vec![
        field("url"),
        Span::raw(match &e.url {
            Some(u) => u.clone(),
            None => "—".into(),
        }),
    ];
    if e.url.is_some() {
        url_spans.push(Span::styled("  ✓ guarded", Style::default().fg(OK)));
    }
    lines.push(Line::from(url_spans));
    lines.push(Line::from(vec![
        field("notes"),
        Span::raw(if e.notes.is_empty() {
            "—".into()
        } else {
            e.notes.clone()
        }),
    ]));
    lines.push(Line::from(vec![
        field("time"),
        Span::styled(
            format!(
                "created {} · updated {}",
                rel_time(&e.created_at),
                rel_time(&e.updated_at)
            ),
            Style::default().fg(DIM),
        ),
    ]));
    (" details ".into(), lines)
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let hint = |k: &str, label: &str| {
        vec![
            Span::styled(
                k.to_string(),
                Style::default().fg(KEYCAP).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {label}  "), Style::default().fg(DIM)),
        ]
    };
    let mut spans = Vec::new();
    match app.mode {
        Mode::Search => {
            spans.extend(hint("type", "filter"));
            spans.extend(hint("Enter", "apply"));
            spans.extend(hint("Esc", "clear"));
        }
        Mode::Add(_) | Mode::Edit(_) => {
            spans.extend(hint("Tab", "next"));
            spans.extend(hint("Enter", "save"));
            spans.extend(hint("Esc", "cancel"));
        }
        Mode::Command(_) => {
            spans.extend(hint("Enter", "run"));
            spans.extend(hint("Esc", "cancel"));
            spans.push(Span::styled(
                "rotate · help · quit",
                Style::default().fg(DIM),
            ));
        }
        _ => {
            spans.extend(hint("↑↓", "move"));
            spans.extend(hint("/", "search"));
            spans.extend(hint("a", "add"));
            spans.extend(hint("e", "edit"));
            spans.extend(hint("d", "del"));
            spans.extend(hint(":", "cmd"));
            spans.extend(hint("?", "help"));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    if let Mode::Command(input) = &app.mode {
        let line = Line::from(vec![
            Span::styled(
                ":",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(input.clone()),
            Span::styled("_", Style::default().fg(ACCENT)),
        ]);
        frame.render_widget(Paragraph::new(line), area);
        return;
    }
    let color = match app.status_kind {
        StatusKind::Info => DIM,
        StatusKind::Success => OK,
        StatusKind::Error => ERR,
    };
    let prefix = match app.status_kind {
        StatusKind::Success => "✔ ",
        StatusKind::Error => "✖ ",
        StatusKind::Info => "",
    };
    frame.render_widget(
        Paragraph::new(Line::styled(
            format!("{prefix}{}", app.status),
            Style::default().fg(color),
        ))
        .alignment(Alignment::Right),
        area,
    );
}

fn draw_confirm_popup(frame: &mut Frame, area: Rect, title: &str, body: &str) {
    let popup = centered_rect(area, 52, 7);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(""),
        Line::styled(format!("  {body}"), Style::default().fg(DIM)),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("y", Style::default().fg(OK).add_modifier(Modifier::BOLD)),
            Span::styled(" yes    ", Style::default().fg(DIM)),
            Span::styled("n", Style::default().fg(ERR).add_modifier(Modifier::BOLD)),
            Span::styled(" / any key  no", Style::default().fg(DIM)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ERR))
                .title(Span::styled(
                    format!(" {title} "),
                    Style::default().fg(ERR).add_modifier(Modifier::BOLD),
                )),
        ),
        popup,
    );
}

fn draw_help_overlay(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(area, 60, 18);
    frame.render_widget(Clear, popup);
    let key = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(
                format!("  {k:<10}"),
                Style::default().fg(KEYCAP).add_modifier(Modifier::BOLD),
            ),
            Span::styled(d.to_string(), Style::default().fg(DIM)),
        ])
    };
    let lines = vec![
        Line::styled(
            "  Keys",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        key("↑ / ↓ j k", "move selection"),
        key("1-9", "jump to secret"),
        key("/", "search"),
        key("a / e / d", "add · edit · delete"),
        key("r / c", "reveal · copy (clears in 15s)"),
        Line::from(""),
        Line::styled(
            "  Commands  (:)",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        key(":rotate", "re-key the vault (revokes Keychain grants)"),
        key(":help", "this screen"),
        key(":quit", "exit"),
        Line::from(""),
        Line::styled(
            "  Agents see names only — never your values.",
            Style::default().fg(OK),
        ),
        Line::styled("  Press any key to close.", Style::default().fg(DIM)),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ACCENT))
                .title(Span::styled(
                    " help ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
        ),
        popup,
    );
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

/// Coarse "Nd ago" / "Nh ago" from an RFC3339 timestamp. Falls back to the
/// raw date on parse failure — never panics.
fn rel_time(ts: &str) -> String {
    let parsed = chrono::DateTime::parse_from_rfc3339(ts);
    let Ok(then) = parsed else {
        return ts.split('T').next().unwrap_or(ts).to_string();
    };
    let secs = (chrono::Utc::now() - then.with_timezone(&chrono::Utc)).num_seconds();
    if secs < 0 {
        return "just now".into();
    }
    match secs as u64 {
        0..=59 => "just now".into(),
        s @ 60..=3599 => format!("{}m ago", s / 60),
        s @ 3600..=86399 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
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

    fn render_sized(app: &App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        buffer_text(&terminal)
    }

    #[test]
    fn list_numbers_names_and_hides_value() {
        let app = test_app();
        let text = render(&app);
        assert!(text.contains("openrouter"), "{text}");
        assert!(text.contains("1 openrouter"), "numbered list: {text}");
        assert!(text.contains("••••"), "value must render hidden: {text}");
        // "name" is the human label now, not "alias"
        assert!(text.contains("name"), "{text}");
        assert!(
            !text.contains("alias"),
            "human UI must not say 'alias': {text}"
        );
    }

    #[test]
    fn banner_and_guarded_badge_and_relative_time() {
        let text = render(&test_app());
        // ASCII banner present (block glyphs) and guarded badge on the URL row
        assert!(text.contains('█'), "banner glyphs expected: {text}");
        assert!(text.contains("guarded"), "url guard badge: {text}");
        assert!(text.contains("ago"), "relative timestamp: {text}");
    }

    #[test]
    fn value_row_is_directly_below_name() {
        let text = render(&test_app());
        let lines: Vec<&str> = text.lines().collect();
        let name_row = lines.iter().position(|l| l.contains("name")).unwrap();
        let value_row = lines.iter().position(|l| l.contains("value")).unwrap();
        assert_eq!(value_row, name_row + 1, "value must sit right below name");
        // optional annotations come after the value
        let label_row = lines.iter().position(|l| l.contains("label")).unwrap();
        assert!(label_row > value_row, "annotations below value");
    }

    #[test]
    fn reveal_shows_plaintext() {
        let mut app = test_app();
        app.mode = Mode::Reveal("sk-or-plaintext-1".into());
        let text = render(&app);
        assert!(text.contains("sk-or-plaintext-1"), "{text}");
    }

    #[test]
    fn add_form_shows_fields_in_order() {
        let mut app = test_app();
        app.handle_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('a'),
            crossterm::event::KeyModifiers::NONE,
        ));
        let text = render(&app);
        for f in crate::tui::app::FIELD_NAMES {
            assert!(text.contains(f), "form must show field '{f}': {text}");
        }
        let lines: Vec<&str> = text.lines().collect();
        let name_row = lines.iter().position(|l| l.contains("name")).unwrap();
        let value_row = lines.iter().position(|l| l.contains("value")).unwrap();
        let label_row = lines.iter().position(|l| l.contains("label")).unwrap();
        assert!(
            name_row < value_row && value_row < label_row,
            "field order: {text}"
        );
    }

    #[test]
    fn help_overlay_lists_keys_and_commands() {
        let mut app = test_app();
        app.mode = Mode::Help;
        let text = render(&app);
        assert!(text.contains("reveal"), "{text}");
        assert!(text.contains(":rotate"), "commands listed: {text}");
        assert!(
            text.contains("never") || text.contains("aliases"),
            "agent explainer present: {text}"
        );
    }

    #[test]
    fn command_line_shows_prompt() {
        let mut app = test_app();
        app.mode = Mode::Command("rot".into());
        let text = render(&app);
        assert!(text.contains(":rot"), "command prompt shown: {text}");
    }

    #[test]
    fn empty_vault_onboards() {
        let id = generate_identity();
        let app = App::new(Vault::default(), id.to_public());
        let text = render(&app);
        assert!(text.contains("envault add"), "onboarding hint: {text}");
    }

    #[test]
    fn narrow_terminal_hides_banner_but_still_renders() {
        // banner auto-hides under 30 rows / narrow width; list still shows
        let text = render_sized(&test_app(), 60, 12);
        assert!(text.contains("openrouter"), "{text}");
    }
}
