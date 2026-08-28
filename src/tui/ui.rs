use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Mode, StatusKind, COMMANDS, FIELD_NAMES};
use super::theme::{ACCENT, DIM, DOTS, ERR, KEYCAP, OK};

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
        Mode::Help => draw_help_overlay(frame, area, app),
        Mode::Command(cl) => draw_command_palette(frame, outer[3], &cl.input, cl.sel),
        Mode::ConfirmDelete => draw_confirm_popup(
            frame,
            area,
            "Delete this secret?",
            &format!(
                "'{}' will be removed permanently. This cannot be undone.",
                app.selected_alias().unwrap_or_default()
            ),
        ),
        Mode::ConfirmRotate => draw_confirm_popup(
            frame,
            area,
            "Rotate the vault keypair?",
            "Re-encrypts every secret to a fresh key and revokes every \
             Keychain grant — macOS will ask you to Always Allow again.",
        ),
        _ => {}
    }
}

/// Command palette: a small list of `:` commands, filtered by what's typed,
/// floating just above the command line, with the highlighted row marked.
fn draw_command_palette(frame: &mut Frame, cmdline_area: Rect, input: &str, sel: usize) {
    let matches = crate::tui::app::command_matches(input);
    if matches.is_empty() {
        return;
    }
    let rows = matches.len() as u16;
    let height = rows + 2; // borders
    let width: u16 = 60;
    // sit directly above the command line
    let y = cmdline_area.y.saturating_sub(height);
    let x = cmdline_area.x;
    let area = Rect {
        x,
        y,
        width: width.min(cmdline_area.width),
        height,
    };
    frame.render_widget(Clear, area);
    let items: Vec<ListItem> = matches
        .iter()
        .enumerate()
        .map(|(row, &idx)| {
            let (name, desc) = COMMANDS[idx];
            let selected = row == sel;
            let marker = if selected { "▌" } else { " " };
            let name_style = if selected {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().add_modifier(Modifier::BOLD)
            };
            ListItem::new(Line::from(vec![
                Span::styled(marker, Style::default().fg(ACCENT)),
                Span::styled(format!(":{name:<8}"), name_style),
                Span::styled(desc.to_string(), Style::default().fg(DIM)),
            ]))
        })
        .collect();
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ACCENT))
                .title(Span::styled(
                    " commands ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
        ),
        area,
    );
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

    let mut items: Vec<ListItem> = visible
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
        .collect();

    // The "＋ add new secret" row sits below the last secret and is selectable.
    let add_selected = app.on_add_row();
    let add_bar = if add_selected { "▌" } else { " " };
    let add_style = if add_selected {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(DIM)
    };
    items.push(ListItem::new(Line::from(vec![
        Span::styled(add_bar, Style::default().fg(ACCENT)),
        Span::styled("＋ ", Style::default().fg(KEYCAP)),
        Span::styled("add new secret", add_style),
    ])));

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
                if i == NAME_IDX {
                    let tag = if editing {
                        "  (locked — names can't change)"
                    } else {
                        "  (permanent)"
                    };
                    spans.push(Span::styled(tag, Style::default().fg(DIM)));
                }
                lines.push(Line::from(spans));
            }
            // "information session": explain the focused field.
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("ℹ ", Style::default().fg(ACCENT)),
                Span::styled(
                    crate::tui::app::FIELD_HELP[form.focus],
                    Style::default().fg(DIM),
                ),
            ]));
            if form.focus == NAME_IDX && !editing {
                lines.push(Line::styled(
                    "  the name is locked once created — choose it carefully.",
                    Style::default().fg(KEYCAP),
                ));
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
        // The add row is selected (or the vault is empty).
        let headline = if app.vault.secrets.is_empty() {
            "No secrets yet."
        } else {
            "Add a new secret."
        };
        return (
            " add ".into(),
            vec![
                Line::styled(headline, Style::default().add_modifier(Modifier::BOLD)),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Press ", Style::default().fg(DIM)),
                    Span::styled(
                        "Enter",
                        Style::default().fg(KEYCAP).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" or ", Style::default().fg(DIM)),
                    Span::styled(
                        "→",
                        Style::default().fg(KEYCAP).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" to add — the agent-facing", Style::default().fg(DIM)),
                ]),
                Line::styled(
                    "way is `envault request` (a request window).",
                    Style::default().fg(DIM),
                ),
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
            spans.extend(hint("↑↓", "pick"));
            spans.extend(hint("Tab", "complete"));
            spans.extend(hint("Enter", "run"));
            spans.extend(hint("Esc", "cancel"));
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
    if let Mode::Command(cl) = &app.mode {
        let line = Line::from(vec![
            Span::styled(
                ":",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(cl.input.clone()),
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
    // Wide enough for the body, and text wraps so nothing is ever clipped.
    let popup = centered_rect(area, 62, 9);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(""),
        Line::styled(format!("  {body}"), Style::default().fg(DIM)),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("y", Style::default().fg(OK).add_modifier(Modifier::BOLD)),
            Span::styled(" yes     ", Style::default().fg(DIM)),
            Span::styled("n", Style::default().fg(ERR).add_modifier(Modifier::BOLD)),
            Span::styled(" / any other key  no", Style::default().fg(DIM)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
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

fn draw_help_overlay(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(area, 68, 30);
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
    let head = |t: &str| {
        Line::styled(
            format!("  {t}"),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )
    };
    let lines = vec![
        head("Keys"),
        key("↑ / ↓ j k", "move selection"),
        key("1-9", "jump to secret"),
        key("/", "search"),
        key("a / e / d", "add · edit · delete"),
        key("r / c", "reveal · copy (clears in 15s)"),
        Line::from(""),
        head("Commands  (: opens a searchable palette)"),
        key(":rotate", "re-key the vault (revokes Keychain grants)"),
        key(
            ":audit",
            &format!("audit log — now {}", on_off(app.settings.audit_log)),
        ),
        key(
            ":touchid",
            &format!("Touch ID gate — now {}", on_off(app.settings.touch_id)),
        ),
        key(
            ":fill",
            &format!("browser fill — now {}", on_off(app.settings.fill)),
        ),
        key(":help / :quit", "this screen · exit"),
        Line::from(""),
        Line::styled(
            "  fill ON lets `envault fill` type secrets into a loopback browser,",
            Style::default().fg(DIM),
        ),
        Line::styled(
            "  but a local process can spoof the target — keep OFF unless needed.",
            Style::default().fg(DIM),
        ),
        Line::from(""),
        head("What agents can see"),
        Line::styled(
            "  Protected: values never enter an agent's context, files, or",
            Style::default().fg(OK),
        ),
        Line::styled(
            "  logs. Agents get names + ciphers only; run output is masked.",
            Style::default().fg(OK),
        ),
        Line::styled(
            "  Bypassed: a process YOU launch via `envault run` holds the",
            Style::default().fg(ERR),
        ),
        Line::styled(
            "  real value and could leak it over the network or to a file;",
            Style::default().fg(ERR),
        ),
        Line::styled(
            "  masking only covers its stdout. :rotate revokes old trust.",
            Style::default().fg(ERR),
        ),
        Line::from(""),
        Line::styled("  Press any key to close.", Style::default().fg(DIM)),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ACCENT))
                .title(Span::styled(
                    " help & security ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
        ),
        popup,
    );
}

fn on_off(b: bool) -> &'static str {
    if b {
        "ON"
    } else {
        "off"
    }
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
    fn help_overlay_lists_keys_commands_and_bypass() {
        let mut app = test_app();
        app.mode = Mode::Help;
        let text = render(&app);
        assert!(text.contains("reveal"), "{text}");
        assert!(text.contains(":rotate"), "commands listed: {text}");
        assert!(
            text.contains("never") || text.contains("aliases"),
            "agent explainer present: {text}"
        );
        // the honest "what's bypassed" boundary must be surfaced
        assert!(text.contains("Bypassed"), "bypass section: {text}");
        assert!(
            text.contains("network") || text.contains("leak"),
            "bypass explains exfiltration: {text}"
        );
    }

    #[test]
    fn command_palette_lists_commands_with_descriptions() {
        use crate::tui::app::CommandLine;
        let mut app = test_app();
        app.mode = Mode::Command(CommandLine {
            input: "r".into(),
            sel: 0,
        });
        let text = render(&app);
        assert!(text.contains(":r"), "command prompt shown: {text}");
        assert!(text.contains("rotate"), "palette lists rotate: {text}");
        assert!(
            text.contains("revokes"),
            "palette shows description: {text}"
        );
    }

    #[test]
    fn add_form_explains_name_is_locked() {
        let mut app = test_app();
        app.handle_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('a'),
            crossterm::event::KeyModifiers::NONE,
        ));
        let text = render(&app);
        // focus starts on name → its help line warns about permanence
        assert!(
            text.contains("locked once created") || text.contains("cannot be renamed"),
            "name-locked notice: {text}"
        );
    }

    #[test]
    fn list_shows_add_row_below_secrets() {
        let text = render(&test_app());
        let lines: Vec<&str> = text.lines().collect();
        let secret_row = lines.iter().position(|l| l.contains("openrouter")).unwrap();
        let add_row = lines
            .iter()
            .position(|l| l.contains("add new secret"))
            .expect("add row present");
        assert!(
            add_row > secret_row,
            "add row sits below the secrets: {text}"
        );
    }

    #[test]
    fn rotate_popup_text_not_truncated() {
        let mut app = test_app();
        app.mode = Mode::ConfirmRotate;
        let text = render(&app);
        // the full sentence must appear un-clipped (wrapping allowed)
        assert!(text.contains("Re-encrypts"), "{text}");
        assert!(
            text.contains("revokes") && text.contains("Keychain"),
            "rotate body must show completely: {text}"
        );
    }

    #[test]
    fn empty_vault_onboards() {
        let id = generate_identity();
        let app = App::new(Vault::default(), id.to_public());
        let text = render(&app);
        assert!(
            text.contains("No secrets yet"),
            "onboarding headline: {text}"
        );
        assert!(text.contains("add new secret"), "add row present: {text}");
    }

    #[test]
    fn narrow_terminal_hides_banner_but_still_renders() {
        // banner auto-hides under 30 rows / narrow width; list still shows
        let text = render_sized(&test_app(), 60, 12);
        assert!(text.contains("openrouter"), "{text}");
    }
}
