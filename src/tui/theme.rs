//! Shared adaptive ANSI palette — resolves against the user's terminal theme,
//! so both the main dashboard and the request window look like one tool.

use ratatui::style::Color;

pub const ACCENT: Color = Color::Cyan;
pub const KEYCAP: Color = Color::Yellow;
pub const DIM: Color = Color::DarkGray;
pub const OK: Color = Color::Green;
pub const ERR: Color = Color::Red;
pub const DOTS: Color = Color::Yellow;
