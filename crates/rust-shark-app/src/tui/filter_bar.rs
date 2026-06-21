use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use super::{App, InputMode, theme};

pub fn render_filter_bar(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let (text, style) = match app.mode {
        InputMode::FilterInput => {
            let mut display = app.filter_input.clone();
            // Show cursor position
            if app.filter_cursor <= display.len() {
                display.insert(app.filter_cursor, '│');
            }
            (
                format!(" Filter: {}", display),
                Style::default().fg(theme::FILTER_EDIT).bg(theme::BASE_BG),
            )
        }
        InputMode::Search => (
            " Filter: (Ctrl-F search active — see status bar)".to_string(),
            Style::default().fg(theme::TEXT_DIM).bg(theme::BASE_BG),
        ),
        InputMode::Normal => {
            if let Some(ref filter) = app.active_filter {
                let _ = filter; // presence check only
                (
                    format!(" Filter: {} [Applied]", app.filter_input),
                    Style::default().fg(theme::FILTER_ACTIVE).bg(theme::BASE_BG),
                )
            } else {
                (
                    " Filter: (press '/' to filter · d/x panes · z all)".to_string(),
                    Style::default().fg(theme::TEXT_DIM).bg(theme::BASE_BG),
                )
            }
        }
    };

    let paragraph = Paragraph::new(text).style(style);
    frame.render_widget(paragraph, area);
}
