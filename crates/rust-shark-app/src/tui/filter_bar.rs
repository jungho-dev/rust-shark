use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use rust_shark_core::decode::Direction;

use super::packet_list::COLUMN_LABELS;
use super::{App, InputMode, theme};

pub fn render_filter_bar(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    // Column-visibility editor (request 2) draws its own multi-span line.
    if app.mode == InputMode::ColumnConfig {
        let mut spans = vec![Span::styled(
            " Columns: ",
            Style::default().fg(theme::HEADER).bg(theme::BASE_BG),
        )];
        for (i, label) in COLUMN_LABELS.iter().enumerate() {
            let on = app.col_visible[i];
            let style = if on {
                Style::default().fg(theme::FILTER_ACTIVE).bg(theme::BASE_BG)
            } else {
                Style::default().fg(theme::TEXT_DIM).bg(theme::BASE_BG)
            };
            spans.push(Span::styled(
                format!("[{}]{}{}  ", i + 1, label, if on { "" } else { " (off)" }),
                style,
            ));
        }
        spans.push(Span::styled(
            "— 1-6 toggle · Esc done",
            Style::default().fg(theme::TEXT_DIM).bg(theme::BASE_BG),
        ));
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }

    let (text, style) = match app.mode {
        InputMode::FilterInput => {
            let mut display = app.filter_input.clone();
            // Show cursor position
            if display.is_char_boundary(app.filter_cursor) {
                display.insert(app.filter_cursor, '\u{2502}');
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
            let dir_tag = match app.dir_filter {
                Some(Direction::In) => "  [IN only]",
                Some(Direction::Out) => "  [OUT only]",
                _ => "",
            };
            if app.active_filter.is_some() {
                (
                    format!(" Filter: {} [Applied]{dir_tag}", app.filter_input),
                    Style::default().fg(theme::FILTER_ACTIVE).bg(theme::BASE_BG),
                )
            } else if !dir_tag.is_empty() {
                (
                    format!(" Filter:{dir_tag} · i/o IN/OUT · '/' filter · 'c' columns"),
                    Style::default().fg(theme::FILTER_ACTIVE).bg(theme::BASE_BG),
                )
            } else {
                (
                    " Filter: type text · 'threat' alerts · i/o IN/OUT · '/' edit · 'c' cols"
                        .to_string(),
                    Style::default().fg(theme::TEXT_DIM).bg(theme::BASE_BG),
                )
            }
        }
        InputMode::ColumnConfig => unreachable!("handled by the early return above"),
    };

    let paragraph = Paragraph::new(text).style(style);
    frame.render_widget(paragraph, area);
}
