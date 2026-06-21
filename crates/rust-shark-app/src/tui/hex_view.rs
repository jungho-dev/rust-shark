use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use super::{App, theme};

pub fn render_hex_view(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let lines = match app.selected_packet() {
        Some(pkt) => format_hex_dump(&pkt.data),
        None => vec![Line::from(Span::styled("No packet selected", theme::dim()))],
    };

    let visible_height = area.height.saturating_sub(2) as usize; // border
    let scroll = app
        .hex_scroll
        .min(lines.len().saturating_sub(visible_height));
    let visible_lines: Vec<Line> = lines
        .into_iter()
        .skip(scroll)
        .take(visible_height)
        .collect();

    let paragraph = Paragraph::new(visible_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER_DIM))
            .style(theme::base())
            .title(Span::styled(
                " Hex Dump ",
                Style::default().fg(theme::HEADER),
            )),
    );
    frame.render_widget(paragraph, area);
}

fn format_hex_dump(data: &[u8]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;

        // Offset
        let mut parts = vec![Span::styled(format!("{:04x}   ", offset), theme::dim())];

        // Hex bytes
        let mut hex = String::new();
        for (j, byte) in chunk.iter().enumerate() {
            hex.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                hex.push(' ');
            }
        }
        // Pad if less than 16 bytes
        let padding = if chunk.len() <= 8 {
            (16 - chunk.len()) * 3 + 1
        } else {
            (16 - chunk.len()) * 3
        };
        for _ in 0..padding {
            hex.push(' ');
        }

        parts.push(Span::styled(hex, Style::default().fg(theme::ACCENT_TCP)));

        // ASCII
        parts.push(Span::styled("  ", Style::default()));
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..=0x7E).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        parts.push(Span::styled(ascii, Style::default().fg(theme::ACCENT_UDP)));

        lines.push(Line::from(parts));
    }

    lines
}
