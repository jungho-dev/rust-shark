use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};

use rust_shark_core::analysis::analyze;

use super::{App, theme};

pub fn render_packet_list(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let header = Row::new(vec![
        "#",
        "Time",
        "Source",
        "Destination",
        "Proto",
        "Len",
        "Info",
    ])
    .style(theme::header_row())
    .bottom_margin(0);

    let visible_count = app.visible_count();
    let table_height = area.height.saturating_sub(3) as usize; // border + header

    // Virtual scrolling: compute visible range
    let scroll_offset = if app.selected >= table_height {
        app.selected - table_height + 1
    } else {
        0
    };

    let visible_range_start = scroll_offset;
    let visible_range_end = (scroll_offset + table_height).min(visible_count);

    let rows: Vec<Row> = (visible_range_start..visible_range_end)
        .filter_map(|i| {
            let pkt = app.visible_packet(i)?;
            let elapsed = pkt.timestamp.format("%H:%M:%S%.3f").to_string();
            let anomaly = analyze(pkt);
            let matches_search = app.search_re.as_ref().is_some_and(|re| {
                re.is_match(&pkt.summary.info)
                    || re.is_match(&pkt.summary.source)
                    || re.is_match(&pkt.summary.destination)
            });

            // Zebra striping (by absolute row index) separates dense rows.
            let zebra = if i % 2 == 0 {
                theme::BASE_BG
            } else {
                theme::ZEBRA_BG
            };
            let style = if i == app.selected {
                theme::selected_row()
            } else if matches_search {
                theme::search_row()
            } else if anomaly.is_some() {
                Style::default().fg(theme::WARN).bg(zebra).bold()
            } else if pkt.retransmission {
                Style::default().fg(theme::ALERT).bg(zebra)
            } else {
                Style::default()
                    .fg(theme::proto_color(pkt.summary.color_hint))
                    .bg(zebra)
            };

            let is_bookmarked = app.bookmarks.contains(&pkt.number);
            let num_cell = if is_bookmarked {
                Cell::from(Line::from(vec![
                    Span::styled("\u{2605}", Style::default().fg(theme::BOOKMARK)),
                    Span::raw(pkt.number.to_string()),
                ]))
            } else {
                Cell::from(format!(" {}", pkt.number))
            };
            let info_full = match &anomaly {
                Some(a) => format!("\u{26a0} {} [{}]", pkt.summary.info, a.detail),
                None => pkt.summary.info.clone(),
            };
            // Char-safe truncation (info may contain multi-byte glyphs).
            let info: String = info_full.chars().take(70).collect();

            Some(
                Row::new(vec![
                    num_cell,
                    Cell::from(elapsed),
                    Cell::from(pkt.summary.source.clone()),
                    Cell::from(pkt.summary.destination.clone()),
                    Cell::from(pkt.summary.protocol.clone()),
                    Cell::from(pkt.summary.length.to_string()),
                    Cell::from(info),
                ])
                .style(style),
            )
        })
        .collect();

    let widths = [
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Length(15),
        Constraint::Length(15),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Min(20),
    ];

    let title = format!(" Packets ({visible_count}) ");
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(theme::BORDER_DIM))
                .style(theme::base())
                .title(Span::styled(title, Style::default().fg(theme::HEADER))),
        );

    frame.render_widget(table, area);

    // Vertical scrollbar on the right border, shown only when the list overflows
    // its viewport. Tracks the same virtual-scroll offset as the table.
    if visible_count > table_height {
        let mut sb_state = ScrollbarState::new(visible_count)
            .position(scroll_offset)
            .viewport_content_length(table_height);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_style(Style::default().fg(theme::BORDER_DIM))
            .thumb_style(Style::default().fg(theme::HEADER));
        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut sb_state,
        );
    }
}
