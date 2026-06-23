use std::net::IpAddr;

use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};

use rust_shark_core::analysis::{ThreatKind, analyze};
use rust_shark_core::decode::{ColorHint, DecodedPacket, Direction, Layer};

use super::{App, theme};

/// Number of main-table columns (Time, Dir, Process, Host, IP, Proto, Len, Info).
pub const COLUMN_COUNT: usize = 8;

/// Column header labels, indexed the same as [`App::col_visible`].
pub const COLUMN_LABELS: [&str; COLUMN_COUNT] = [
    "Time", "Dir", "Process", "Host", "IP", "Proto", "Len", "Info",
];

/// Per-column width constraints, indexed the same as [`COLUMN_LABELS`]. Host
/// (resolved domain) and IP (address:port) are split into their own columns;
/// Info is the only flexible column and grows to fill the rest.
const COLUMN_WIDTHS: [Constraint; COLUMN_COUNT] = [
    Constraint::Length(13),
    Constraint::Length(6),
    Constraint::Length(12),
    Constraint::Length(20),
    Constraint::Length(22),
    Constraint::Length(5),
    Constraint::Length(5),
    Constraint::Min(20),
];

pub fn render_packet_list(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    // Columns the user has left enabled (request 2). If everything is toggled
    // off, fall back to all columns so the table never renders fully empty.
    let mut vis: Vec<usize> = (0..COLUMN_COUNT).filter(|&i| app.col_visible[i]).collect();
    if vis.is_empty() {
        vis = (0..COLUMN_COUNT).collect();
    }

    let header = Row::new(vis.iter().map(|&i| COLUMN_LABELS[i]).collect::<Vec<_>>())
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
            let dir = pkt.direction(&app.local_ips);
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
            // Row priority: selection → threat → search → anomaly → retransmission
            // → direction. An ordinary row is tinted by direction so inbound
            // (green) vs outbound (blue) is obvious across the whole line; only
            // the rarer states above override it. Unknown direction (e.g. file
            // capture without local IPs) falls back to the protocol color.
            let style = if i == app.selected {
                theme::selected_row()
            } else if let Some(t) = &pkt.threat {
                match t.kind {
                    ThreatKind::RareExternal => {
                        Style::default().fg(theme::BASE_BG).bg(theme::WARN).bold()
                    }
                    _ => Style::default().fg(theme::TEXT_STRONG).bg(theme::ALERT).bold(),
                }
            } else if matches_search {
                theme::search_row()
            } else if anomaly.is_some() {
                Style::default().fg(theme::WARN).bg(zebra).bold()
            } else if pkt.retransmission {
                Style::default().fg(theme::ALERT).bg(zebra)
            } else {
                let fg = match dir {
                    Direction::In => theme::DIR_IN,
                    Direction::Out => theme::DIR_OUT,
                    Direction::Unknown => theme::proto_color(pkt.summary.color_hint),
                };
                Style::default().fg(fg).bg(zebra)
            };

            // Direction marker with a space after the arrow; inherits the row
            // color (which already encodes IN/OUT), just bolded.
            let dir_txt = match dir {
                Direction::In => "\u{25c0} IN",
                Direction::Out => "\u{25b6} OUT",
                Direction::Unknown => "\u{2194}",
            };
            let dir_cell = Cell::from(Span::styled(dir_txt, Style::default().bold()));

            // The bookmark star rides on the Time cell (no dedicated column).
            let is_bookmarked = app.bookmarks.contains(&pkt.number);
            let time_cell = if is_bookmarked {
                Cell::from(Line::from(vec![
                    Span::styled("\u{2605}", Style::default().fg(theme::BOOKMARK)),
                    Span::raw(elapsed),
                ]))
            } else {
                Cell::from(elapsed)
            };

            let proc: String = pkt
                .process
                .as_ref()
                .map(|p| p.name.as_str())
                .unwrap_or("\u{2014}")
                .chars()
                .take(12)
                .collect();

            // Peer split into Host (resolved domain) and IP (addr:port) columns.
            let (remote_ip, remote_pt) = remote_endpoint(pkt, &app.local_ips);
            let host_name = remote_ip
                .and_then(|ip| app.names.resolve(ip))
                .map(|e| e.name)
                .unwrap_or_default();
            let host: String = if host_name.is_empty() {
                "\u{2014}".to_string()
            } else {
                host_name.chars().take(20).collect()
            };
            let ip_str: String = match (remote_ip, remote_pt) {
                (Some(ip), Some(p)) => format!("{ip}:{p}"),
                (Some(ip), None) => ip.to_string(),
                _ => "\u{2014}".to_string(),
            };
            let ip_str: String = ip_str.chars().take(22).collect();

            // Info: drop the leading "sport → dport" token for TCP/UDP (the ports
            // now live in the IP column); prepend a threat or anomaly tag. The
            // original summary.info is untouched so search/filter still see ports.
            let base_info: &str = if matches!(pkt.summary.color_hint, ColorHint::Tcp | ColorHint::Udp)
            {
                strip_leading_ports(&pkt.summary.info)
            } else {
                &pkt.summary.info
            };
            let info_full = match (&pkt.threat, &anomaly) {
                (Some(t), _) => {
                    format!("\u{26a0} [{}] {} — {}", t.kind.label(), base_info, t.detail)
                }
                (None, Some(a)) => format!("\u{26a0} {} [{}]", base_info, a.detail),
                (None, None) => base_info.to_string(),
            };
            let info: String = info_full.chars().take(100).collect();

            let all_cells = [
                time_cell,
                dir_cell,
                Cell::from(proc),
                Cell::from(host),
                Cell::from(ip_str),
                Cell::from(pkt.summary.protocol.clone()),
                Cell::from(pkt.summary.length.to_string()),
                Cell::from(info),
            ];
            let cells: Vec<Cell> = vis.iter().map(|&c| all_cells[c].clone()).collect();

            Some(Row::new(cells).style(style))
        })
        .collect();

    let widths: Vec<Constraint> = vis.iter().map(|&i| COLUMN_WIDTHS[i]).collect();

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
        // Track the selected row (not the viewport top) so the thumb position
        // matches where a click/drag lands on the track — they share the same
        // selected-based mapping.
        let mut sb_state = ScrollbarState::new(visible_count)
            .position(app.selected)
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

/// Remote (non-local) endpoint of the packet as `(ip, port)`. The remote side
/// is chosen by direction: inbound → the source is remote, otherwise the
/// destination. Returns `(None, None)` for non-IP packets (e.g. ARP).
fn remote_endpoint(pkt: &DecodedPacket, local_ips: &[IpAddr]) -> (Option<IpAddr>, Option<u16>) {
    let Some((src, dst)) = pkt.ip_pair() else {
        return (None, None);
    };
    let inbound = matches!(pkt.direction(local_ips), Direction::In);
    let remote_ip = if inbound { src } else { dst };
    (Some(remote_ip), remote_port(pkt, !inbound))
}

/// The transport port on the remote side: destination port when the local host
/// is the sender (`to_dst`), source port when the local host is the receiver.
fn remote_port(pkt: &DecodedPacket, to_dst: bool) -> Option<u16> {
    for l in &pkt.layers {
        match l {
            Layer::Tcp(t) => return Some(if to_dst { t.dst_port } else { t.src_port }),
            Layer::Udp(u) => return Some(if to_dst { u.dst_port } else { u.src_port }),
            _ => {}
        }
    }
    None
}

/// Strip the leading `<sport> \u{2192} <dport> ` token from a TCP/UDP info
/// string, leaving just the meaning (flags/len/etc). Falls back to the original
/// string when the pattern is absent.
fn strip_leading_ports(info: &str) -> &str {
    let Some(arrow) = info.find(" \u{2192} ") else {
        return info;
    };
    let after = &info[arrow + " \u{2192} ".len()..];
    match after.find(' ') {
        Some(sp) => after[sp + 1..].trim_start(),
        None => info,
    }
}

#[cfg(test)]
mod tests {
    use super::strip_leading_ports;

    #[test]
    fn strips_tcp_udp_port_prefix() {
        assert_eq!(
            strip_leading_ports("443 \u{2192} 50000 [SYN] Seq=0 Len=0"),
            "[SYN] Seq=0 Len=0"
        );
        assert_eq!(strip_leading_ports("12345 \u{2192} 53 Len=40"), "Len=40");
    }

    #[test]
    fn leaves_info_without_port_prefix() {
        assert_eq!(
            strip_leading_ports("DNS Q example.com"),
            "DNS Q example.com"
        );
        assert_eq!(strip_leading_ports("Echo Request"), "Echo Request");
    }
}
