//! Centralized 256-color modern-dark palette and shared styles.
//!
//! HARD invariant: every color in the TUI is a `Color::Indexed(n)` sourced
//! from this module. No named 16-colors, no `Color::Rgb`. Indices are chosen
//! from the xterm-256 cube and are safe on Windows Terminal.

use ratatui::style::{Color, Modifier, Style};

use rust_shark_core::decode::ColorHint;

// ---- Base surfaces ------------------------------------------------------
/// Calm near-black application/panel background.
pub const BASE_BG: Color = Color::Indexed(234);
/// One step lighter: header-row band, status/throughput strips.
pub const SURFACE_BG: Color = Color::Indexed(236);
/// Alternating packet-row background for zebra striping (just above BASE_BG).
pub const ZEBRA_BG: Color = Color::Indexed(235);
/// Status bar background strip.
pub const STATUS_BG: Color = Color::Indexed(237);
/// Quiet panel border for unfocused frames and overlays.
pub const BORDER_DIM: Color = Color::Indexed(238);

// ---- Text ---------------------------------------------------------------
/// Soft white default foreground (not harsh).
pub const TEXT: Color = Color::Indexed(252);
/// Bright white for strong emphasis / selected-row text.
pub const TEXT_STRONG: Color = Color::Indexed(231);
/// Muted/secondary text: chrome columns, placeholders, offsets.
pub const TEXT_DIM: Color = Color::Indexed(244);
/// Column-header label foreground.
pub const HEADER: Color = Color::Indexed(250);

// ---- Selection / highlight bands ---------------------------------------
/// Selected-row background (deep teal-blue); reserved, used nowhere else.
pub const SEL_BG: Color = Color::Indexed(24);
/// Selected-row foreground (bright white).
pub const SEL_FG: Color = Color::Indexed(231);
/// Search-match row / search prompt background (amber band).
pub const SEARCH_BG: Color = Color::Indexed(178);
/// Foreground on the amber search band (dark for contrast).
pub const SEARCH_FG: Color = Color::Indexed(234);
/// Inbound direction marker — packets arriving to the local host (bright green).
pub const DIR_IN: Color = Color::Indexed(78);
/// Outbound direction marker — packets the local host sends (blue).
pub const DIR_OUT: Color = Color::Indexed(39);

// ---- Protocol accents ---------------------------------------------------
/// TCP (bright azure). Also hex byte column + throughput sparkline.
pub const ACCENT_TCP: Color = Color::Indexed(39);
/// UDP (fresh green). Also hex ASCII column + stream server lines.
pub const ACCENT_UDP: Color = Color::Indexed(78);
/// DNS + ARP (warm amber).
pub const ACCENT_DNS_ARP: Color = Color::Indexed(179);
/// ICMP / ICMPv6 (magenta-violet).
pub const ACCENT_ICMP: Color = Color::Indexed(170);
/// TLS (periwinkle), distinct from TCP azure.
pub const ACCENT_TLS: Color = Color::Indexed(111);
/// Detail-tree layer header lines (bright cyan).
pub const DETAIL_HEADER: Color = Color::Indexed(81);

// ---- Semantic state -----------------------------------------------------
/// Anomaly rows / warning glyphs (amber-orange).
pub const WARN: Color = Color::Indexed(208);
/// Retransmission rows, error status, retransmission banner (calm red).
pub const ALERT: Color = Color::Indexed(203);
/// Bookmark star glyph + bookmark accents (gold).
pub const BOOKMARK: Color = Color::Indexed(220);
/// Filter applied (live green).
pub const FILTER_ACTIVE: Color = Color::Indexed(78);
/// Filter editing (warm yellow).
pub const FILTER_EDIT: Color = Color::Indexed(221);

// ---- Shared styles ------------------------------------------------------
/// Default panel base: soft white on calm dark.
pub fn base() -> Style {
    Style::default().fg(TEXT).bg(BASE_BG)
}

/// Column-header row style (label fg on raised surface, bold).
pub fn header_row() -> Style {
    Style::default()
        .fg(HEADER)
        .bg(SURFACE_BG)
        .add_modifier(Modifier::BOLD)
}

/// Selected packet-list row band.
pub fn selected_row() -> Style {
    Style::default()
        .fg(SEL_FG)
        .bg(SEL_BG)
        .add_modifier(Modifier::BOLD)
}

/// Search-match packet-list row band.
pub fn search_row() -> Style {
    Style::default().fg(SEARCH_FG).bg(SEARCH_BG)
}

/// Dim/secondary text style.
pub fn dim() -> Style {
    Style::default().fg(TEXT_DIM)
}

/// Status-bar normal style.
pub fn status_normal() -> Style {
    Style::default().fg(TEXT).bg(STATUS_BG)
}

/// Status-bar error style.
pub fn status_error() -> Style {
    Style::default().fg(ALERT).bg(STATUS_BG)
}

/// Map a decode `ColorHint` to its protocol accent color.
pub fn proto_color(hint: ColorHint) -> Color {
    match hint {
        ColorHint::Tcp => ACCENT_TCP,
        ColorHint::Udp => ACCENT_UDP,
        ColorHint::Arp => ACCENT_DNS_ARP,
        ColorHint::Dns => ACCENT_DNS_ARP,
        ColorHint::Icmp => ACCENT_ICMP,
        ColorHint::Tls => ACCENT_TLS,
        ColorHint::Retransmission => ALERT,
        ColorHint::Other => TEXT,
    }
}
