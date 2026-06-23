pub mod detail_tree;
pub mod filter_bar;
pub mod hex_view;
pub mod packet_list;
pub mod theme;
pub mod views;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use ratatui::Terminal;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Paragraph};

use rust_shark_core::analysis::ThreatTracker;
use rust_shark_core::decode::{DecodedPacket, Direction as PktDir};
use rust_shark_core::enrich::names::SharedNameResolver;
use rust_shark_core::filter::ast::FilterExpr;
use rust_shark_core::filter::eval::eval_filter;
use rust_shark_core::filter::parser::parse_filter;
use rust_shark_core::output::PacketSink;
use rust_shark_core::output::log_writer;
use rust_shark_core::output::pcap_writer::PcapWriter;
use rust_shark_core::output::pcapng_writer::PcapngWriter;
use rust_shark_core::storage::ring::PacketRing;

const FRAME_INTERVAL: Duration = Duration::from_millis(33);
/// Bottom hex pane height: a thin border + ~4 content rows (64 bytes). Kept
/// minimal so the packet list keeps the vertical space; the pane still scrolls.
const HEX_HEIGHT: u16 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    FilterInput,
    Search,
    /// Column-visibility editor: digit keys 1-6 toggle the main-table columns.
    ColumnConfig,
}

/// Full-area statistics/stream overlays toggled from Normal mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayKind {
    TopTalkers,
    ProtocolDist,
    Flows,
    Timeline,
    Stream,
    Bookmarks,
}

const THROUGHPUT_WINDOW: usize = 60;

#[derive(Debug, Clone)]
pub struct StatusMessage {
    pub text: String,
    pub is_error: bool,
}

pub struct App {
    pub packets: PacketRing,
    pub filtered_indices: Option<Vec<usize>>,
    pub active_filter: Option<FilterExpr>,
    /// Direction-only view filter (show IN-only / OUT-only), combined with
    /// `active_filter` as AND when building the visible index.
    pub dir_filter: Option<PktDir>,
    pub mode: InputMode,
    pub selected: usize,
    pub paused: bool,
    /// Follow (LIVE) mode pins the view to the newest packet. Cleared by manual
    /// navigation (click, scrollbar drag, wheel/k/g/PageUp); restored by G/End
    /// or scrolling to the last packet.
    pub follow: bool,
    pub status_message: Option<StatusMessage>,
    pub detail_scroll: usize,
    pub hex_scroll: usize,
    pub total_received: u64,
    pub total_dropped: u64,
    pub filter_input: String,
    pub filter_cursor: usize,
    pub pcap_writer: Option<Box<dyn PacketSink>>,

    // Phase-4 stats / follow-stream overlays (all computed from the packet ring).
    pub overlay: Option<OverlayKind>,
    pub overlay_scroll: usize,
    pub stream: Option<(String, rust_shark_core::flow::StreamData)>,
    pub throughput_pps: VecDeque<u64>,
    pub throughput_bps: VecDeque<u64>,
    pub last_tick: Instant,
    pub tick_pkts: u64,
    pub tick_bytes: u64,
    pub proto_counts: BTreeMap<String, u64>,
    pub saved_filters: HashMap<String, String>,
    pub bookmarks: HashSet<u64>,
    pub search_query: String,
    pub search_re: Option<regex::Regex>,
    pub show_detail: bool,
    pub show_hex: bool,
    /// Packet-list rect from the previous frame, cached for mouse hit-testing
    /// (wheel scroll, scrollbar drag, row click).
    pub list_area: Rect,
    /// Per-column visibility for the packet list (Time, Source, Destination,
    /// Proto, Len, Info). Toggled in `InputMode::ColumnConfig`.
    pub col_visible: [bool; packet_list::COLUMN_COUNT],
    /// True while the user is dragging the packet-list scrollbar thumb, so
    /// motion keeps tracking the scrollbar even if the cursor leaves its column.
    pub scrollbar_drag: bool,
    /// Live recon / rare-destination detector, fed every captured packet.
    pub threat_tracker: ThreatTracker,
    /// Local interface IPs for IN/OUT direction classification (empty when
    /// reading a pcap file — falls back to a private/public heuristic).
    pub local_ips: Vec<IpAddr>,
    /// IP→hostname resolver (DNS/SNI), fed every packet for the Peer column.
    pub names: SharedNameResolver,
}

impl App {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            packets: PacketRing::new(buffer_size),
            filtered_indices: None,
            active_filter: None,
            dir_filter: None,
            mode: InputMode::Normal,
            selected: 0,
            paused: false,
            follow: true,
            status_message: None,
            detail_scroll: 0,
            hex_scroll: 0,
            total_received: 0,
            total_dropped: 0,
            filter_input: String::new(),
            filter_cursor: 0,
            pcap_writer: None,
            overlay: None,
            overlay_scroll: 0,
            stream: None,
            throughput_pps: VecDeque::new(),
            throughput_bps: VecDeque::new(),
            last_tick: Instant::now(),
            tick_pkts: 0,
            tick_bytes: 0,
            proto_counts: BTreeMap::new(),
            saved_filters: HashMap::new(),
            bookmarks: HashSet::new(),
            search_query: String::new(),
            search_re: None,
            show_detail: true,
            show_hex: true,
            list_area: Rect::default(),
            col_visible: [true; packet_list::COLUMN_COUNT],
            scrollbar_drag: false,
            threat_tracker: ThreatTracker::new(),
            local_ips: Vec::new(),
            names: SharedNameResolver::new(),
        }
    }

    fn toggle_bookmark(&mut self) {
        if let Some(num) = self.selected_packet().map(|p| p.number) {
            if !self.bookmarks.insert(num) {
                self.bookmarks.remove(&num);
            }
        }
    }

    /// Jump to the next packet (after `selected`) matching the active regex.
    fn next_search_match(&mut self) {
        let Some(re) = self.search_re.clone() else {
            return;
        };
        let count = self.visible_count();
        for off in 1..=count {
            let i = (self.selected + off) % count.max(1);
            if let Some(p) = self.visible_packet(i) {
                if re.is_match(&p.summary.info)
                    || re.is_match(&p.summary.source)
                    || re.is_match(&p.summary.destination)
                {
                    self.selected = i;
                    return;
                }
            }
        }
    }

    /// Advance the per-second throughput rings (runs every frame, even when paused).
    pub fn tick_throughput(&mut self) {
        if self.last_tick.elapsed() >= Duration::from_secs(1) {
            push_capped(&mut self.throughput_pps, self.tick_pkts, THROUGHPUT_WINDOW);
            push_capped(&mut self.throughput_bps, self.tick_bytes, THROUGHPUT_WINDOW);
            self.tick_pkts = 0;
            self.tick_bytes = 0;
            self.last_tick = Instant::now();
        }
    }

    pub fn visible_count(&self) -> usize {
        match &self.filtered_indices {
            Some(indices) => indices.len(),
            None => self.packets.len(),
        }
    }

    pub fn visible_packet(&self, visible_idx: usize) -> Option<&DecodedPacket> {
        match &self.filtered_indices {
            Some(indices) => indices
                .get(visible_idx)
                .and_then(|&ring_idx| self.packets.get(ring_idx)),
            None => self.packets.get(visible_idx),
        }
    }

    pub fn selected_packet(&self) -> Option<&DecodedPacket> {
        self.visible_packet(self.selected)
    }

    /// Whether a packet passes both the active text filter and the direction
    /// filter (AND). Used to (re)build the visible index.
    fn passes(&self, pkt: &DecodedPacket) -> bool {
        let text_ok = match &self.active_filter {
            Some(f) => eval_filter(f, pkt),
            None => true,
        };
        let dir_ok = match self.dir_filter {
            Some(d) => pkt.direction(&self.local_ips) == d,
            None => true,
        };
        text_ok && dir_ok
    }

    fn toggle_overlay(&mut self, kind: OverlayKind) {
        self.overlay = if self.overlay == Some(kind) {
            None
        } else {
            self.overlay_scroll = 0;
            Some(kind)
        };
    }

    /// Build the reassembled conversation for the selected packet's flow and
    /// open the follow-stream overlay.
    fn open_stream(&mut self) {
        if let Some(stream) = views::build_stream(self) {
            self.stream = Some(stream);
            self.overlay_scroll = 0;
            self.overlay = Some(OverlayKind::Stream);
        } else {
            self.status_message = Some(StatusMessage {
                text: "Select a TCP packet to follow its stream".into(),
                is_error: true,
            });
        }
    }

    /// Export the currently visible (filtered) packets to a timestamped plain
    /// `.log` file in the working directory (request 4: human-readable log).
    fn save_log(&mut self) {
        let count = self.visible_count();
        if count == 0 {
            self.status_message = Some(StatusMessage {
                text: "No packets to save".into(),
                is_error: true,
            });
            return;
        }
        let pkts: Vec<&DecodedPacket> =
            (0..count).filter_map(|i| self.visible_packet(i)).collect();
        let fname = format!(
            "rust-shark-{}.log",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        );
        match log_writer::write_packet_log(std::path::Path::new(&fname), pkts, &self.local_ips) {
            Ok(n) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Saved {n} packets to {fname}"),
                    is_error: false,
                });
            }
            Err(e) => {
                self.status_message = Some(StatusMessage {
                    text: format!("Log save failed: {e}"),
                    is_error: true,
                });
            }
        }
    }
}

fn push_capped(ring: &mut VecDeque<u64>, value: u64, cap: usize) {
    ring.push_back(value);
    while ring.len() > cap {
        ring.pop_front();
    }
}

pub fn run_tui(
    rx: Receiver<DecodedPacket>,
    buffer_size: usize,
    save_path: Option<&Path>,
    saved_filters: HashMap<String, String>,
    pcapng: bool,
    local_ips: Vec<IpAddr>,
) -> anyhow::Result<()> {
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture, cursor::Hide)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Set up panic hook to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            cursor::Show
        );
        original_hook(panic_info);
    }));

    let mut app = App::new(buffer_size);
    app.saved_filters = saved_filters;
    app.local_ips = local_ips;

    if let Some(path) = save_path {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        let lt = rust_shark_core::capture::Linktype::Ethernet;
        app.pcap_writer = Some(if pcapng {
            Box::new(PcapngWriter::new(writer, lt, 65535)?)
        } else {
            Box::new(PcapWriter::new(writer, lt, 65535)?)
        });
    }

    loop {
        let frame_start = Instant::now();
        app.tick_throughput();

        terminal.draw(|frame| render_frame(frame, &mut app))?;

        let timeout = FRAME_INTERVAL.saturating_sub(frame_start.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    if !handle_key_event(&mut app, key) {
                        break;
                    }
                }
                Event::Mouse(me) => handle_mouse_event(&mut app, me),
                _ => {}
            }
        }

        if !app.paused {
            drain_packets(&mut app, &rx);
        }
    }

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        cursor::Show
    )?;

    if let Some(ref mut writer) = app.pcap_writer {
        writer.flush()?;
    }

    Ok(())
}

fn handle_key_event(app: &mut App, key: event::KeyEvent) -> bool {
    // Windows (crossterm) reports both Press and Release for every keystroke.
    // Without this guard each key is handled twice: toggle keys open then
    // immediately close (appear dead), navigation jumps two rows, and typed
    // filter/search characters are doubled. Ignore Release so each key acts once.
    if key.kind == KeyEventKind::Release {
        return true;
    }

    // Ctrl-C always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return false;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('f') {
        app.mode = InputMode::Search;
        app.search_query.clear();
        return true;
    }

    match app.mode {
        InputMode::Normal => match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Char('j') | KeyCode::Down => {
                if app.overlay.is_some() {
                    app.overlay_scroll = app.overlay_scroll.saturating_add(1);
                } else {
                    let count = app.visible_count();
                    if count > 0 && app.selected < count - 1 {
                        app.selected += 1;
                        app.detail_scroll = 0;
                        app.hex_scroll = 0;
                        // Reaching the last packet re-enters LIVE follow.
                        if app.selected + 1 >= count {
                            app.follow = true;
                        }
                    }
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if app.overlay.is_some() {
                    app.overlay_scroll = app.overlay_scroll.saturating_sub(1);
                } else if app.selected > 0 {
                    app.selected -= 1;
                    app.follow = false;
                    app.detail_scroll = 0;
                    app.hex_scroll = 0;
                }
            }
            KeyCode::Char('t') => app.toggle_overlay(OverlayKind::TopTalkers),
            KeyCode::Char('P') => app.toggle_overlay(OverlayKind::ProtocolDist),
            KeyCode::Char('F') => app.toggle_overlay(OverlayKind::Flows),
            KeyCode::Char('T') => app.toggle_overlay(OverlayKind::Timeline),
            KeyCode::Char('f') => app.open_stream(),
            KeyCode::Char('m') => app.toggle_bookmark(),
            KeyCode::Char('\'') => app.toggle_overlay(OverlayKind::Bookmarks),
            KeyCode::Char('n') => app.next_search_match(),
            KeyCode::Char('d') => app.show_detail = !app.show_detail,
            KeyCode::Char('x') => app.show_hex = !app.show_hex,
            KeyCode::Char('c') => app.mode = InputMode::ColumnConfig,
            KeyCode::Char('i') => {
                app.dir_filter = if app.dir_filter == Some(PktDir::In) {
                    None
                } else {
                    Some(PktDir::In)
                };
                rebuild_filter_indices(app);
                app.selected = 0;
                app.status_message = Some(StatusMessage {
                    text: match app.dir_filter {
                        Some(_) => "Showing inbound (IN) only".into(),
                        None => "Direction filter cleared".into(),
                    },
                    is_error: false,
                });
            }
            KeyCode::Char('o') => {
                app.dir_filter = if app.dir_filter == Some(PktDir::Out) {
                    None
                } else {
                    Some(PktDir::Out)
                };
                rebuild_filter_indices(app);
                app.selected = 0;
                app.status_message = Some(StatusMessage {
                    text: match app.dir_filter {
                        Some(_) => "Showing outbound (OUT) only".into(),
                        None => "Direction filter cleared".into(),
                    },
                    is_error: false,
                });
            }
            KeyCode::Char('z') => {
                // Master toggle: hide both panes for a full-width list, or
                // restore both if either is currently hidden.
                let any = app.show_detail || app.show_hex;
                app.show_detail = !any;
                app.show_hex = !any;
            }
            KeyCode::Esc => {
                app.overlay = None;
                app.stream = None;
            }
            KeyCode::Char('G') | KeyCode::End => {
                let count = app.visible_count();
                if count > 0 {
                    app.selected = count - 1;
                    app.follow = true;
                    app.detail_scroll = 0;
                    app.hex_scroll = 0;
                }
            }
            KeyCode::Char('g') | KeyCode::Home => {
                app.selected = 0;
                app.follow = false;
                app.detail_scroll = 0;
                app.hex_scroll = 0;
            }
            KeyCode::PageDown => {
                let count = app.visible_count();
                app.selected = (app.selected + 20).min(count.saturating_sub(1));
                if app.selected + 1 >= count {
                    app.follow = true;
                }
            }
            KeyCode::PageUp => {
                app.selected = app.selected.saturating_sub(20);
                app.follow = false;
            }
            KeyCode::Char(' ') => {
                app.paused = !app.paused;
                app.status_message = Some(StatusMessage {
                    text: if app.paused {
                        "Paused".into()
                    } else {
                        "Resumed".into()
                    },
                    is_error: false,
                });
            }
            KeyCode::Char('/') => {
                app.mode = InputMode::FilterInput;
                app.filter_input.clear();
                app.filter_cursor = 0;
            }
            KeyCode::Char('s') => app.save_log(),
            _ => {}
        },
        InputMode::FilterInput => match key.code {
            KeyCode::Enter => {
                if app.filter_input.is_empty() {
                    app.active_filter = None;
                    rebuild_filter_indices(app);
                    app.selected = 0;
                    app.status_message = Some(StatusMessage {
                        text: "Filter cleared".into(),
                        is_error: false,
                    });
                } else {
                    // `:name` recalls a saved named filter from config.toml.
                    let expr = match app.filter_input.strip_prefix(':') {
                        Some(name) => match app.saved_filters.get(name) {
                            Some(f) => f.clone(),
                            None => {
                                app.status_message = Some(StatusMessage {
                                    text: format!("No saved filter ':{name}'"),
                                    is_error: true,
                                });
                                app.mode = InputMode::Normal;
                                return true;
                            }
                        },
                        None => app.filter_input.clone(),
                    };
                    match parse_filter(&expr) {
                        Ok(filter) => {
                            app.active_filter = Some(filter);
                            rebuild_filter_indices(app);
                            app.selected = 0;
                            app.status_message = Some(StatusMessage {
                                text: format!("Filter applied: {expr}"),
                                is_error: false,
                            });
                        }
                        Err(e) => {
                            app.status_message = Some(StatusMessage {
                                text: format!("Filter error: {e}"),
                                is_error: true,
                            });
                        }
                    }
                }
                app.mode = InputMode::Normal;
            }
            KeyCode::Esc => {
                app.mode = InputMode::Normal;
            }
            KeyCode::Backspace if app.filter_cursor > 0 => {
                app.filter_cursor -= 1;
                app.filter_input.remove(app.filter_cursor);
            }
            KeyCode::Left if app.filter_cursor > 0 => {
                app.filter_cursor -= 1;
            }
            KeyCode::Right if app.filter_cursor < app.filter_input.len() => {
                app.filter_cursor += 1;
            }
            KeyCode::Char(c) => {
                app.filter_input.insert(app.filter_cursor, c);
                app.filter_cursor += 1;
            }
            _ => {}
        },
        InputMode::Search => match key.code {
            KeyCode::Enter => {
                match regex::Regex::new(&app.search_query) {
                    Ok(re) => {
                        app.search_re = Some(re);
                        app.next_search_match();
                    }
                    Err(e) => {
                        app.status_message = Some(StatusMessage {
                            text: format!("Bad regex: {e}"),
                            is_error: true,
                        });
                    }
                }
                app.mode = InputMode::Normal;
            }
            KeyCode::Esc => {
                app.search_query.clear();
                app.search_re = None;
                app.mode = InputMode::Normal;
            }
            KeyCode::Backspace => {
                app.search_query.pop();
            }
            KeyCode::Char(c) => app.search_query.push(c),
            _ => {}
        },
        InputMode::ColumnConfig => match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('c') => {
                app.mode = InputMode::Normal;
            }
            KeyCode::Char(d @ '1'..='8') => {
                let idx = d as usize - '1' as usize;
                app.col_visible[idx] = !app.col_visible[idx];
            }
            _ => {}
        },
    }
    true
}

fn handle_mouse_event(app: &mut App, me: MouseEvent) {
    match me.kind {
        MouseEventKind::ScrollDown => {
            if app.overlay.is_some() {
                app.overlay_scroll = app.overlay_scroll.saturating_add(3);
            } else {
                let count = app.visible_count();
                if count > 0 {
                    app.selected = (app.selected + 3).min(count - 1);
                    app.detail_scroll = 0;
                    app.hex_scroll = 0;
                    if app.selected + 1 >= count {
                        app.follow = true;
                    }
                }
            }
        }
        MouseEventKind::ScrollUp => {
            if app.overlay.is_some() {
                app.overlay_scroll = app.overlay_scroll.saturating_sub(3);
            } else {
                app.selected = app.selected.saturating_sub(3);
                app.follow = false;
                app.detail_scroll = 0;
                app.hex_scroll = 0;
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            if app.overlay.is_none() {
                // A press on the scrollbar grabs the thumb; anywhere else picks a row.
                if on_scrollbar(app, me.column, me.row) {
                    app.scrollbar_drag = true;
                    scroll_to_row(app, me.row);
                } else {
                    select_row_by_mouse(app, me.column, me.row);
                }
            }
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            if app.overlay.is_none() {
                if app.scrollbar_drag {
                    // Thumb held: keep tracking the row even if the cursor drifts
                    // off the scrollbar column — the classic grab-and-drag feel.
                    scroll_to_row(app, me.row);
                } else {
                    select_row_by_mouse(app, me.column, me.row);
                }
            }
        }
        MouseEventKind::Up(MouseButton::Left) => app.scrollbar_drag = false,
        _ => {}
    }
}

/// True when `(col, row)` lands on the packet-list scrollbar track. The
/// scrollbar exists only while the list overflows its viewport and sits on the
/// rightmost column of the list rect.
fn on_scrollbar(app: &App, col: u16, row: u16) -> bool {
    let area = app.list_area;
    if area.width == 0 || area.height == 0 {
        return false;
    }
    let count = app.visible_count();
    let table_height = area.height.saturating_sub(3) as usize;
    if count <= table_height {
        return false;
    }
    let sb_col = area.x + area.width - 1;
    let track_top = area.y + 1;
    let track_bottom = area.y + area.height.saturating_sub(1);
    col == sb_col && row >= track_top && row < track_bottom
}

/// Map a scrollbar-track row onto a position in the full list (proportional
/// jump). Used for both a track click and an ongoing thumb drag; the row is
/// clamped so dragging past either end pins to the first/last packet.
fn scroll_to_row(app: &mut App, row: u16) {
    let area = app.list_area;
    let count = app.visible_count();
    if count == 0 {
        return;
    }
    let track_top = area.y + 1;
    let track_h = area.height.saturating_sub(2) as usize;
    if track_h == 0 {
        return;
    }
    let rel = row.saturating_sub(track_top) as usize;
    let max_idx = count - 1;
    // Divide by (track_h - 1) so the bottom-most track cell reaches the last
    // packet instead of stopping ~one viewport short.
    let denom = track_h.saturating_sub(1).max(1);
    app.selected = (rel * max_idx / denom).min(max_idx);
    // Dragging the scrollbar is manual navigation — leave LIVE follow.
    app.follow = false;
    app.detail_scroll = 0;
    app.hex_scroll = 0;
}

/// Select the data row under the cursor (a plain click inside the list).
fn select_row_by_mouse(app: &mut App, col: u16, row: u16) {
    let area = app.list_area;
    if area.width == 0 || area.height == 0 {
        return;
    }
    let inside = col >= area.x
        && col < area.x + area.width
        && row >= area.y
        && row < area.y + area.height;
    if !inside {
        return;
    }
    let count = app.visible_count();
    if count == 0 {
        return;
    }
    // Data rows start below the top border (area.y) and header (area.y + 1).
    let data_top = area.y + 2;
    if row < data_top {
        return;
    }
    let table_height = area.height.saturating_sub(3) as usize;
    let scroll_offset = if app.selected >= table_height {
        app.selected - table_height + 1
    } else {
        0
    };
    let target = scroll_offset + (row - data_top) as usize;
    if target < count {
        app.selected = target;
        // A plain click surfaces the detail pane and leaves LIVE follow so the
        // selection doesn't jump away as new packets arrive.
        app.show_detail = true;
        app.follow = false;
    }
    app.detail_scroll = 0;
    app.hex_scroll = 0;
}

fn drain_packets(app: &mut App, rx: &Receiver<DecodedPacket>) {
    while let Ok(mut pkt) = rx.try_recv() {
        app.total_received += 1;
        app.tick_pkts += 1;
        app.tick_bytes += pkt.wire_len as u64;
        // Live threat detection + name resolution: annotate before filtering so
        // the `threat` filter, the row highlight, and the Peer column all see it.
        pkt.threat = app.threat_tracker.observe(&pkt);
        app.names.observe(&pkt);
        *app.proto_counts
            .entry(pkt.summary.protocol.clone())
            .or_insert(0) += 1;

        // Write to pcap if saving
        if let Some(ref mut writer) = app.pcap_writer {
            let _ = writer.write_packet(pkt.timestamp, &pkt.data, pkt.wire_len);
        }

        let matches_filter = app.passes(&pkt);

        let ring_idx = app.packets.len();
        let evicted = app.packets.push(pkt);

        if evicted.is_some() {
            // An old packet was evicted; adjust filtered indices
            if let Some(ref mut indices) = app.filtered_indices {
                indices.retain_mut(|idx| {
                    if *idx == 0 {
                        false
                    } else {
                        *idx -= 1;
                        true
                    }
                });
            }
        }

        if matches_filter {
            if let Some(ref mut indices) = app.filtered_indices {
                let actual_idx = if evicted.is_some() {
                    ring_idx.min(app.packets.len() - 1)
                } else {
                    ring_idx
                };
                indices.push(actual_idx);
            }
        }
    }

    // LIVE follow pins the view to the newest packet; in BROWSE mode the
    // selection stays put so clicks/scrolling work while capture continues.
    if app.follow {
        let count = app.visible_count();
        if count > 0 {
            app.selected = count - 1;
        }
    }
}

fn rebuild_filter_indices(app: &mut App) {
    // No filter of any kind → show everything (None == unfiltered).
    if app.active_filter.is_none() && app.dir_filter.is_none() {
        app.filtered_indices = None;
        return;
    }
    let mut indices = Vec::new();
    for i in 0..app.packets.len() {
        if let Some(pkt) = app.packets.get(i) {
            if app.passes(pkt) {
                indices.push(i);
            }
        }
    }
    app.filtered_indices = Some(indices);
}

fn render_frame(frame: &mut ratatui::Frame, app: &mut App) {
    let area = frame.area();

    // Overlay views take over the content area (filter bar + status stay).
    if let Some(kind) = app.overlay {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);
        filter_bar::render_filter_bar(frame, layout[0], app);
        views::render_overlay(frame, layout[1], app, kind);
        render_status_bar(frame, layout[2], app);
        return;
    }

    // Dense layout with independently toggleable panes:
    //   filter (1) | main: list [+ detail] | [hex] | throughput (1) | status (1)
    // `d` toggles the detail pane, `x` the hex pane, `z` toggles both at once.
    let mut constraints = vec![Constraint::Length(1), Constraint::Min(6)];
    if app.show_hex {
        constraints.push(Constraint::Length(HEX_HEIGHT));
    }
    constraints.push(Constraint::Length(1)); // throughput
    constraints.push(Constraint::Length(1)); // status
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut idx = 0;
    filter_bar::render_filter_bar(frame, rows[idx], app);
    idx += 1;

    let main_area = rows[idx];
    idx += 1;
    if app.show_detail {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(main_area);
        app.list_area = split[0];
        packet_list::render_packet_list(frame, split[0], app);
        detail_tree::render_detail_tree(frame, split[1], app);
    } else {
        app.list_area = main_area;
        packet_list::render_packet_list(frame, main_area, app);
    }

    if app.show_hex {
        hex_view::render_hex_view(frame, rows[idx], app);
        idx += 1;
    }
    views::render_throughput(frame, rows[idx], app);
    idx += 1;
    render_status_bar(frame, rows[idx], app);
}

fn render_status_bar(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let displayed = app.visible_count();
    let state = if app.paused {
        "PAUSED"
    } else if app.follow {
        "LIVE"
    } else {
        "BROWSE (G=live)"
    };

    if app.mode == InputMode::Search {
        let p = Paragraph::new(format!(" /regex: {}", app.search_query))
            .style(Style::default().fg(theme::SEARCH_FG).bg(theme::SEARCH_BG));
        frame.render_widget(p, area);
        return;
    }

    let panes = match (app.show_detail, app.show_hex) {
        (true, true) => "",
        (true, false) => " │ hex:off",
        (false, true) => " │ detail:off",
        (false, false) => " │ detail:off hex:off",
    };

    let status_text = match &app.status_message {
        Some(msg) => format!(
            " {} │ Packets: {} │ Displayed: {} │ Dropped: {}{} │ {} │ d:detail x:hex c:cols s:log ",
            state, app.total_received, displayed, app.total_dropped, panes, msg.text
        ),
        None => format!(
            " {} │ Packets: {} │ Displayed: {} │ Dropped: {}{} │ d:detail x:hex c:cols s:log ",
            state, app.total_received, displayed, app.total_dropped, panes
        ),
    };

    let style = if app.status_message.as_ref().is_some_and(|m| m.is_error) {
        theme::status_error()
    } else {
        theme::status_normal()
    };

    let paragraph = Paragraph::new(status_text)
        .style(style)
        .block(Block::default());
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;

    fn key(code: KeyCode, kind: KeyEventKind) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind)
    }

    // On Windows crossterm emits a Press and a Release for every keystroke.
    // A toggle key must fire once: Press toggles, the paired Release is ignored.
    #[test]
    fn release_event_is_ignored_so_toggle_sticks() {
        let mut app = App::new(1024);
        assert!(!app.paused);

        assert!(handle_key_event(
            &mut app,
            key(KeyCode::Char(' '), KeyEventKind::Press)
        ));
        assert!(app.paused, "Press should toggle pause on");

        assert!(handle_key_event(
            &mut app,
            key(KeyCode::Char(' '), KeyEventKind::Release)
        ));
        assert!(
            app.paused,
            "Release must be ignored, otherwise the toggle cancels itself out"
        );
    }

    // A Press toggles an overlay open; the duplicated Release must not close it.
    #[test]
    fn release_does_not_undo_overlay_toggle() {
        let mut app = App::new(1024);
        assert!(app.overlay.is_none());

        handle_key_event(&mut app, key(KeyCode::Char('t'), KeyEventKind::Press));
        assert_eq!(app.overlay, Some(OverlayKind::TopTalkers));

        handle_key_event(&mut app, key(KeyCode::Char('t'), KeyEventKind::Release));
        assert_eq!(
            app.overlay,
            Some(OverlayKind::TopTalkers),
            "Release must not toggle the overlay back closed"
        );
    }

    // Every render path must survive the empty-capture state without panicking
    // (layout splits, empty throughput sparkline, zero-row tables, overlays).
    #[test]
    fn render_paths_do_not_panic() {
        use chrono::DateTime;
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        use rust_shark_core::capture::{Linktype, RawPacket};
        use rust_shark_core::decode::decode_packet;

        fn draw_all(app: &mut App, w: u16, h: u16) {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| render_frame(f, app)).unwrap();

            app.mode = InputMode::FilterInput;
            term.draw(|f| render_frame(f, app)).unwrap();
            app.mode = InputMode::Search;
            term.draw(|f| render_frame(f, app)).unwrap();
            app.mode = InputMode::Normal;

            for (d, x) in [(true, true), (false, true), (true, false), (false, false)] {
                app.show_detail = d;
                app.show_hex = x;
                term.draw(|f| render_frame(f, app)).unwrap();
            }
            app.show_detail = true;
            app.show_hex = true;

            // Stream overlay needs a built stream; the rest render from the ring.
            for kind in [
                OverlayKind::TopTalkers,
                OverlayKind::ProtocolDist,
                OverlayKind::Flows,
                OverlayKind::Timeline,
                OverlayKind::Bookmarks,
            ] {
                app.overlay = Some(kind);
                term.draw(|f| render_frame(f, app)).unwrap();
            }
            app.overlay = None;
        }

        // Empty state: no scrollbar, "No packet selected" panes.
        let mut empty = App::new(1024);
        draw_all(&mut empty, 120, 40);
        draw_all(&mut empty, 80, 24);

        // Populated state: forces the packet-list scrollbar to render.
        let mut app = App::new(1024);
        let ts = DateTime::from_timestamp(0, 0).unwrap();
        for n in 0..60u64 {
            let raw = RawPacket {
                number: n,
                timestamp: ts,
                wire_len: 64,
                data: vec![0u8; 64],
                linktype: Linktype::Ethernet,
            };
            app.packets.push(decode_packet(&raw));
        }
        app.selected = 30;
        draw_all(&mut app, 120, 40);
        draw_all(&mut app, 80, 24);
    }

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn populate(app: &mut App, n: u64) {
        use chrono::DateTime;
        use rust_shark_core::capture::{Linktype, RawPacket};
        use rust_shark_core::decode::decode_packet;
        let ts = DateTime::from_timestamp(0, 0).unwrap();
        for num in 0..n {
            let raw = RawPacket {
                number: num,
                timestamp: ts,
                wire_len: 64,
                data: vec![0u8; 64],
                linktype: Linktype::Ethernet,
            };
            app.packets.push(decode_packet(&raw));
        }
    }

    // The wheel nudges the selection by three rows and clamps at both ends.
    #[test]
    fn mouse_wheel_scrolls_selection_by_three() {
        let mut app = App::new(1024);
        populate(&mut app, 60);
        app.selected = 10;
        handle_mouse_event(&mut app, mouse(MouseEventKind::ScrollDown, 5, 5));
        assert_eq!(app.selected, 13);
        handle_mouse_event(&mut app, mouse(MouseEventKind::ScrollUp, 5, 5));
        assert_eq!(app.selected, 10);
    }

    // A left click on a data row selects the packet under the cursor. With the
    // list rect at y=1, the border is y=1, the header y=2, data rows from y=3.
    #[test]
    fn mouse_click_in_list_selects_row_under_cursor() {
        let mut app = App::new(1024);
        populate(&mut app, 60);
        app.selected = 0;
        app.list_area = Rect::new(0, 1, 80, 20);
        handle_mouse_event(
            &mut app,
            mouse(MouseEventKind::Down(MouseButton::Left), 10, 5),
        );
        // Row 5 → data offset 5 - 3 = 2, no scroll → packet index 2.
        assert_eq!(app.selected, 2);
    }

    // A click on the scrollbar column maps proportionally onto the full list.
    #[test]
    fn mouse_click_on_scrollbar_jumps_proportionally() {
        let mut app = App::new(1024);
        populate(&mut app, 100);
        app.selected = 0;
        app.list_area = Rect::new(0, 1, 80, 20);
        // Scrollbar col = x + width - 1 = 79; track_top = 2, track_h = 18.
        handle_mouse_event(
            &mut app,
            mouse(MouseEventKind::Down(MouseButton::Left), 79, 19),
        );
        // rel = 19 - 2 = 17 → 17 * 99 / 17 = 99 (bottom cell → last row).
        assert_eq!(app.selected, 99);
    }
}
