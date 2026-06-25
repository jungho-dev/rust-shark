# Architecture

This document describes the rust-shark architecture as implemented in the current
source tree. rust-shark is a Cargo workspace with a reusable engine crate and a
single CLI binary that hosts two terminal frontends.

## Goals

rust-shark is designed around four constraints.

- Keep the capture, decode, and UI stages decoupled so a slow terminal never
  drops packets and a packet burst never stalls the UI.
- Decode untrusted wire data without panicking: every decoder validates length
  before indexing.
- Stay fully offline and local-first — no cloud calls, no telemetry; GeoIP/ASN
  enrichment reads local `.mmdb` files only.
- Keep the egress monitor strictly observational (no blocking) with a single
  owner for the SQLite writer.

## Workspace Layout

| Crate | Kind | Responsibility |
| --- | --- | --- |
| rust-shark-core | library (`rust_shark_core`) | Capture, decoders, flow tracking, filters, process attribution, name/GeoIP/identity enrichment, SQLite store, the alert engine, the monitor daemon, and Unix-socket IPC. |
| rust-shark-app | binary (`rust-shark`) | CLI dispatch (clap), the capture pipeline wiring, and the two ratatui frontends (capture TUI, inspector). |

Edition 2024, rust-version 1.85. `libc`, `ipc`, `inspector`, and `monitor` are
`#[cfg(unix)]`-gated; Windows builds the capture/decode/analysis/TUI surface
without the daemon.

## Capture Pipeline

The live path is three threads over bounded crossbeam channels, so each stage
applies backpressure instead of dropping work.

```text
pcap interface
  |
  v
[capture thread]  capture::live::start_live_capture
  |  RawPacket  (bounded channel, cap 10_000)
  v
[decode thread]   decode_thread
  |   decode::decode_packet  -> flow::tracker::update  -> process attribution
  |  DecodedPacket  (bounded channel, cap 10_000)
  v
[UI thread]       tui::run_tui   (or json_output_loop when --json)
     PacketRing (bounded) + ratatui render loop (~30 fps)
```

- The capture thread translates libpcap records into `RawPacket` and stops on a
  shared `AtomicBool`.
- The decode thread runs the layered decoder chain, updates flow state
  (reassembly, RTT, retransmission), and attaches the owning process.
- The UI thread drains decoded packets into a bounded `storage::ring::PacketRing`
  and renders. `--json` swaps the TUI for a one-shot/streaming JSON writer with
  optional count/duration limits.

## Decoder Chain

`decode::decode_packet` walks a `DecodeResult` / `NextDecode` chain from the link
layer up. Each protocol decoder returns `Option`, validates every length before
slicing, and uses saturating arithmetic so malformed or truncated packets stop
the chain cleanly rather than panicking.

Supported layers: Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, DNS
(questions and answers), TLS (SNI plus JA3/JA4 fingerprints), HTTP/1.1, cleartext
HTTP/2 (HPACK), and QUIC long-header detection. `compute_summary` derives the
human-readable summary and color hint used by the TUI.

## Module Responsibilities

| Module | Role |
| --- | --- |
| capture | libpcap live and offline capture; the shared `capture_loop`; `Linktype` mapping. |
| decode | Per-protocol decoders, the `DecodedPacket`/`Layer` model, and summary computation. |
| flow | `FlowTracker` (LRU-keyed by a normalized 5-tuple `FlowKey`), TCP reassembly, DNS query/response pairing, and RTT estimation. |
| filter | nom-based display-filter parser, `FilterExpr` AST, and per-packet `eval_filter`. |
| storage | `PacketRing`, the bounded `VecDeque` ring that backs the TUI scrollback. |
| analysis | Conservative anomaly detection (cleartext credentials, unusual ports) over decoded packets. |
| process | OS socket-table lookup mapping a 5-tuple to a PID (Linux/macOS/Windows). |
| enrich | Passive name resolution (DNS answers + TLS SNI) and offline GeoIP/ASN lookup behind an `Enricher` trait. |
| identity | Binary identity (macOS code signature / content hash) with an LRU cache, for the program-modification signal. |
| store | SQLite data-access layer (`rusqlite`, bundled) with parameterized queries; schema and models live alongside. |
| alert | The five-signal egress alert engine plus the EWMA volume baseline. |
| monitor | The always-on daemon: capture, the correlate/detect worker, and lifecycle (`run`/`status`/`stop`, daemonize). |
| ipc | Unix-socket request/response protocol and server used by `inspect`. |
| inspector | The reducer that turns IPC events into inspector view state. |
| notify | Best-effort desktop notifications (macOS `osascript`, Linux `notify-send`) plus stderr logging. |
| output | JSON line output and pcap / pcapng writers behind a `PacketSink` trait. |
| diff | Content-based pcap diff. |
| error | The shared `RustSharkError` enum. |

## Egress Monitor

`rust-shark monitor run` (Unix only) starts a daemon that captures continuously
and runs a correlate/detect worker alongside an IPC server. A single thread owns
the SQLite writer; readers reach it under a mutex.

For each closed/updated flow the worker correlates the 5-tuple to a PID, resolves
the destination name passively (DNS answers + TLS SNI, no decryption), enriches
with offline country/ASN, updates the per-process baseline, and evaluates five
signals:

1. New process → destination — a process contacts a domain/org it never has.
2. New process phoning home — a binary's first-ever outbound connection.
3. New country / ASN — first contact with a host in a new country or network.
4. Volume / exfil spike — outbound volume far above a process's EWMA baseline.
5. Program modification — a process's binary identity changed since baseline.

`rust-shark inspect` attaches a second ratatui frontend over the Unix socket and
shows live connections, per-process / per-domain breakdowns, history, and the
alert feed; `inspect --json` prints a one-shot snapshot.

## Terminal UI

Both frontends use ratatui over crossterm. The capture TUI renders a dense,
256-color modern-dark layout from a central `tui::theme` palette: a scrollable
packet table (with a scrollbar on overflow), an independently toggleable detail
tree (`d`) and hex pane (`x`), a throughput strip, and full-screen stats overlays.
The event loop ignores crossterm key-release events so each keystroke is handled
once on Windows.

## State Model

| State | Owner | Backing type | Lifetime |
| --- | --- | --- | --- |
| Capture scrollback | tui::App | `PacketRing` (bounded `VecDeque`) | UI session |
| Flow table | flow::FlowTracker | `LruCache<FlowKey, FlowState>` | Capture session |
| Monitor records | store | SQLite (single writer thread) | Persistent on disk |
| Live connections | monitor worker | `Mutex<LiveState>` | Daemon lifetime |

## Display Filters

Protocol atoms: `tcp udp icmp icmpv6 arp ip ipv4 ipv6 dns tls`. Comparisons such
as `ip.src == 10.0.0.1` and `tcp.port == 443`, containment such as `tls.sni
contains example.com`, and boolean composition (`and`/`&&`, `or`/`||`, `not`,
parentheses). The parser builds the canonical dotted field path once at parse
time so per-packet evaluation does not allocate.

## Validation Strategy

Use the narrowest commands that cover the changed surface.

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build --workspace
```

The core crate carries unit tests for the decoders, flow tracker, filter, ring,
and writers; the app crate carries TUI input-guard and render smoke tests.
Unix-only modules (`monitor`, `ipc`, `inspector`, `notify`) compile and run on
Unix targets only.
