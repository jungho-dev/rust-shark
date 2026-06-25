# Architecture

이 문서는 현재 source tree에 구현된 rust-shark architecture를 설명합니다. rust-shark는 재사용 가능한 engine crate와 두 개의 terminal frontend를 호스팅하는 단일 CLI binary로 구성된 Cargo workspace입니다.

## Goals

rust-shark는 네 가지 제약을 기준으로 설계됩니다.

- capture, decode, UI 단계를 decouple하여 느린 terminal이 packet을 drop하지 않게 하고 packet burst가 UI를 멈추지 않게 합니다.
- 신뢰할 수 없는 wire data를 panic 없이 decode합니다. 모든 decoder는 indexing 전에 length를 검증합니다.
- 완전히 offline, local-first를 유지합니다. cloud call이나 telemetry가 없으며, GeoIP/ASN enrichment는 local `.mmdb` file만 읽습니다.
- egress monitor를 엄격히 관찰 전용(blocking 없음)으로 유지하며 SQLite writer는 단일 owner가 소유합니다.

## Workspace Layout

| Crate | 종류 | 역할 |
| --- | --- | --- |
| rust-shark-core | library (`rust_shark_core`) | Capture, decoder, flow tracking, filter, process attribution, name/GeoIP/identity enrichment, SQLite store, alert engine, monitor daemon, Unix-socket IPC입니다. |
| rust-shark-app | binary (`rust-shark`) | CLI dispatch (clap), capture pipeline wiring, 두 ratatui frontend (capture TUI, inspector)입니다. |

Edition 2024, rust-version 1.85입니다. `libc`, `ipc`, `inspector`, `monitor`는 `#[cfg(unix)]`로 gate되며, Windows는 daemon 없이 capture/decode/analysis/TUI surface를 빌드합니다.

## Capture Pipeline

live path는 bounded crossbeam channel을 사이에 둔 세 개의 thread이며, 각 단계가 work를 drop하는 대신 backpressure를 적용합니다.

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

- capture thread는 libpcap record를 `RawPacket`으로 변환하고 공유 `AtomicBool`에서 멈춥니다.
- decode thread는 layered decoder chain을 실행하고, flow state(reassembly, RTT, retransmission)를 갱신하며, owning process를 attach합니다.
- UI thread는 decoded packet을 bounded `storage::ring::PacketRing`으로 drain하고 render합니다. `--json`은 TUI를 one-shot/streaming JSON writer로 교체하며 optional count/duration limit을 지원합니다.

## Decoder Chain

`decode::decode_packet`은 link layer부터 위로 `DecodeResult` / `NextDecode` chain을 따라갑니다. 각 protocol decoder는 `Option`을 반환하고, slicing 전에 모든 length를 검증하며, saturating arithmetic을 사용하여 malformed하거나 truncated된 packet이 panic 대신 chain을 깔끔하게 멈추게 합니다.

지원 layer: Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, DNS(question과 answer), TLS(SNI와 JA3/JA4 fingerprint), HTTP/1.1, cleartext HTTP/2(HPACK), QUIC long-header detection입니다. `compute_summary`는 TUI가 사용하는 human-readable summary와 color hint를 만듭니다.

## Module Responsibilities

| Module | 역할 |
| --- | --- |
| capture | libpcap live 및 offline capture, 공유 `capture_loop`, `Linktype` mapping입니다. |
| decode | Per-protocol decoder, `DecodedPacket`/`Layer` model, summary computation입니다. |
| flow | `FlowTracker`(정규화된 5-tuple `FlowKey`로 LRU-keyed), TCP reassembly, DNS query/response pairing, RTT estimation입니다. |
| filter | nom 기반 display-filter parser, `FilterExpr` AST, per-packet `eval_filter`입니다. |
| storage | `PacketRing`, TUI scrollback을 뒷받침하는 bounded `VecDeque` ring입니다. |
| analysis | decoded packet에 대한 conservative anomaly detection(cleartext credential, unusual port)입니다. |
| process | 5-tuple을 PID로 mapping하는 OS socket-table lookup(Linux/macOS/Windows)입니다. |
| enrich | Passive name resolution(DNS answer + TLS SNI)과 `Enricher` trait 뒤의 offline GeoIP/ASN lookup입니다. |
| identity | LRU cache를 갖춘 binary identity(macOS code signature / content hash)이며 program-modification signal에 사용됩니다. |
| store | parameterized query를 사용하는 SQLite data-access layer(`rusqlite`, bundled)이며 schema와 model이 함께 있습니다. |
| alert | five-signal egress alert engine과 EWMA volume baseline입니다. |
| monitor | always-on daemon: capture, correlate/detect worker, lifecycle(`run`/`status`/`stop`, daemonize)입니다. |
| ipc | `inspect`가 사용하는 Unix-socket request/response protocol과 server입니다. |
| inspector | IPC event를 inspector view state로 바꾸는 reducer입니다. |
| notify | Best-effort desktop notification(macOS `osascript`, Linux `notify-send`)과 stderr logging입니다. |
| output | `PacketSink` trait 뒤의 JSON line output과 pcap / pcapng writer입니다. |
| diff | Content-based pcap diff입니다. |
| error | 공유 `RustSharkError` enum입니다. |

## Egress Monitor

`rust-shark monitor run`(Unix 전용)은 지속적으로 capture하면서 IPC server와 함께 correlate/detect worker를 실행하는 daemon을 시작합니다. 단일 thread가 SQLite writer를 소유하며, reader는 mutex를 통해 접근합니다.

closed/updated된 각 flow에 대해 worker는 5-tuple을 PID로 correlate하고, destination name을 passive하게 resolve하며(DNS answer + TLS SNI, decryption 없음), offline country/ASN으로 enrich하고, per-process baseline을 갱신한 뒤 다섯 가지 signal을 평가합니다.

1. New process → destination — process가 한 번도 접촉한 적 없는 domain/org에 접촉합니다.
2. New process phoning home — binary의 최초 outbound connection입니다.
3. New country / ASN — 새로운 country나 network의 host에 처음 접촉합니다.
4. Volume / exfil spike — process의 EWMA baseline을 크게 상회하는 outbound volume입니다.
5. Program modification — process의 binary identity가 baseline 이후 변경되었습니다.

`rust-shark inspect`는 Unix socket을 통해 두 번째 ratatui frontend를 attach하여 live connection, per-process / per-domain breakdown, history, alert feed를 보여줍니다. `inspect --json`은 one-shot snapshot을 출력합니다.

## Terminal UI

두 frontend 모두 crossterm 위의 ratatui를 사용합니다. capture TUI는 중앙 `tui::theme` palette에서 조밀한 256-color modern-dark layout을 render합니다: scrollable packet table(overflow 시 scrollbar 포함), 독립적으로 toggle 가능한 detail tree(`d`)와 hex pane(`x`), throughput strip, full-screen stats overlay입니다. event loop는 crossterm key-release event를 무시하여 Windows에서 각 keystroke가 한 번만 처리되게 합니다.

## State Model

| State | Owner | Backing type | Lifetime |
| --- | --- | --- | --- |
| Capture scrollback | tui::App | `PacketRing` (bounded `VecDeque`) | UI session |
| Flow table | flow::FlowTracker | `LruCache<FlowKey, FlowState>` | Capture session |
| Monitor records | store | SQLite (single writer thread) | Persistent on disk |
| Live connections | monitor worker | `Mutex<LiveState>` | Daemon lifetime |

## Display Filters

Protocol atom: `tcp udp icmp icmpv6 arp ip ipv4 ipv6 dns tls`입니다. `ip.src == 10.0.0.1`과 `tcp.port == 443` 같은 comparison, `tls.sni contains example.com` 같은 containment, boolean composition(`and`/`&&`, `or`/`||`, `not`, 괄호)을 지원합니다. parser는 parse 시점에 canonical dotted field path를 한 번 만들어 per-packet evaluation이 allocate하지 않게 합니다.

## Validation Strategy

changed surface를 덮는 가장 좁은 command를 사용합니다.

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build --workspace
```

core crate는 decoder, flow tracker, filter, ring, writer에 대한 unit test를 가지며, app crate는 TUI input-guard와 render smoke test를 가집니다. Unix 전용 module(`monitor`, `ipc`, `inspector`, `notify`)은 Unix target에서만 컴파일·실행됩니다.
