# rust-shark

[![Crates.io](https://img.shields.io/crates/v/rust-shark.svg)](https://crates.io/crates/rust-shark)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE.md)

터미널에서 동작하는 Wireshark 스타일 packet analyzer이자, **동시에** 항상 켜져 있는
local-first **egress monitor**로서 "내 머신이 무엇과 통신하고 있으며, 그중 새로운 것이
있는가?"에 답합니다. 가볍고, keyboard 중심이며, scriptable합니다. macOS 우선, Linux와 Windows에서 packet analyzer가
동작합니다(egress monitor daemon은 Unix 전용). 완전 offline — cloud 없음, telemetry 없음.

## Features

### Packet analyzer

- BPF filter를 사용한 임의 interface로부터의 **Live capture**, 그리고 **PCAP / PCAPNG** read/write
- **Decoders**: Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6; DNS (questions
  **및** answer records), TLS (SNI + **JA3/JA4** fingerprints), HTTP/1.1,
  cleartext HTTP/2 (HPACK), QUIC (long-header detect)
- **TCP stream reassembly** + **follow-stream** view, **RTT** 추정
- boolean operator를 지원하는 **Display filters**: `tcp.port == 443 and ip.src == 10.0.0.1`
- **Stats views**: live throughput sparkline, top talkers, protocol distribution,
  per-flow table, connection timeline
- **Power-user**: bookmarks, regex search, anomaly highlighting (cleartext
  credentials / unusual ports), capture diff, one-shot/sample mode, saved filters
- scripting을 위한 **JSON output**; **process attribution** (Linux, macOS, Windows)
- **조밀한 terminal UI**: 256-color modern-dark theme, scrollable packet list,
  독립적으로 toggle 가능한 detail / hex pane

### Egress monitor (`rust-shark monitor` + `rust-shark inspect`)

background daemon이 지속적으로 capture하면서 각 flow의 5-tuple을 OS socket table을 통해
PID에 correlate하고, 목적지 **names**를 passive하게 resolve하며(DNS
answers + TLS SNI, decryption 없음), **offline country/ASN**으로 enrich하고,
**baseline**을 학습한 뒤 **다섯 가지 alert signal**을 발생시킵니다.

1. **New process → destination** — 어떤 process가 한 번도 접촉한 적 없는 domain/org에 접속
2. **New process phoning home** — 어떤 binary의 사상 첫 outbound connection
3. **New country / ASN** — 새로운 country 또는 network의 host와 첫 접촉
4. **Volume / exfil spike** — process의 baseline을 크게 상회하는 outbound volume
5. **Program modification** — process의 binary identity (macOS code signature /
   content hash)가 baseline 이후 변경된 뒤 외부로 connect

Monitor 전용(blocking 없음 — Little Snitch와의 의도적 차별점). inspector TUI는
live connections, per-process / per-domain breakdowns, time-travel history,
alerts feed를 보여줍니다.

## Installation

```bash
cargo install rust-shark
```

### Prerequisites

libpcap이 필요합니다(`rust-shark-core` engine이 이를 link합니다; `rusqlite`는 bundle되어 있습니다).

- **Linux**: `sudo apt install libpcap-dev` (Debian/Ubuntu) / `sudo dnf install libpcap-devel` (Fedora)
- **macOS**: `xcode-select --install`
- **Windows**: [Npcap](https://npcap.com/) 설치 ("WinPcap API-compatible Mode")

### Build from source

```bash
git clone https://github.com/jungho-dev/rust-shark.git
cd rust-shark
cargo build --release   # binary at target/release/rust-shark
```

이 프로젝트는 Cargo workspace입니다: `rust-shark-core` (재사용 가능한 engine) + `rust-shark`
(CLI binary).

## Permissions

Capture에는 root / BPF access가 필요합니다.

- **Linux**: `sudo rust-shark capture -i eth0`, 또는 `sudo setcap cap_net_raw+eip ./rust-shark`
- **macOS**: `sudo rust-shark capture -i en0`, 또는 본인을 `access_bpf`에 추가
- **Windows**: Npcap을 설치한 상태에서 Administrator로 실행

egress monitor는 추가로 모든 user에 걸친 완전한 socket→PID attribution을 위해 root의
혜택을 받습니다.

## Usage — packet analyzer

```bash
rust-shark list-interfaces
sudo rust-shark                                     # live TUI, auto-selects the active interface
sudo rust-shark capture -i en0                      # live TUI on a chosen interface
sudo rust-shark capture -i eth0 -f "tcp port 443"   # BPF filter
sudo rust-shark capture -i en0 -w out.pcapng --pcapng   # save PCAPNG
sudo rust-shark capture -i en0 --json -c 100        # one-shot: 100 packets as JSON
rust-shark read capture.pcap                        # offline (pcap or pcapng)
rust-shark diff a.pcap b.pcap                        # content diff
```

## Usage — egress monitor

```bash
# Start the daemon (foreground; --demo uses a 5s learning window so signals fire fast)
sudo rust-shark monitor run -i en0 --demo \
  --geoip-country-db ~/.local/share/rust-shark/dbip-country.mmdb \
  --geoip-asn-db ~/.local/share/rust-shark/dbip-asn.mmdb

rust-shark monitor status            # human or --json
rust-shark inspect                   # attach the inspector TUI
rust-shark inspect --json            # one-shot JSON dump (status + connections + alerts)
rust-shark monitor stop              # clean shutdown
```

`--daemonize`는 background로 detach합니다; `dist/`에는 이를 service로 실행하기 위한
launchd와 systemd template이 있습니다.

### Offline GeoIP / ASN data

Country와 ASN enrichment는 local MaxMind-format `.mmdb` file을 사용하며 runtime에
network를 전혀 건드리지 않습니다. 재배포 가능한 DB-IP Lite database를 받으세요.

```bash
scripts/fetch-geoip.sh             # downloads to your data dir; prints the paths
```

Data © [db-ip.com](https://db-ip.com), CC-BY-4.0. (`--geoip-*-db`를 본인 사본으로
지정하면 MaxMind GeoLite2도 동작합니다; bundle되거나 auto-fetch되지 않습니다.)
database가 없으면 country/ASN은 단순히 unknown으로 표시됩니다.

### Configuration

선택적 `~/.config/rust-shark/config.toml`:

```toml
[capture]
default_interface = "en0"        # used when -i is omitted

[display]
color_scheme = "dark"

[filters]                        # recall in the filter bar as :name
https = "tcp.port == 443"
dns   = "udp.port == 53"
```

## Keybindings

**Capture TUI:** `j`/`k` 이동, `g`/`G` top/bottom, `Space` pause, `/` filter
(`:name`은 saved filter를 recall), `s` save, `m` bookmark, `'` bookmarks,
`Ctrl-F` regex search (`n` next), `t` top talkers, `P` protocol distribution,
`F` flows, `T` timeline, `f` follow stream, `d` detail pane 토글, `x` hex pane 토글, `z` 두 pane
모두 토글, `Esc` overlay 닫기, `q` quit. packet list는 overflow 시 scrollbar를
표시합니다.

**Inspector:** `Tab`/`1`-`5` view 전환, `j`/`k` 이동, `/` search, `r`
refresh, `q` quit.

## Display filters

Protocol atoms: `tcp udp icmp icmpv6 arp ip ipv4 ipv6 dns tls`. Comparisons:
`ip.src == 10.0.0.1`, `tcp.port == 443`. Containment: `tls.sni contains
example.com`. Boolean: `and`/`&&`, `or`/`||`, `not`, 괄호.

## Architecture

- **`rust-shark-core`** — capture, decoders, flow tracking + reassembly, filters,
  process attribution, passive name resolution, GeoIP/identity enrichment,
  SQLite store, 5-signal alert engine, daemon + Unix-socket IPC,
  inspector reducer.
- **`rust-shark`** — CLI binary와 두 개의 ratatui frontend (capture TUI,
  inspector).

capture path는 bounded channel 위의 세 thread(capture → decode → UI)로 구성됩니다.
daemon은 correlate/detect worker와 IPC server를 추가하며; 단일 thread가 SQLite
writer를 소유합니다.

## Not yet implemented

솔직한 scope 메모: blocking/firewalling (설계상 monitor 전용); SNI를 위한 QUIC Initial
**decryption** (DNS에서 유도된 names가 동일 목적지를 cover함); HPACK Huffman literal
expansion (h2는 어차피 보통 TLS-encrypted됨); color-scheme theming과 keybinding remap
(config key는 예약됨); mmap disk-spill scrollback (큰 file은 bounded ring으로 stream됨;
모든 것을 보존하려면 pcap을 write); Windows process attribution은 가볍게만 테스트됨.

## License

Apache-2.0. GeoIP data를 받았다면 CC-BY-4.0 하에 © db-ip.com입니다.
