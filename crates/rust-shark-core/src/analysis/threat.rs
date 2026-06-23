//! Stateful live threat heuristics over the decoded packet stream.
//!
//! Unlike the stateless [`super::anomaly`] checks, this detector keeps a short
//! sliding history per source address so reconnaissance patterns — port scans
//! and host sweeps ("someone is scanning me") — become visible across packets.
//! It also flags cleartext traffic to uncommon ports on public hosts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::decode::{DecodedPacket, Layer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatKind {
    /// One source sending connection attempts to many distinct ports on a host.
    PortScan,
    /// One source touching many distinct hosts in a short window.
    HostSweep,
    /// Cleartext traffic to an uncommon port on a public (non-private) host.
    RareExternal,
}

impl ThreatKind {
    /// Short tag shown in the packet list / log and matched by the filter.
    pub fn label(self) -> &'static str {
        match self {
            ThreatKind::PortScan => "PORT-SCAN",
            ThreatKind::HostSweep => "HOST-SWEEP",
            ThreatKind::RareExternal => "RARE-DEST",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatAnnotation {
    pub kind: ThreatKind,
    pub detail: String,
}

/// Sliding window for the recon detectors.
const SCAN_WINDOW_MS: i64 = 10_000;
/// Distinct dst ports from one source to one host that trip a port-scan.
const PORT_SCAN_MIN_PORTS: usize = 15;
/// Distinct dst hosts from one source that trip a host-sweep.
const HOST_SWEEP_MIN_HOSTS: usize = 12;

/// Common service ports that never count as a "rare" external destination.
const COMMON_PORTS: &[u16] = &[
    20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3389, 8080, 8443,
];

/// Per-source ring of recent connection-initiation events.
#[derive(Default)]
struct SrcWindow {
    /// Kept within the window: (ts_ms, dst, dst_port).
    events: VecDeque<(i64, IpAddr, u16)>,
}

impl SrcWindow {
    fn record(&mut self, ts: i64, dst: IpAddr, port: u16, cutoff: i64) {
        self.events.push_back((ts, dst, port));
        while let Some(&(t, _, _)) = self.events.front() {
            if t < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// `(dst, distinct_port_count)` for the host this source probed most.
    fn busiest_dst(&self) -> Option<(IpAddr, usize)> {
        let mut per_dst: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
        for &(_, dst, port) in &self.events {
            per_dst.entry(dst).or_default().insert(port);
        }
        per_dst
            .into_iter()
            .map(|(dst, ports)| (dst, ports.len()))
            .max_by_key(|&(_, n)| n)
    }

    fn distinct_hosts(&self) -> usize {
        self.events
            .iter()
            .map(|&(_, dst, _)| dst)
            .collect::<HashSet<_>>()
            .len()
    }
}

/// Tracks per-source recon activity across the live packet stream. One instance
/// lives for the whole capture session and is fed every packet in arrival order.
#[derive(Default)]
pub struct ThreatTracker {
    sources: HashMap<IpAddr, SrcWindow>,
}

impl ThreatTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inspect one packet and return a threat annotation if it participates in a
    /// recon pattern or contacts a rare external destination. Recon detectors
    /// only advance on connection-initiation signals (pure SYN / ICMP echo) so
    /// established conversations do not look like scans.
    pub fn observe(&mut self, pkt: &DecodedPacket) -> Option<ThreatAnnotation> {
        let conn = extract_conn(pkt)?;
        let now = pkt.timestamp.timestamp_millis();

        if conn.syn_only || conn.icmp_echo {
            let win = self.sources.entry(conn.src).or_default();
            win.record(now, conn.dst, conn.dport, now - SCAN_WINDOW_MS);

            if let Some((dst, ports)) = win.busiest_dst() {
                if ports >= PORT_SCAN_MIN_PORTS {
                    return Some(ThreatAnnotation {
                        kind: ThreatKind::PortScan,
                        detail: format!(
                            "{} probed {ports} ports on {dst} within {}s",
                            conn.src,
                            SCAN_WINDOW_MS / 1000
                        ),
                    });
                }
            }
            let hosts = win.distinct_hosts();
            if hosts >= HOST_SWEEP_MIN_HOSTS {
                return Some(ThreatAnnotation {
                    kind: ThreatKind::HostSweep,
                    detail: format!(
                        "{} contacted {hosts} hosts within {}s",
                        conn.src,
                        SCAN_WINDOW_MS / 1000
                    ),
                });
            }
        }

        if is_cleartext(pkt)
            && conn.dport != 0
            && is_public(conn.dst)
            && !COMMON_PORTS.contains(&conn.dport)
        {
            return Some(ThreatAnnotation {
                kind: ThreatKind::RareExternal,
                detail: format!("cleartext to {}:{} (uncommon port)", conn.dst, conn.dport),
            });
        }

        None
    }
}

struct Conn {
    src: IpAddr,
    dst: IpAddr,
    dport: u16,
    syn_only: bool,
    icmp_echo: bool,
}

fn extract_conn(pkt: &DecodedPacket) -> Option<Conn> {
    let mut src = None;
    let mut dst = None;
    let mut dport = 0u16;
    let mut syn_only = false;
    let mut icmp_echo = false;
    for l in &pkt.layers {
        match l {
            Layer::Ipv4(ip) => {
                src = Some(IpAddr::V4(ip.src_ip));
                dst = Some(IpAddr::V4(ip.dst_ip));
            }
            Layer::Ipv6(ip) => {
                src = Some(IpAddr::V6(ip.src_ip));
                dst = Some(IpAddr::V6(ip.dst_ip));
            }
            Layer::Tcp(t) => {
                dport = t.dst_port;
                syn_only = t.flags.syn && !t.flags.ack;
            }
            Layer::Udp(u) => dport = u.dst_port,
            Layer::Icmp(ic) => icmp_echo = ic.icmp_type == 8,
            Layer::Icmpv6(ic) => icmp_echo = ic.icmp_type == 128,
            _ => {}
        }
    }
    Some(Conn {
        src: src?,
        dst: dst?,
        dport,
        syn_only,
        icmp_echo,
    })
}

/// True when the packet carries no encrypted application layer.
fn is_cleartext(pkt: &DecodedPacket) -> bool {
    !pkt.layers.iter().any(|l| {
        matches!(
            l,
            Layer::TlsClientHello(_) | Layer::TlsHandshake(_) | Layer::Quic(_)
        )
    })
}

/// Conservative "routable public address" test (no unstable `is_global`).
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::*;
    use chrono::DateTime;
    use std::net::Ipv4Addr;

    fn syn(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, ts_ms: i64) -> DecodedPacket {
        DecodedPacket {
            number: 0,
            timestamp: DateTime::from_timestamp_millis(ts_ms).unwrap(),
            wire_len: 60,
            data: vec![],
            layers: vec![
                Layer::Ipv4(Ipv4Header {
                    version: 4,
                    ihl: 5,
                    dscp: 0,
                    ecn: 0,
                    total_length: 40,
                    identification: 0,
                    flags: 0,
                    fragment_offset: 0,
                    ttl: 64,
                    protocol: 6,
                    checksum: 0,
                    src_ip: src,
                    dst_ip: dst,
                    header_range: (0, 20),
                }),
                Layer::Tcp(TcpHeader {
                    src_port: 40000,
                    dst_port: dport,
                    seq_num: 0,
                    ack_num: 0,
                    data_offset: 5,
                    flags: TcpFlags::from_bits(0x02),
                    window_size: 1024,
                    checksum: 0,
                    urgent_pointer: 0,
                    payload_len: 0,
                    header_range: (20, 40),
                }),
            ],
            summary: PacketSummary {
                source: src.to_string(),
                destination: dst.to_string(),
                protocol: "TCP".into(),
                length: 60,
                info: String::new(),
                color_hint: ColorHint::Tcp,
            },
            process: None,
            retransmission: false,
            threat: None,
        }
    }

    #[test]
    fn detects_port_scan() {
        let mut t = ThreatTracker::new();
        let attacker = Ipv4Addr::new(192, 168, 1, 66);
        let victim = Ipv4Addr::new(192, 168, 1, 10);
        let mut hit = None;
        for port in 1..=PORT_SCAN_MIN_PORTS as u16 {
            hit = t.observe(&syn(attacker, victim, port, 1_000 + port as i64));
        }
        assert!(matches!(
            hit,
            Some(ThreatAnnotation {
                kind: ThreatKind::PortScan,
                ..
            })
        ));
    }

    #[test]
    fn normal_handshake_is_quiet() {
        let mut t = ThreatTracker::new();
        let me = Ipv4Addr::new(192, 168, 1, 5);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        assert!(t.observe(&syn(me, server, 80, 1_000)).is_none());
        assert!(t.observe(&syn(me, server, 443, 1_100)).is_none());
    }
}
