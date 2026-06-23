//! Human-readable text-log export of the packets currently shown in the TUI.
//!
//! Distinct from the pcap/pcapng writers: this produces a flat, greppable
//! summary (one line per packet) including direction, owning process, and any
//! live threat annotation, so a capture can be saved as a plain `.log` for
//! sharing or post-hoc inspection.

use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;

use crate::decode::{DecodedPacket, Direction};

/// Write `packets` to `path` as a plain-text log: a header line, then one line
/// per packet. `local_ips` drives the Dir (IN/OUT) column; pass an empty slice
/// to fall back to the private/public heuristic. Threat-flagged packets get a
/// trailing `[KIND: detail]` marker. Returns the number of packet lines written.
pub fn write_packet_log<'a, I>(path: &Path, packets: I, local_ips: &[IpAddr]) -> io::Result<usize>
where
    I: IntoIterator<Item = &'a DecodedPacket>,
{
    let file = std::fs::File::create(path)?;
    let mut w = io::BufWriter::new(file);
    writeln!(w, "# rust-shark packet log")?;
    writeln!(
        w,
        "{:>7}  {:<3}  {:<12}  {:<14}  {:<21}  {:<21}  {:<6}  {:>6}  info",
        "No.", "Dir", "Time", "Process", "Source", "Destination", "Proto", "Len"
    )?;
    let mut count = 0usize;
    for pkt in packets {
        let dir = match pkt.direction(local_ips) {
            Direction::In => "IN",
            Direction::Out => "OUT",
            Direction::Unknown => "-",
        };
        let proc: String = pkt
            .process
            .as_ref()
            .map(|p| p.name.as_str())
            .unwrap_or("-")
            .chars()
            .take(14)
            .collect();
        let marker = match &pkt.threat {
            Some(t) => format!("  [{}: {}]", t.kind.label(), t.detail),
            None => String::new(),
        };
        writeln!(
            w,
            "{:>7}  {:<3}  {:<12}  {:<14}  {:<21}  {:<21}  {:<6}  {:>6}  {}{}",
            pkt.number,
            dir,
            pkt.timestamp.format("%H:%M:%S%.3f"),
            proc,
            pkt.summary.source,
            pkt.summary.destination,
            pkt.summary.protocol,
            pkt.summary.length,
            pkt.summary.info,
            marker
        )?;
        count += 1;
    }
    w.flush()?;
    Ok(count)
}
