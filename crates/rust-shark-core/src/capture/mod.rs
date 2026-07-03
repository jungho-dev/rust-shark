pub mod file;
pub mod live;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub number: u64,
    pub timestamp: DateTime<Utc>,
    pub wire_len: u32,
    pub data: Vec<u8>,
    pub linktype: Linktype,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Linktype {
    Ethernet,
    RawIp,
    Other(u16),
}

impl From<pcap::Linktype> for Linktype {
    fn from(lt: pcap::Linktype) -> Self {
        match lt.0 {
            1 => Linktype::Ethernet,
            101 | 228 => Linktype::RawIp,
            other => Linktype::Other(other as u16),
        }
    }
}

impl Linktype {
    pub fn to_pcap_linktype(self) -> u32 {
        match self {
            Linktype::Ethernet => 1,
            Linktype::RawIp => 101,
            Linktype::Other(v) => v as u32,
        }
    }
}

pub(crate) fn capture_loop<T: pcap::Activated + Send>(
    mut cap: pcap::Capture<T>,
    tx: crossbeam_channel::Sender<RawPacket>,
    stop: Arc<AtomicBool>,
    linktype: Linktype,
    counter: &AtomicU64,
) -> anyhow::Result<()> {
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match cap.next_packet() {
            Ok(packet) => {
                let num = counter.fetch_add(1, Ordering::Relaxed);
                let ts = packet.header.ts;
                // A crafted/corrupt pcap can carry an out-of-range tv_usec; widen
                // before the *1000 so the multiply cannot overflow, then clamp to ns.
                let nsec = (ts.tv_usec as i64)
                    .saturating_mul(1000)
                    .clamp(0, 999_999_999) as u32;
                let timestamp =
                    DateTime::from_timestamp(ts.tv_sec as i64, nsec).unwrap_or_default();
                let raw = RawPacket {
                    number: num,
                    timestamp,
                    wire_len: packet.header.len,
                    data: packet.data.to_vec(),
                    linktype,
                };
                if tx.send(raw).is_err() {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                if !stop.load(Ordering::Relaxed) {
                    return Err(e.into());
                }
                break;
            }
        }
    }
    Ok(())
}
