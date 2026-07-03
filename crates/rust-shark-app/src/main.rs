//! rust-shark application binary: CLI dispatch, capture pipeline, and TUI.

mod core;
#[cfg(unix)]
mod inspect;
mod tui;

use anyhow::Result;
use clap::Parser;
use core::cli::{Cli, Command, DEFAULT_BUFFER_SIZE, DEFAULT_SNAPLEN, MonitorAction};
use crossbeam_channel::bounded;
use rust_shark_core::{capture, decode, flow, output, process};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// 0. constants -------------------------------------------------------------------------
const CHANNEL_CAPACITY: usize = 10_000;

fn read_pcap(path: &std::path::PathBuf) -> Result<Vec<decode::DecodedPacket>> {
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = bounded(CHANNEL_CAPACITY);
    let handle = capture::file::start_file_capture(path, None, tx, stop.clone())?;
    let mut out = Vec::new();
    while let Ok(raw) = rx.recv() {
        out.push(decode::decode_packet(raw));
    }
    let _ = handle.join();
    Ok(out)
}
fn diff_cmd(file_a: PathBuf, file_b: PathBuf) -> Result<()> {
    let pa = read_pcap(&file_a)?;
    let pb = read_pcap(&file_b)?;
    let d = rust_shark_core::diff::diff_by_content(&pa, &pb);
    println!("{}: {} packets", file_a.display(), pa.len());
    println!("{}: {} packets", file_b.display(), pb.len());
    println!("common: {}", d.common);
    println!("only in A ({}):", d.only_a.len());
    for &i in d.only_a.iter().take(20) {
        println!("  - #{} {}", pa[i].number, pa[i].summary.info);
    }
    println!("only in B ({}):", d.only_b.len());
    for &i in d.only_b.iter().take(20) {
        println!("  + #{} {}", pb[i].number, pb[i].summary.info);
    }
    Ok(())
}
#[cfg(unix)]
fn inspect_cmd(state_dir: Option<PathBuf>, socket: Option<PathBuf>, json: bool) -> Result<()> {
    let sock = socket.unwrap_or_else(|| rust_shark_core::monitor::paths::resolve(state_dir).socket);
    if json {
        inspect_json(&sock)
    } else {
        inspect::run_inspector(&sock)
    }
}
#[cfg(unix)]
fn inspect_json(sock: &std::path::Path) -> Result<()> {
    use rust_shark_core::ipc::{IpcClient, Request, Response};
    let mut client = IpcClient::connect(sock)?;
    let status = match client.request(&Request::Status)? {
        Response::Status(s) => Some(s),
        _ => None,
    };
    let connections = match client.request(&Request::LiveConnections)? {
        Response::Connections(v) => v,
        _ => vec![],
    };
    let alerts = match client.request(&Request::RecentAlerts { limit: 200 })? {
        Response::Alerts(v) => v,
        _ => vec![],
    };
    let out = serde_json::json!({
      "status": status,
      "connections": connections,
      "alerts": alerts,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
#[cfg(not(unix))]
fn inspect_cmd(_state_dir: Option<PathBuf>, _socket: Option<PathBuf>, _json: bool) -> Result<()> {
    anyhow::bail!("the inspector is only supported on Unix")
}
#[cfg(unix)]
static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_signal(_sig: libc::c_int) {
    SIGNAL_STOP.store(true, Ordering::Relaxed);
}
#[cfg(unix)]
fn install_signal_handlers(stop: Arc<AtomicBool>) {
    // SAFETY: handler only performs an atomic store, which is async-signal-safe.
    let handler = handle_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
    std::thread::spawn(move || {
        while !SIGNAL_STOP.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        stop.store(true, Ordering::Relaxed);
    });
}
#[cfg(unix)]
fn monitor_cmd(action: MonitorAction) -> Result<()> {
    use rust_shark_core::alert::AlertConfig;
    use rust_shark_core::monitor::{self, MonitorConfig};

    match action {
        MonitorAction::Run {
            interface,
            filter,
            snaplen,
            state_dir,
            geoip_country_db,
            geoip_asn_db,
            demo,
            daemonize,
            no_notify,
        } => {
            permissions::check_capture_permissions()?;
            let paths = monitor::paths::resolve(state_dir);
            std::fs::create_dir_all(&paths.state_dir).ok();
            if daemonize {
                monitor::daemonize::daemonize(&paths.log)?;
            }
            let stop = Arc::new(AtomicBool::new(false));
            install_signal_handlers(stop.clone());
            let alert = if demo {
                AlertConfig::demo()
            } else {
                AlertConfig::default()
            };
            eprintln!(
                "rust-shark monitor: interface={interface} filter={filter:?} snaplen={snaplen} demo={demo} daemonize={daemonize} notify={} db={} socket={} geoip_country={geoip_country_db:?} geoip_asn={geoip_asn_db:?}",
                !no_notify,
                paths.db.display(),
                paths.socket.display()
            );
            let cfg = MonitorConfig {
                interface,
                bpf: filter,
                snaplen,
                db_path: paths.db,
                socket_path: paths.socket,
                geoip_country: geoip_country_db,
                geoip_asn: geoip_asn_db,
                alert,
                notify: !no_notify,
            };
            monitor::run_monitor(cfg, stop)
        }
        MonitorAction::Status { state_dir, json } => {
            let paths = monitor::paths::resolve(state_dir);
            let status = monitor::monitor_status(&paths.socket)?;
            if json {
                println!("{}", serde_json::to_string(&status)?);
            } else {
                println!(
                    "rust-shark monitor — {} (pid {})",
                    status.baseline, status.pid
                );
                println!("  interface:    {}", status.interface);
                println!("  uptime:       {}s", status.uptime_secs);
                println!(
                    "  processes:    {}\n  destinations: {}\n  alerts:       {}",
                    status.processes, status.destinations, status.alerts
                );
            }
            Ok(())
        }
        MonitorAction::Stop { state_dir } => {
            let paths = monitor::paths::resolve(state_dir);
            monitor::monitor_stop(&paths.socket)?;
            println!("monitor stopping");
            Ok(())
        }
    }
}
#[cfg(not(unix))]
fn monitor_cmd(_action: MonitorAction) -> Result<()> {
    anyhow::bail!("the egress monitor daemon is only supported on Unix")
}
fn list_interfaces() -> Result<()> {
    let devices = pcap::Device::list()?;
    if devices.is_empty() {
        println!("No interfaces found. You may need elevated privileges.");
        return Ok(());
    }
    for dev in devices {
        let desc = dev.desc.as_deref().unwrap_or("No description");
        let addrs: Vec<String> = dev.addresses.iter().map(|a| a.addr.to_string()).collect();
        let addr_str = if addrs.is_empty() {
            String::new()
        } else {
            format!(" [{}]", addrs.join(", "))
        };
        println!("  {}: {}{}", dev.name, desc, addr_str);
    }
    Ok(())
}
/// Pick a sensible default capture interface when the user gives no `-i`.
///
/// `pcap::Device::lookup()` is unreliable on Windows/Npcap: it often returns a
/// WAN Miniport or other virtual adapter that carries no traffic, so capture
/// silently shows zero packets. Instead, scan every device and prefer the
/// active NIC — up, running, connected, non-loopback, with a real
/// (non-link-local) IPv4 address.
fn pick_default_interface() -> Option<String> {
    fn has_real_ipv4(dev: &pcap::Device) -> bool {
        dev.addresses.iter().any(|a| match a.addr {
            std::net::IpAddr::V4(ip) => {
                !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()
            }
            _ => false,
        })
    }
    fn is_active(dev: &pcap::Device) -> bool {
        !dev.flags.is_loopback()
            && dev.flags.is_up()
            && dev.flags.is_running()
            && dev.flags.connection_status == pcap::ConnectionStatus::Connected
            && has_real_ipv4(dev)
    }

    let devices = pcap::Device::list().ok()?;
    devices
        .iter()
        .find(|d| is_active(d))
        .or_else(|| {
            devices
                .iter()
                .find(|d| !d.flags.is_loopback() && has_real_ipv4(d))
        })
        .map(|d| d.name.clone())
        .or_else(|| pcap::Device::lookup().ok().flatten().map(|d| d.name))
}
/// All IP addresses bound to the named capture interface. The TUI uses these to
/// classify packet direction (IN/OUT). Empty when the device can't be resolved
/// (the TUI then falls back to a private/public heuristic).
fn interface_ips(name: &str) -> Vec<std::net::IpAddr> {
    pcap::Device::list()
        .ok()
        .into_iter()
        .flatten()
        .find(|d| d.name == name)
        .map(|d| d.addresses.iter().map(|a| a.addr).collect())
        .unwrap_or_default()
}
fn decode_thread(
    raw_rx: crossbeam_channel::Receiver<capture::RawPacket>,
    decoded_tx: crossbeam_channel::Sender<decode::DecodedPacket>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let mut flow_tracker = flow::tracker::FlowTracker::new();

    while !stop.load(Ordering::Relaxed) {
        match raw_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(raw) => {
                let mut decoded = decode::decode_packet(raw);

                flow_tracker.update(&mut decoded);

                decoded.process = try_process_lookup(&decoded);

                if decoded_tx.send(decoded).is_err() {
                    break;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }
    Ok(())
}
fn try_process_lookup(pkt: &decode::DecodedPacket) -> Option<decode::ProcessInfo> {
    for layer in &pkt.layers {
        match layer {
            decode::Layer::Tcp(tcp) => {
                if let Some(ip) = find_local_ip(pkt) {
                    return process::lookup_process(6, ip, tcp.src_port)
                        .or_else(|| process::lookup_process(6, ip, tcp.dst_port));
                }
            }
            decode::Layer::Udp(udp) => {
                if let Some(ip) = find_local_ip(pkt) {
                    return process::lookup_process(17, ip, udp.src_port)
                        .or_else(|| process::lookup_process(17, ip, udp.dst_port));
                }
            }
            _ => {}
        }
    }
    None
}
fn find_local_ip(pkt: &decode::DecodedPacket) -> Option<std::net::IpAddr> {
    for layer in &pkt.layers {
        match layer {
            decode::Layer::Ipv4(ip) => {
                return Some(std::net::IpAddr::V4(ip.src_ip));
            }
            decode::Layer::Ipv6(ip) => {
                return Some(std::net::IpAddr::V6(ip.src_ip));
            }
            _ => {}
        }
    }
    None
}
fn json_output_loop(
    rx: crossbeam_channel::Receiver<decode::DecodedPacket>,
    stop: Arc<AtomicBool>,
    count: Option<u64>,
    duration: Option<u64>,
) -> Result<()> {
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    let start = std::time::Instant::now();
    let mut emitted = 0u64;
    while !stop.load(Ordering::Relaxed) {
        if let Some(secs) = duration {
            if start.elapsed().as_secs() >= secs {
                break;
            }
        }
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(pkt) => {
                output::json::write_json_line(&mut writer, &pkt)?;
                emitted += 1;
                if let Some(c) = count {
                    if emitted >= c {
                        break;
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }
    // One-shot: signal the capture/decode threads to wind down.
    stop.store(true, Ordering::Relaxed);
    Ok(())
}
// 99. main -----------------------------------------------------------------------------
fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = core::config::Config::load();

    // No subcommand → start the live-capture TUI on the default interface.
    let command = cli.command.unwrap_or(Command::Capture {
        interface: None,
        filter: None,
        write: None,
        pcapng: false,
        json: false,
        snaplen: DEFAULT_SNAPLEN,
        buffer_size: DEFAULT_BUFFER_SIZE,
        count: None,
        duration: None,
    });

    match command {
        Command::ListInterfaces => list_interfaces(),
        Command::Capture {
            interface,
            filter,
            write,
            pcapng,
            json,
            snaplen,
            buffer_size,
            count,
            duration,
        } => {
            core::permissions::check_capture_permissions()?;
            let interface = match interface.or_else(|| config.capture.default_interface.clone()) {
                Some(iface) => iface,
                None => {
                    let auto = pick_default_interface().ok_or_else(|| anyhow::anyhow!("no interface specified (use -i <iface> or set capture.default_interface in config.toml)"))?;
                    eprintln!(
                        "rust-shark: auto-selected interface {auto} (override with -i <iface>)"
                    );
                    auto
                }
            };

            let local_ips = interface_ips(&interface);

            // Effective capture parameters, always echoed to stderr at startup
            // (does not corrupt --json stdout). RUST_SHARK_DEBUG adds IPC tracing.
            eprintln!(
                "rust-shark capture: interface={interface} filter={filter:?} snaplen={snaplen} buffer_size={buffer_size} write={write:?} pcapng={pcapng} json={json} count={count:?} duration={duration:?} local_ips={local_ips:?}"
            );

            let stop = Arc::new(AtomicBool::new(false));

            let (raw_tx, raw_rx) = bounded(CHANNEL_CAPACITY);
            let (decoded_tx, decoded_rx) = bounded(CHANNEL_CAPACITY);

            let capture_handle = capture::live::start_live_capture(
                &interface,
                filter.as_deref(),
                snaplen,
                raw_tx,
                stop.clone(),
            )?;

            let decode_stop = stop.clone();
            let decode_handle = std::thread::Builder::new()
                .name("decode".into())
                .spawn(move || decode_thread(raw_rx, decoded_tx, decode_stop))?;

            if json {
                json_output_loop(decoded_rx, stop.clone(), count, duration)?;
            } else {
                tui::run_tui(
                    decoded_rx,
                    buffer_size,
                    write.as_deref(),
                    config.filters.clone(),
                    pcapng,
                    local_ips,
                )?;
            }
            stop.store(true, Ordering::Relaxed);
            let _ = capture_handle.join();
            let _ = decode_handle.join();
            Ok(())
        }
        Command::Read {
            file,
            filter,
            json,
            buffer_size,
        } => {
            eprintln!(
                "rust-shark read: file={} filter={filter:?} json={json} buffer_size={buffer_size}",
                file.display()
            );

            let stop = Arc::new(AtomicBool::new(false));

            let (raw_tx, raw_rx) = bounded(CHANNEL_CAPACITY);
            let (decoded_tx, decoded_rx) = bounded(CHANNEL_CAPACITY);

            let capture_handle =
                capture::file::start_file_capture(&file, filter.as_deref(), raw_tx, stop.clone())?;

            let decode_stop = stop.clone();
            let decode_handle = std::thread::Builder::new()
                .name("decode".into())
                .spawn(move || decode_thread(raw_rx, decoded_tx, decode_stop))?;

            if json {
                json_output_loop(decoded_rx, stop.clone(), None, None)?;
            } else {
                tui::run_tui(
                    decoded_rx,
                    buffer_size,
                    None,
                    config.filters.clone(),
                    false,
                    Vec::new(),
                )?;
            }
            stop.store(true, Ordering::Relaxed);
            let _ = capture_handle.join();
            let _ = decode_handle.join();
            Ok(())
        }
        Command::Monitor { action } => monitor_cmd(action),
        Command::Inspect {
            state_dir,
            socket,
            json,
        } => inspect_cmd(state_dir, socket, json),
        Command::Diff { file_a, file_b } => diff_cmd(file_a, file_b),
    }
}
