//! Opt-in developer tracing. Set `RUST_SHARK_DEBUG=1` to print effective
//! parameters and IPC traffic (client requests, server responses, daemon
//! config) to stderr. Off by default so normal output stays clean; the flag is
//! read once and cached, so guarded call sites pay only an atomic load.

use std::sync::OnceLock;

// 1. flag state ---------------------------------------------------------------

/// True when `RUST_SHARK_DEBUG` is set to a non-empty value other than `0`.
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("RUST_SHARK_DEBUG")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    })
}

/// Emit `[debug] <tag>: <msg>` to stderr when tracing is enabled; a no-op
/// otherwise. `tag` names the source (e.g. `capture`, `ipc-client`, `monitor`).
pub fn log(tag: &str, msg: &str) {
    if enabled() {
        eprintln!("[debug] {tag}: {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_is_silent_without_the_env_flag() {
        // Without RUST_SHARK_DEBUG set, enabled() is false and log() must not
        // panic or emit. (We can't assert on stderr here, only on the guard.)
        if std::env::var_os("RUST_SHARK_DEBUG").is_none() {
            assert!(!enabled());
        }
        log("test", "this line is suppressed unless the flag is on");
    }
}
