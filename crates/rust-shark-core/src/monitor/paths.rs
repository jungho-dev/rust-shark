use std::path::PathBuf;

/// Filesystem locations for the daemon's runtime state.
pub struct Paths {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub db: PathBuf,
    pub pidfile: PathBuf,
    pub log: PathBuf,
}

/// Resolve runtime paths, defaulting to the platform's local data directory
/// (`~/Library/Application Support/rust-shark` on macOS, `~/.local/share/rust-shark`
/// on Linux).
pub fn resolve(state_dir: Option<PathBuf>) -> Paths {
    let dir = state_dir.unwrap_or_else(default_state_dir);
    Paths {
        socket: dir.join("rust-shark.sock"),
        db: dir.join("rust-shark.db"),
        pidfile: dir.join("rust-shark.pid"),
        log: dir.join("monitor.log"),
        state_dir: dir,
    }
}

fn default_state_dir() -> PathBuf {
    dirs::data_local_dir()
        .map(|d| d.join("rust-shark"))
        .unwrap_or_else(|| PathBuf::from("/tmp/rust-shark"))
}
