pub fn check_capture_permissions() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err(rust_shark_core::error::RustSharkError::Permission(
                "Requires root privileges. Run with sudo, or grant cap_net_raw:\n  \
                 sudo setcap cap_net_raw+eip ./rust-shark"
                    .into(),
            )
            .into());
        }
    }
    #[cfg(target_os = "windows")]
    {
        eprintln!(
            "Note: Ensure Npcap is installed (https://npcap.com) and run from an Administrator prompt."
        );
    }

    Ok(())
}
