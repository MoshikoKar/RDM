use std::path::PathBuf;

pub const SERVICE_NAME: &str = "RDPMonitor";
pub const SERVICE_DISPLAY_NAME: &str = "RDP Monitor";
pub const PIPE_NAME: &str = r"\\.\pipe\RDPMonitor.Admin";
pub const PRODUCT_REGISTRY_KEY: &str = r"SOFTWARE\RDP Monitor";

/// `C:\ProgramData\RDP Monitor` - configuration, history, queue and logs.
/// Nothing mutable is ever stored in the installation directory.
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("RDP Monitor")
}
