//! Shared building blocks for the RDP Monitor service, configuration utility
//! and offline signing tool.

pub mod config;
pub mod crypto;
pub mod ipc;
pub mod package;
pub mod password;
pub mod paths;
pub mod release;

/// Version of the installed product (taken from the workspace version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Converts a Rust string to a NUL-terminated UTF-16 buffer for Win32 calls.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Converts a (possibly NUL-terminated) UTF-16 buffer to a Rust string.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
