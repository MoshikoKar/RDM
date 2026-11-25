//! Reverse name lookup of a connection's source IP for the alert email.
//!
//! Uses GetNameInfoW, which asks DNS (PTR record) and, where enabled,
//! NetBIOS / LLMNR. A lookup that does not answer in time is abandoned so a
//! slow or unreachable DNS server never delays monitoring.

use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::Once;
use std::time::Duration;
use windows_sys::Win32::Networking::WinSock::{
    GetNameInfoW, WSAStartup, AF_INET, AF_INET6, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, WSADATA,
};

pub const TIMEOUT: Duration = Duration::from_secs(3);

/// Host name of `ip`, or None when it cannot be resolved within `timeout`.
pub fn hostname(ip: &str, timeout: Duration) -> Option<String> {
    let addr: IpAddr = ip.trim().trim_start_matches('[').trim_end_matches(']').parse().ok()?;
    let addr = match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        a => a,
    };
    if addr.is_loopback() || addr.is_unspecified() {
        return None;
    }
    let (tx, rx) = mpsc::channel();
    // Detached: if the lookup overruns, the thread finishes on its own and
    // its result is discarded.
    std::thread::Builder::new()
        .name("rdpmon-resolve".into())
        .spawn(move || {
            let _ = tx.send(lookup(addr));
        })
        .ok()?;
    rx.recv_timeout(timeout).ok().flatten()
}

fn lookup(addr: IpAddr) -> Option<String> {
    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe {
        let mut data: WSADATA = std::mem::zeroed();
        WSAStartup(0x0202, &mut data);
    });
    let mut name = [0u16; 1025]; // NI_MAXHOST
    let rc = unsafe {
        match addr {
            IpAddr::V4(v4) => {
                let mut sa: SOCKADDR_IN = std::mem::zeroed();
                sa.sin_family = AF_INET;
                sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
                GetNameInfoW(&sa as *const _ as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN>() as i32, name.as_mut_ptr(), name.len() as u32, std::ptr::null_mut(), 0, NI_NAMEREQD as i32)
            }
            IpAddr::V6(v6) => {
                let mut sa: SOCKADDR_IN6 = std::mem::zeroed();
                sa.sin6_family = AF_INET6;
                sa.sin6_addr.u.Byte = v6.octets();
                GetNameInfoW(&sa as *const _ as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN6>() as i32, name.as_mut_ptr(), name.len() as u32, std::ptr::null_mut(), 0, NI_NAMEREQD as i32)
            }
        }
    };
    if rc != 0 {
        return None;
    }
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let s: String = String::from_utf16_lossy(&name[..len]).trim().trim_end_matches('.').chars().filter(|c| !c.is_control()).take(255).collect();
    (!s.is_empty() && s.parse::<IpAddr>().is_err()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unusable_input() {
        assert_eq!(hostname("not an ip", TIMEOUT), None);
        assert_eq!(hostname("127.0.0.1", TIMEOUT), None);
        assert_eq!(hostname("::1", TIMEOUT), None);
        assert_eq!(hostname("-", TIMEOUT), None);
    }
}
