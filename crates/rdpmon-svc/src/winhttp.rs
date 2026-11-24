//! Minimal HTTPS GET client on WinHTTP: system proxy configuration, Windows
//! certificate validation (SChannel), no automatic redirects (the caller
//! decides which redirects to follow and which headers to forward).

use rdpmon_core::wide;
use std::io::Write;
use windows_sys::Win32::Networking::WinHttp::*;

pub struct Response {
    pub status: u16,
    pub location: Option<String>,
    /// Body for non-2xx responses or when no sink was supplied (bounded).
    pub body: Vec<u8>,
}

struct H(*mut std::ffi::c_void);

impl Drop for H {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

/// Splits an https URL into (host, port, path-and-query).
pub fn split_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| format!("only https:// URLs are allowed ({url})"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("invalid URL host in {url}"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h.to_string(), p.parse().map_err(|_| format!("invalid port in {url}"))?),
        _ => (authority.to_string(), 443),
    };
    Ok((host.to_ascii_lowercase(), port, path.to_string()))
}

fn last_err(what: &str) -> String {
    let e = std::io::Error::last_os_error();
    let hint = match e.raw_os_error() {
        Some(12007) => " (host name not found)",
        Some(12029) | Some(12030) => " (cannot connect - check network and proxy)",
        Some(12002) => " (timed out)",
        Some(12175) | Some(12045) | Some(12169) | Some(12038) | Some(12037) => " (TLS certificate is not valid or not trusted)",
        _ => "",
    };
    format!("{what} failed: {e}{hint}")
}

pub fn get(url: &str, headers: &[(&str, String)], max_bytes: u64, mut sink: Option<&mut dyn Write>) -> Result<Response, String> {
    let (host, port, path) = split_url(url)?;
    let agent = wide(&format!("RDPMonitor-Updater/{}", rdpmon_core::VERSION));
    unsafe {
        let mut session = H(WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, std::ptr::null(), std::ptr::null(), 0));
        if session.0.is_null() {
            session = H(WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, std::ptr::null(), std::ptr::null(), 0));
        }
        if session.0.is_null() {
            return Err(last_err("WinHttpOpen"));
        }
        WinHttpSetTimeouts(session.0, 15_000, 15_000, 30_000, 60_000);
        let host_w = wide(&host);
        let conn = H(WinHttpConnect(session.0, host_w.as_ptr(), port, 0));
        if conn.0.is_null() {
            return Err(last_err(&format!("connect to {host}")));
        }
        let verb = wide("GET");
        let path_w = wide(&path);
        let req = H(WinHttpOpenRequest(conn.0, verb.as_ptr(), path_w.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), WINHTTP_FLAG_SECURE));
        if req.0.is_null() {
            return Err(last_err("open request"));
        }
        let policy: u32 = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(req.0, WINHTTP_OPTION_REDIRECT_POLICY, &policy as *const u32 as *const _, 4);
        // Never answer NTLM/Negotiate challenges with the computer account.
        let logon: u32 = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
        WinHttpSetOption(req.0, WINHTTP_OPTION_AUTOLOGON_POLICY, &logon as *const u32 as *const _, 4);
        if !headers.is_empty() {
            let text: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
            if text.contains('\0') || headers.iter().any(|(k, v)| k.contains(['\r', '\n']) || v.contains(['\r', '\n'])) {
                return Err("invalid header value".into());
            }
            let w = wide(&text);
            if WinHttpAddRequestHeaders(req.0, w.as_ptr(), (w.len() - 1) as u32, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) == 0 {
                return Err(last_err("add headers"));
            }
        }
        if WinHttpSendRequest(req.0, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) == 0 {
            return Err(last_err(&format!("request to {host}")));
        }
        if WinHttpReceiveResponse(req.0, std::ptr::null_mut()) == 0 {
            return Err(last_err(&format!("response from {host}")));
        }
        let mut status: u32 = 0;
        let mut len: u32 = 4;
        WinHttpQueryHeaders(req.0, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, std::ptr::null(), &mut status as *mut u32 as *mut _, &mut len, std::ptr::null_mut());
        let mut location = None;
        if (300..400).contains(&status) {
            let mut buf = vec![0u16; 4096];
            let mut blen = (buf.len() * 2) as u32;
            if WinHttpQueryHeaders(req.0, WINHTTP_QUERY_LOCATION, std::ptr::null(), buf.as_mut_ptr() as *mut _, &mut blen, std::ptr::null_mut()) != 0 {
                location = Some(String::from_utf16_lossy(&buf[..(blen / 2) as usize]));
            }
        }
        let ok = (200..300).contains(&status);
        let limit = if ok { max_bytes } else { 64 * 1024 };
        let mut body = Vec::new();
        let mut total: u64 = 0;
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let mut read = 0u32;
            if WinHttpReadData(req.0, chunk.as_mut_ptr() as *mut _, chunk.len() as u32, &mut read) == 0 {
                return Err(last_err("download"));
            }
            if read == 0 {
                break;
            }
            total += read as u64;
            if total > limit {
                if ok {
                    return Err(format!("download from {host} exceeds the size limit ({limit} bytes)"));
                }
                break;
            }
            match (&mut sink, ok) {
                (Some(w), true) => w.write_all(&chunk[..read as usize]).map_err(|e| format!("cannot write download: {e}"))?,
                _ => body.extend_from_slice(&chunk[..read as usize]),
            }
        }
        Ok(Response { status: status as u16, location, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_splitting() {
        assert_eq!(split_url("https://api.github.com/repos/a/b").unwrap(), ("api.github.com".into(), 443, "/repos/a/b".into()));
        assert_eq!(split_url("https://GitLab.local:8443/api/v4?x=1").unwrap(), ("gitlab.local".into(), 8443, "/api/v4?x=1".into()));
        assert!(split_url("http://example.com/").is_err());
        assert!(split_url("https://user:pw@example.com/").is_err());
    }
}
