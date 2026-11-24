//! Local administration protocol over a named pipe.
//!
//! Framing: 4-byte little-endian length + JSON. One request per connection.
//! The pipe only accepts local clients that are SYSTEM or elevated
//! Administrators; every state-changing request additionally needs a session
//! token obtained with the application administration password (or a valid
//! signed configuration package).

use crate::config::{Config, SmtpConfig};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const MAX_MESSAGE: u32 = 4 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    Status,
    Login { password: String },
    Logout { token: String },
    /// Only accepted while no administration password exists (first run).
    InitialSetup { password: String, config: Config },
    GetConfig { token: String },
    /// `smtp_password` / `update_token`: None = keep current, Some("") = clear.
    SaveConfig { token: String, config: Config, smtp_password: Option<String>, update_token: Option<String> },
    /// `token` may be None only during first-run setup.
    TestEmail { token: Option<String>, smtp: SmtpConfig, use_stored_password: bool },
    ChangePassword { token: String, current_password: String, new_password: String },
    GetAudit { token: String, limit: u32 },
    GetHistory { token: String, limit: u32 },
    CheckUpdates { token: String },
    InstallUpdate { token: String, version: String },
    RestartMonitoring { token: String },
    AuthorizeUninstall { token: String },
    /// Asked by the MSI during removal (runs as SYSTEM).
    CheckUninstall,
    /// Authenticated by the package signature, not by password.
    ImportPackage { data: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStatus {
    pub name: String,
    pub state: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatusInfo {
    pub version: String,
    pub hostname: String,
    pub password_set: bool,
    pub smtp_configured: bool,
    pub monitoring: Vec<ChannelStatus>,
    pub pending_notifications: u64,
    pub failed_notifications: u64,
    pub last_connection: Option<String>,
    pub last_error: Option<String>,
    pub locked_out_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub time: String,
    pub category: String,
    pub action: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub time: String,
    pub kind: String,
    pub user: String,
    pub domain: String,
    pub source_ip: String,
    pub session_id: Option<u32>,
    pub event_ids: String,
    pub notification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_name: String,
    pub release_notes: String,
    pub published_at: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    Ok { message: String },
    Error { message: String },
    Status(StatusInfo),
    Token { token: String },
    Config { config: Config, has_smtp_password: bool, has_update_token: bool },
    Audit { entries: Vec<AuditEntry> },
    History { entries: Vec<HistoryEntry> },
    Update(UpdateInfo),
    Uninstall { authorized: bool },
}

impl Response {
    pub fn ok(m: impl Into<String>) -> Self {
        Response::Ok { message: m.into() }
    }
    pub fn err(m: impl Into<String>) -> Self {
        Response::Error { message: m.into() }
    }
}

pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    if body.len() as u64 > MAX_MESSAGE as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    w.write_all(&frame)?;
    w.flush()
}

pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Sends one request to the local service and returns its response.
#[cfg(windows)]
pub fn call(req: &Request) -> io::Result<Response> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    let name = crate::wide(crate::paths::PIPE_NAME);
    for _ in 0..10 {
        // SAFETY: valid NUL-terminated name; returned handle is owned by File.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            let mut f = unsafe { std::fs::File::from_raw_handle(h as _) };
            verify_server(h)?;
            write_msg(&mut f, req)?;
            return read_msg(&mut f);
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_BUSY {
            let e = io::Error::from_raw_os_error(err as i32);
            return Err(match e.kind() {
                io::ErrorKind::NotFound => io::Error::new(io::ErrorKind::NotFound, "The RDP Monitor service is not running."),
                io::ErrorKind::PermissionDenied => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Access denied. Run this program as Administrator.",
                ),
                _ => e,
            });
        }
        unsafe { WaitNamedPipeW(name.as_ptr(), 3000) };
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "The RDP Monitor service is busy. Try again."))
}

/// Refuses to talk to a pipe that is not served by the installed RDP Monitor
/// service process (protects passwords against a pipe-squatting process).
/// Debug builds also accept a server in console mode when the service is not
/// running, for development.
#[cfg(windows)]
fn verify_server(h: windows_sys::Win32::Foundation::HANDLE) -> io::Result<()> {
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
        SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    };
    let mut server_pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(h, &mut server_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let name = crate::wide(crate::paths::SERVICE_NAME);
    let mut service_pid = 0u32;
    // SAFETY: handles are checked and closed; status buffer has the right size.
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if !scm.is_null() {
            let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_STATUS);
            if !svc.is_null() {
                let mut st: SERVICE_STATUS_PROCESS = std::mem::zeroed();
                let mut needed = 0u32;
                if QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, &mut st as *mut _ as *mut u8, std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32, &mut needed) != 0 {
                    service_pid = st.dwProcessId;
                }
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
    }
    if service_pid != 0 && service_pid == server_pid {
        return Ok(());
    }
    if cfg!(debug_assertions) && service_pid == 0 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "The administration pipe is not served by the RDP Monitor service. Refusing to connect.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrip() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Request::Login { password: "x".into() }).unwrap();
        let r: Request = read_msg(&mut buf.as_slice()).unwrap();
        assert!(matches!(r, Request::Login { password } if password == "x"));
    }

    #[test]
    fn rejects_oversized_frames() {
        let mut buf = (MAX_MESSAGE + 1).to_le_bytes().to_vec();
        buf.extend_from_slice(b"{}");
        assert!(read_msg::<_, Request>(&mut buf.as_slice()).is_err());
    }
}
