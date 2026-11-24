//! Local administration named pipe. One client at a time, local only,
//! SYSTEM / elevated Administrators only, 30-second I/O timeout.

use crate::app::Shared;
use crate::handler::{self, Client};
use crate::logging;
use crate::winsec::{wait_any, Event, SecurityDescriptor, PIPE_SDDL};
use rdpmon_core::ipc::{read_msg, write_msg, Request, Response};
use rdpmon_core::wide;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

const REQUEST_DEADLINE: Duration = Duration::from_secs(30);
const REPLY_DEADLINE: Duration = Duration::from_secs(10);

struct Pipe(HANDLE);

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub fn run(sh: Arc<Shared>) {
    let db = match sh.open_db() {
        Ok(d) => d,
        Err(e) => {
            logging::error(&e);
            std::process::exit(2);
        }
    };
    let sd = match SecurityDescriptor::from_sddl(PIPE_SDDL) {
        Ok(s) => s,
        Err(e) => {
            logging::error(&format!("cannot build pipe security descriptor: {e}"));
            return;
        }
    };
    let ev = Event::new(true).expect("create event");
    while !sh.stopping() {
        let pipe = match create(&sd) {
            Ok(p) => p,
            Err(e) => {
                let msg = format!("administration interface unavailable ({e}); another process may be using the pipe name");
                logging::error(&msg);
                sh.set_error(Some(msg));
                wait_any(&[sh.stop.0], 30_000);
                continue;
            }
        };
        // Serve clients on this instance until an error forces re-creation.
        while !sh.stopping() {
            match connect(&pipe, &ev, sh.stop.0) {
                Ok(true) => {}
                Ok(false) => return, // stopping
                Err(e) => {
                    logging::warn(&format!("pipe connect failed: {e}"));
                    break;
                }
            }
            // The whole request must arrive within REQUEST_DEADLINE (no slow drip).
            let mut conn = Conn { h: pipe.0, ev: &ev, stop: sh.stop.0, deadline: Instant::now() + REQUEST_DEADLINE };
            let req = read_msg::<_, Request>(&mut conn);
            // Impersonation identifies the client of the last message read,
            // so this must happen after the read.
            let client = identify(pipe.0);
            match req {
                Ok(req) => {
                    let resp = handler::handle(&sh, &db, req, &client);
                    conn.deadline = Instant::now() + REPLY_DEADLINE;
                    if let Err(e) = write_msg(&mut conn, &resp) {
                        logging::warn(&format!("cannot reply to {}: {e}", client.user));
                    }
                }
                Err(e) => {
                    conn.deadline = Instant::now() + REPLY_DEADLINE;
                    let _ = write_msg(&mut conn, &Response::err("Malformed request."));
                    logging::warn(&format!("bad request from {} (pid {}): {e}", client.user, client.pid));
                }
            }
            // Let the client read the reply: wait (bounded) until it closes its
            // end instead of FlushFileBuffers, which can block forever.
            let mut b = [0u8; 1];
            let _ = conn.read(&mut b);
            unsafe { DisconnectNamedPipe(pipe.0) };
        }
    }
}

fn create(sd: &SecurityDescriptor) -> io::Result<Pipe> {
    let name = wide(rdpmon_core::paths::PIPE_NAME);
    let sa = sd.attributes();
    // FIRST_PIPE_INSTANCE: fail instead of joining a pipe another process created.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            &sa,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(Pipe(h))
}

/// Ok(true) = client connected, Ok(false) = service stopping.
fn connect(pipe: &Pipe, ev: &Event, stop: HANDLE) -> io::Result<bool> {
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = ev.0;
    ev.reset();
    if unsafe { ConnectNamedPipe(pipe.0, &mut ov) } == 0 {
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => return Ok(true),
            ERROR_IO_PENDING => {}
            e => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
    match wait_any(&[stop, ev.0], u32::MAX) {
        Some(1) => {
            let mut n = 0;
            if unsafe { GetOverlappedResult(pipe.0, &ov, &mut n, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(true)
        }
        _ => {
            unsafe {
                CancelIoEx(pipe.0, &ov);
                let mut n = 0;
                GetOverlappedResult(pipe.0, &ov, &mut n, 1);
            }
            Ok(false)
        }
    }
}

fn identify(h: HANDLE) -> Client {
    let mut pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(h, &mut pid) };
    let mut user = "unknown user".to_string();
    // SAFETY: impersonation is reverted immediately after reading the name.
    unsafe {
        if ImpersonateNamedPipeClient(h) != 0 {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            if windows_sys::Win32::System::WindowsProgramming::GetUserNameW(buf.as_mut_ptr(), &mut len) != 0 {
                user = rdpmon_core::from_wide(&buf);
            }
            windows_sys::Win32::Security::RevertToSelf();
        }
    }
    Client { pid, user }
}

struct Conn<'a> {
    h: HANDLE,
    ev: &'a Event,
    stop: HANDLE,
    deadline: Instant,
}

impl Conn<'_> {
    fn io(&mut self, ptr: *mut u8, len: usize, write: bool) -> io::Result<usize> {
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = self.ev.0;
        self.ev.reset();
        let len = len.min(u32::MAX as usize) as u32;
        let ok = unsafe {
            if write {
                WriteFile(self.h, ptr, len, std::ptr::null_mut(), &mut ov)
            } else {
                ReadFile(self.h, ptr, len, std::ptr::null_mut(), &mut ov)
            }
        };
        if ok == 0 {
            let e = unsafe { GetLastError() };
            if e != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(e as i32));
            }
            let left = self.deadline.saturating_duration_since(Instant::now()).as_millis().min(u32::MAX as u128 - 1) as u32;
            if wait_any(&[self.ev.0, self.stop], left) != Some(0) {
                unsafe {
                    CancelIoEx(self.h, &ov);
                    let mut n = 0;
                    GetOverlappedResult(self.h, &ov, &mut n, 1);
                }
                return Err(io::Error::new(io::ErrorKind::TimedOut, "client timed out"));
            }
        }
        let mut n = 0u32;
        if unsafe { GetOverlappedResult(self.h, &ov, &mut n, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl Read for Conn<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.io(buf.as_mut_ptr(), buf.len(), false)
    }
}

impl Write for Conn<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io(buf.as_ptr() as *mut u8, buf.len(), true)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
