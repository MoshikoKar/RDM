//! Thin wrapper over the Windows Event Log subscription API (pull model).
//!
//! Each subscription signals a Win32 event when new records are available;
//! the monitor thread then drains them with `EvtNext`. Nothing polls.

use rdpmon_core::{from_wide, wide};
use std::io;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_OPERATION, ERROR_NO_MORE_ITEMS, HANDLE};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtCreateBookmark, EvtNext, EvtRender, EvtRenderBookmark, EvtRenderEventXml, EvtSubscribe,
    EvtSubscribeStartAfterBookmark, EvtSubscribeStartAtOldestRecord, EvtSubscribeToFutureEvents, EvtUpdateBookmark, EVT_HANDLE,
};

struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { EvtClose(self.0) };
        }
    }
}

pub struct Subscription {
    sub: Handle,
    bookmark: Handle,
    dirty: bool,
}

// SAFETY: EVT handles may be used from any thread; we use each from one thread.
unsafe impl Send for Subscription {}

/// Builds a structured XML query for one channel. `selects` are XPath
/// expressions; `max_age_ms` bounds how far back recovery may reach.
pub fn query_xml(channel: &str, selects: &[String]) -> String {
    let mut q = format!("<QueryList><Query Id=\"0\" Path=\"{channel}\">");
    for s in selects {
        q.push_str(&format!("<Select Path=\"{channel}\">{s}</Select>"));
    }
    q.push_str("</Query></QueryList>");
    q
}

impl Subscription {
    /// Subscribes to `query`. With a bookmark, delivery resumes after the
    /// bookmarked record (or the closest surviving one if the log was cleared
    /// or wrapped); without one, only future events are delivered.
    pub fn open(query: &str, bookmark_xml: Option<&str>, signal: HANDLE) -> io::Result<Self> {
        Self::open_with(query, bookmark_xml, false, signal)
    }

    /// `from_oldest` (without bookmark): deliver every record matching the
    /// query, which is expected to bound the age with `timediff`.
    pub fn open_with(query: &str, bookmark_xml: Option<&str>, from_oldest: bool, signal: HANDLE) -> io::Result<Self> {
        let q = wide(query);
        let bm_w = bookmark_xml.map(wide);
        // SAFETY: strings are NUL-terminated and outlive the calls.
        unsafe {
            let mut bookmark = Handle(EvtCreateBookmark(bm_w.as_ref().map_or(std::ptr::null(), |b| b.as_ptr())));
            if bookmark.0 == 0 && bm_w.is_some() {
                // Corrupt bookmark: start fresh rather than failing forever.
                bookmark = Handle(EvtCreateBookmark(std::ptr::null()));
            }
            if bookmark.0 == 0 {
                return Err(io::Error::last_os_error());
            }
            let resume = bm_w.is_some();
            let flags = if resume {
                EvtSubscribeStartAfterBookmark
            } else if from_oldest {
                EvtSubscribeStartAtOldestRecord
            } else {
                EvtSubscribeToFutureEvents
            };
            let sub = EvtSubscribe(
                0,
                signal,
                std::ptr::null(),
                q.as_ptr(),
                if resume { bookmark.0 } else { 0 },
                std::ptr::null(),
                None,
                flags,
            );
            if sub == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { sub: Handle(sub), bookmark, dirty: false })
        }
    }

    /// Returns all currently available events as XML. An error means the
    /// subscription is broken (log service restarted, log cleared, …) and
    /// must be re-created.
    pub fn drain(&mut self, max: usize) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        while out.len() < max {
            let mut handles = [0 as EVT_HANDLE; 16];
            let mut returned = 0u32;
            // SAFETY: buffer of 16 handles; returned handles are closed below.
            let ok = unsafe { EvtNext(self.sub.0, handles.len() as u32, handles.as_mut_ptr(), 0, 0, &mut returned) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                // ERROR_INVALID_OPERATION is returned by a healthy pull
                // subscription that has not been signalled yet (nothing to read).
                if err == ERROR_NO_MORE_ITEMS || err == ERROR_INVALID_OPERATION {
                    break;
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            let events: Vec<Handle> = handles[..returned as usize].iter().map(|h| Handle(*h)).collect();
            for e in &events {
                match render(e.0, EvtRenderEventXml) {
                    Ok(xml) => out.push(xml),
                    Err(err) => crate::logging::warn(&format!("could not render event: {err}")),
                }
            }
            if let Some(last) = events.last() {
                unsafe { EvtUpdateBookmark(self.bookmark.0, last.0) };
                self.dirty = true;
            }
        }
        Ok(out)
    }

    /// Bookmark XML if it advanced since the last call.
    pub fn take_bookmark(&mut self) -> Option<String> {
        if !self.dirty {
            return None;
        }
        match render(self.bookmark.0, EvtRenderBookmark) {
            Ok(x) => {
                self.dirty = false;
                Some(x)
            }
            Err(_) => None,
        }
    }
}

fn render(h: EVT_HANDLE, flags: u32) -> io::Result<String> {
    let mut used = 0u32;
    let mut count = 0u32;
    // SAFETY: first call obtains the required size; second fills the buffer.
    unsafe {
        if EvtRender(0, h, flags, 0, std::ptr::null_mut(), &mut used, &mut count) == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u16; (used as usize).div_ceil(2) + 1];
        if EvtRender(0, h, flags, (buf.len() * 2) as u32, buf.as_mut_ptr() as _, &mut used, &mut count) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(from_wide(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winsec::{wait_any, Event};

    fn write_app_event(source: &str, id: u32, text: &str) {
        use windows_sys::Win32::System::EventLog::{DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_INFORMATION_TYPE};
        let src = wide(source);
        let msg = wide(text);
        let strings = [msg.as_ptr()];
        unsafe {
            let h = RegisterEventSourceW(std::ptr::null(), src.as_ptr());
            assert!(!h.is_null());
            assert_ne!(ReportEventW(h, EVENTLOG_INFORMATION_TYPE, 0, id, std::ptr::null_mut(), 1, 0, strings.as_ptr(), std::ptr::null()), 0);
            DeregisterEventSource(h);
        }
    }

    fn wait_events(s: &mut Subscription, sig: &Event, want: usize) -> Vec<String> {
        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while got.len() < want && std::time::Instant::now() < deadline {
            let _ = wait_any(&[sig.0], 500);
            sig.reset();
            got.extend(s.drain(100).unwrap());
        }
        got
    }

    /// Live test against the Application log (writable/readable without
    /// elevation): real-time delivery, then bookmark-based recovery of an
    /// event written while no subscription existed (service restart).
    #[test]
    fn live_subscription_and_bookmark_recovery() {
        let source = format!("RDPMonitorTest{}", std::process::id());
        let q = query_xml("Application", &[format!("*[System[Provider[@Name='{source}'] and (EventID=999)]]")]);
        let sig = Event::new(true).unwrap();
        let mut s = Subscription::open(&q, None, sig.0).unwrap();
        // Draining before any signal must not be treated as a failure.
        assert!(s.drain(10).unwrap().is_empty());
        write_app_event(&source, 999, "first");
        let first = wait_events(&mut s, &sig, 1);
        assert_eq!(first.len(), 1, "real-time event not delivered");
        assert!(first[0].contains("<EventID") && first[0].contains("first"));
        let bookmark = s.take_bookmark().expect("bookmark advanced");
        drop(s);

        write_app_event(&source, 999, "while-stopped");
        let sig2 = Event::new(true).unwrap();
        let mut s2 = Subscription::open(&q, Some(&bookmark), sig2.0).unwrap();
        let recovered = wait_events(&mut s2, &sig2, 1);
        assert_eq!(recovered.len(), 1, "missed event not recovered: {recovered:?}");
        assert!(recovered[0].contains("while-stopped") && !recovered[0].contains(">first<"));
    }

    /// Without a bookmark, `from_oldest` + a timediff bound recovers an event
    /// written before the subscription existed (first restart after install).
    #[test]
    fn recovery_without_bookmark() {
        let source = format!("RDPMonitorTestB{}", std::process::id());
        write_app_event(&source, 998, "before-subscribe");
        let q = query_xml("Application", &[format!(
            "*[System[Provider[@Name='{source}'] and (EventID=998) and TimeCreated[timediff(@SystemTime) &lt;= 600000]]]"
        )]);
        let sig = Event::new(true).unwrap();
        let mut s = Subscription::open_with(&q, None, true, sig.0).unwrap();
        let got = wait_events(&mut s, &sig, 1);
        assert_eq!(got.len(), 1);
        assert!(got[0].contains("before-subscribe"));
    }

    #[test]
    fn missing_channel_fails_cleanly() {
        let sig = Event::new(true).unwrap();
        let bad = Subscription::open(&query_xml("No-Such-Channel/Operational", &["*".into()]), None, sig.0);
        assert!(bad.is_err());
    }
}
