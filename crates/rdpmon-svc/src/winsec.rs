//! Windows security helpers: SDDL security descriptors, data-directory ACLs,
//! service DACL hardening, computer name, Win32 event objects.

use rdpmon_core::wide;
use std::io;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};

/// SYSTEM: full control. Administrators: read & execute (they can still take
/// ownership - see docs/SECURITY.md). No access for anyone else.
pub const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BA)";
/// Local SYSTEM and elevated Administrators only; network logons denied.
pub const PIPE_SDDL: &str = "D:P(D;;GA;;;NU)(A;;GRGW;;;SY)(A;;GRGW;;;BA)";
/// Administrators may query, start and interrogate the service but not stop,
/// reconfigure or delete it through the SCM. SYSTEM (MSI, GPO) keeps full control.
pub const SERVICE_SDDL_HARDENED: &str =
    "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
/// Windows default for a service created by the SCM.
pub const SERVICE_SDDL_DEFAULT: &str =
    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is immutable after creation and freed exactly once.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let w = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated string; sd receives a LocalAlloc'd buffer.
        let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }

    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: self.0, bInheritHandle: 0 }
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted) = (0, 0);
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: self.0 is a valid security descriptor.
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(acl)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0 as _) };
    }
}

/// Applies a protected DACL to a directory and propagates it to its children.
pub fn secure_directory(path: &Path) -> io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(DATA_DIR_SDDL)?;
    let acl = sd.dacl()?;
    let w = wide(&path.to_string_lossy());
    // SAFETY: valid path and DACL pointer that outlives the call.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            w.as_ptr() as *mut _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// Sets the service object's DACL (hardened or Windows default).
pub fn set_service_dacl(hardened: bool) -> io::Result<()> {
    use windows_sys::Win32::System::Services::{CloseServiceHandle, OpenSCManagerW, OpenServiceW, SetServiceObjectSecurity, SC_MANAGER_CONNECT};
    const WRITE_DAC: u32 = 0x0004_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    let sd = SecurityDescriptor::from_sddl(if hardened { SERVICE_SDDL_HARDENED } else { SERVICE_SDDL_DEFAULT })?;
    let name = wide(rdpmon_core::paths::SERVICE_NAME);
    // SAFETY: handles are checked and closed; sd outlives the call.
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(io::Error::last_os_error());
        }
        let svc = OpenServiceW(scm, name.as_ptr(), WRITE_DAC | READ_CONTROL);
        if svc.is_null() {
            let e = io::Error::last_os_error();
            CloseServiceHandle(scm);
            return Err(e);
        }
        let ok = SetServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, sd.as_ptr());
        let e = io::Error::last_os_error();
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok == 0 {
            return Err(e);
        }
    }
    Ok(())
}

pub fn hostname() -> String {
    use windows_sys::Win32::System::SystemInformation::{ComputerNamePhysicalDnsHostname, GetComputerNameExW};
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: buffer and length are valid.
    if unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf.as_mut_ptr(), &mut len) } != 0 {
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        if !s.is_empty() {
            return s.to_uppercase();
        }
    }
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into())
}

/// Owned Win32 event object.
pub struct Event(pub HANDLE);

unsafe impl Send for Event {}
unsafe impl Sync for Event {}

impl Event {
    pub fn new(manual_reset: bool) -> io::Result<Self> {
        use windows_sys::Win32::System::Threading::CreateEventW;
        // SAFETY: unnamed event with default security.
        let h = unsafe { CreateEventW(std::ptr::null(), manual_reset as i32, 0, std::ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(h))
    }
    pub fn set(&self) {
        unsafe { windows_sys::Win32::System::Threading::SetEvent(self.0) };
    }
    pub fn reset(&self) {
        unsafe { windows_sys::Win32::System::Threading::ResetEvent(self.0) };
    }
    pub fn is_set(&self) -> bool {
        unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(self.0, 0) == 0 }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Waits for any handle. Returns Some(index) or None on timeout.
pub fn wait_any(handles: &[HANDLE], timeout_ms: u32) -> Option<usize> {
    use windows_sys::Win32::System::Threading::WaitForMultipleObjects;
    // SAFETY: handles are valid for the duration of the call.
    let r = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout_ms) };
    let i = r as usize;
    (i < handles.len()).then_some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_strings_parse() {
        for s in [DATA_DIR_SDDL, PIPE_SDDL, SERVICE_SDDL_HARDENED, SERVICE_SDDL_DEFAULT] {
            SecurityDescriptor::from_sddl(s).unwrap();
        }
        assert!(SecurityDescriptor::from_sddl("garbage").is_err());
    }

    #[test]
    fn events_and_hostname() {
        let e = Event::new(true).unwrap();
        assert_eq!(wait_any(&[e.0], 0), None);
        e.set();
        assert_eq!(wait_any(&[e.0], 0), Some(0));
        assert!(!hostname().is_empty());
    }
}
