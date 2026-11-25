//! Checks that the audit subcategories the enabled optional alerts depend on
//! are turned on, so a silently missing event source shows up in the status.

use rdpmon_core::config::Config;
use windows_sys::core::GUID;
use windows_sys::Win32::Security::Authentication::Identity::{
    AuditFree, AuditQuerySystemPolicy, AUDIT_POLICY_INFORMATION, POLICY_AUDIT_EVENT_FAILURE, POLICY_AUDIT_EVENT_SUCCESS,
};

const LOGON: GUID = GUID::from_u128(0x0cce9215_69ae_11d9_bed3_505054503030);
const FILE_SHARE: GUID = GUID::from_u128(0x0cce9224_69ae_11d9_bed3_505054503030);
const DETAILED_FILE_SHARE: GUID = GUID::from_u128(0x0cce9244_69ae_11d9_bed3_505054503030);

/// (success, failure) auditing of a subcategory; None if it cannot be read.
fn query(guid: &GUID) -> Option<(bool, bool)> {
    let mut p: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
    // SAFETY: one GUID in, one structure out, freed with AuditFree.
    unsafe {
        if AuditQuerySystemPolicy(guid, 1, &mut p) == 0 || p.is_null() {
            return None;
        }
        let info = (*p).AuditingInformation;
        AuditFree(p as *const _);
        Some((info & POLICY_AUDIT_EVENT_SUCCESS as u32 != 0, info & POLICY_AUDIT_EVENT_FAILURE as u32 != 0))
    }
}

/// (subcategory, success needed, failure needed) for the current settings.
pub fn required(cfg: &Config) -> Vec<(&'static str, GUID, bool, bool)> {
    let mut v = Vec::new();
    if cfg.failed_logons_active() {
        v.push(("Logon", LOGON, false, true));
    }
    if cfg.smb.enabled {
        v.push(("File Share", FILE_SHARE, cfg.smb.notify_success, false));
        if cfg.smb.notify_failed {
            v.push(("Detailed File Share", DETAILED_FILE_SHARE, false, true));
        }
    }
    v
}

/// Human-readable warnings for required auditing that is off. Empty when
/// everything needed is on, or the policy cannot be read.
pub fn warnings(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for (name, guid, success, failure) in required(cfg) {
        let Some((s, f)) = query(&guid) else { continue };
        let mut missing = Vec::new();
        if success && !s {
            missing.push("success");
        }
        if failure && !f {
            missing.push("failure");
        }
        if !missing.is_empty() {
            let flags = missing.iter().map(|m| format!("/{m}:enable")).collect::<Vec<_>>().join(" ");
            out.push(format!("'{name}' {} auditing is off (auditpol /set /subcategory:\"{name}\" {flags})", missing.join(" and ")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_required_by_default() {
        assert!(required(&Config::default()).is_empty());
        assert!(warnings(&Config::default()).is_empty());
    }

    #[test]
    fn requirements_follow_settings() {
        let mut c = Config::default();
        c.smb.enabled = true;
        let names: Vec<&str> = required(&c).iter().map(|r| r.0).collect();
        assert_eq!(names, vec!["Logon", "File Share", "Detailed File Share"]);
        c.smb.notify_failed = false;
        let names: Vec<&str> = required(&c).iter().map(|r| r.0).collect();
        assert_eq!(names, vec!["File Share"]);
        // Reading the policy must not fail or panic (it may be unreadable
        // without elevation, which yields no warning).
        let _ = warnings(&c);
    }
}
