//! Locating the installed RDP Monitor product through Windows Installer.

/// UpgradeCode of the RDP Monitor MSI (installer/RDPMonitor.wxs). Stable across versions.
pub const UPGRADE_CODE: &str = "{56E6081C-56F2-4289-93C3-A252863CFC91}";

/// Product code (`{GUID}`) of the installed RDP Monitor, found by its
/// UpgradeCode, so it does not depend on display names in the registry.
#[cfg(windows)]
pub fn installed_product_code() -> Result<String, String> {
    use windows_sys::Win32::System::ApplicationInstallationAndServicing::MsiEnumRelatedProductsW;
    let upgrade = crate::wide(UPGRADE_CODE);
    let mut buf = [0u16; 39]; // GUID string + NUL
    let rc = unsafe { MsiEnumRelatedProductsW(upgrade.as_ptr(), 0, 0, buf.as_mut_ptr()) };
    match rc {
        0 => Ok(crate::from_wide(&buf)),
        259 => Err("RDP Monitor is not installed.".into()), // ERROR_NO_MORE_ITEMS
        e => Err(format!("cannot query Windows Installer (error {e})")),
    }
}
