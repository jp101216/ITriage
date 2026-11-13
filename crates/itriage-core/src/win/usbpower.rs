//! USB power saving: selective suspend in the active power plan, and a USB
//! device's own power settings under its `Device Parameters` key.

use windows::core::GUID;
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::System::Power::{
    PowerGetActiveScheme, PowerReadACValueIndex, PowerReadDCValueIndex, PowerSetActiveScheme, PowerWriteACValueIndex,
    PowerWriteDCValueIndex,
};

/// Power-plan subgroup "USB settings" and its "USB selective suspend
/// setting" (0 = disabled, 1 = enabled).
pub const SUBGROUP: GUID = GUID::from_u128(0x2a737441_1930_4402_8d77_b2bebba308a3);
pub const SETTING: GUID = GUID::from_u128(0x48e6b7a6_50f5_4782_a5d4_53bb8f07e226);

/// The device-level values worth showing, when a driver sets them.
pub const DEVICE_VALUES: &[&str] = &["SelectiveSuspendEnabled", "EnhancedPowerManagementEnabled", "AllowIdleIrpInD3"];

#[derive(Debug, Clone)]
pub struct Suspend {
    pub scheme: GUID,
    /// Plugged in and on battery.
    pub ac: Option<u32>,
    pub dc: Option<u32>,
}

pub fn guid_text(g: &GUID) -> String {
    format!("{g:?}").to_ascii_lowercase()
}

/// The active plan and its selective-suspend values.
pub fn selective_suspend() -> Result<Suspend, String> {
    // SAFETY: PowerGetActiveScheme allocates the GUID, freed with LocalFree
    // after it's copied; the reads write into live locals.
    unsafe {
        let mut active: *mut GUID = std::ptr::null_mut();
        let rc = PowerGetActiveScheme(None, &mut active);
        if rc != ERROR_SUCCESS || active.is_null() {
            return Err(format!("can't read the active power plan (error {})", rc.0));
        }
        let scheme = *active;
        let _ = LocalFree(Some(HLOCAL(active as *mut _)));
        let mut ac = 0u32;
        let mut dc = 0u32;
        let ac_ok = PowerReadACValueIndex(None, Some(&scheme), Some(&SUBGROUP), Some(&SETTING), &mut ac) == ERROR_SUCCESS;
        let dc_ok = PowerReadDCValueIndex(None, Some(&scheme), Some(&SUBGROUP), Some(&SETTING), &mut dc) == 0;
        Ok(Suspend { scheme, ac: ac_ok.then_some(ac), dc: dc_ok.then_some(dc) })
    }
}

/// Set selective suspend in a plan, then re-apply the active plan so it
/// takes effect now. Administrator rights are needed for the built-in plans.
pub fn set_selective_suspend(scheme: &GUID, ac: u32, dc: u32) -> Result<(), String> {
    // SAFETY: the GUIDs are live locals or constants.
    unsafe {
        let rc = PowerWriteACValueIndex(None, scheme, Some(&SUBGROUP), Some(&SETTING), ac);
        if rc != ERROR_SUCCESS {
            return Err(format!("couldn't change the plugged-in setting (error {})", rc.0));
        }
        let rc = PowerWriteDCValueIndex(None, scheme, Some(&SUBGROUP), Some(&SETTING), dc);
        if rc != 0 {
            return Err(format!("couldn't change the on-battery setting (error {rc})"));
        }
        let rc = PowerSetActiveScheme(None, Some(scheme));
        if rc != ERROR_SUCCESS {
            return Err(format!("changed, but couldn't re-apply the power plan (error {})", rc.0));
        }
    }
    Ok(())
}

/// Is selective suspend set by policy (Group Policy or MDM)? A change to the
/// plan wouldn't stick.
pub fn set_by_policy() -> bool {
    let key = format!(r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\{}", guid_text(&SETTING).trim_matches(['{', '}']));
    use crate::win::registry::{read_dword, HKLM};
    read_dword(HKLM, &key, "ACSettingIndex").is_some() || read_dword(HKLM, &key, "DCSettingIndex").is_some()
}

/// A USB device's own power values (`USB\VID_…\serial` instance).
pub fn device_values(usb_instance: &str) -> Vec<(String, u32)> {
    use crate::win::registry::{read_dword, HKLM};
    if usb_instance.contains("..") || !usb_instance.starts_with("USB\\") {
        return Vec::new();
    }
    let key = format!(r"SYSTEM\CurrentControlSet\Enum\{usb_instance}\Device Parameters");
    DEVICE_VALUES.iter().filter_map(|v| read_dword(HKLM, &key, v).map(|n| (v.to_string(), n))).collect()
}
