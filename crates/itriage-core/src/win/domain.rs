//! Domain membership (NetAPI) and power status.

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGetJoinInformation, NetSetupDomainName, NetSetupWorkgroupName, NETSETUP_JOIN_STATUS,
};
use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

#[derive(Clone, Debug, PartialEq)]
pub enum Join {
    Domain(String),
    Workgroup(String),
    Unjoined,
}

pub fn join_info() -> Option<Join> {
    let mut name = PWSTR::null();
    let mut status = NETSETUP_JOIN_STATUS::default();
    // SAFETY: NetAPI allocates `name`; it's freed with NetApiBufferFree.
    unsafe {
        if NetGetJoinInformation(PCWSTR::null(), &mut name, &mut status) != 0 {
            return None;
        }
        let text = if name.is_null() { String::new() } else { name.to_string().unwrap_or_default() };
        if !name.is_null() {
            let _ = NetApiBufferFree(Some(name.0 as *const core::ffi::c_void));
        }
        Some(if status == NetSetupDomainName {
            Join::Domain(text)
        } else if status == NetSetupWorkgroupName {
            Join::Workgroup(text)
        } else {
            Join::Unjoined
        })
    }
}

/// The domain controller that authenticated this sign-in (`LOGONSERVER`), or
/// `None` for a local or cached-credential sign-in, where Windows sets it to
/// this computer's own name.
pub fn logon_server() -> Option<String> {
    let raw = std::env::var("LOGONSERVER").ok()?;
    let name = raw.trim_start_matches('\\').to_string();
    let me = std::env::var("COMPUTERNAME").unwrap_or_default();
    (!name.is_empty() && !name.eq_ignore_ascii_case(&me)).then_some(name)
}

/// AC/battery state: (on AC power, battery percent, has a battery).
pub fn power() -> Option<(Option<bool>, Option<u8>, bool)> {
    let mut s = SYSTEM_POWER_STATUS::default();
    // SAFETY: plain out-parameter.
    unsafe { GetSystemPowerStatus(&mut s) }.ok()?;
    let ac = match s.ACLineStatus {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    };
    let percent = (s.BatteryLifePercent != 255).then_some(s.BatteryLifePercent);
    let has_battery = s.BatteryFlag & 128 == 0 && s.BatteryFlag != 255;
    Some((ac, percent, has_battery))
}
