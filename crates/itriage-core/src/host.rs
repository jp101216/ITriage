//! Facts about the machine and this process that the UI needs up front: the
//! host's name, whether we're elevated, and how admin-only modules will get
//! their rights.

use serde::Serialize;
use sysinfo::System;

#[derive(Debug, Clone, Serialize)]
pub struct HostContext {
    pub hostname: String,
    pub os: String,
    /// `std::env::consts::OS`: "windows", "linux", …
    pub platform: &'static str,
    pub elevated: bool,
    /// Windows only: the app can restart itself elevated through UAC.
    pub can_relaunch_elevated: bool,
    /// One line telling the user how admin-only modules get their rights here.
    pub elevation_note: String,
}

pub fn host_context() -> HostContext {
    let elevated = is_elevated();
    let platform = std::env::consts::OS;
    let os = System::long_os_version()
        .or_else(System::name)
        .unwrap_or_else(|| platform.to_string());
    let hostname = System::host_name().unwrap_or_else(|| "unknown host".to_string());
    let (can_relaunch_elevated, elevation_note) = elevation_story(elevated);
    HostContext {
        hostname,
        os,
        platform,
        elevated,
        can_relaunch_elevated,
        elevation_note,
    }
}

#[cfg(windows)]
fn elevation_story(elevated: bool) -> (bool, String) {
    if elevated {
        (false, "Running as administrator.".into())
    } else {
        (
            true,
            "Install modules need administrator rights. Use Relaunch as admin.".into(),
        )
    }
}

#[cfg(not(windows))]
fn elevation_story(elevated: bool) -> (bool, String) {
    let note = if elevated {
        "Running as root."
    } else if crate::util::command_exists("pkexec") {
        "Install modules will ask for your password (pkexec)."
    } else {
        "Install modules need root: re-run with sudo, or install polkit (pkexec)."
    };
    (false, note.into())
}

/// Is this process running with administrator (Windows) / root (Unix) rights?
#[cfg(windows)]
pub fn is_elevated() -> bool {
    crate::win::token::is_elevated()
}

#[cfg(unix)]
pub fn is_elevated() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(any(windows, unix)))]
pub fn is_elevated() -> bool {
    false
}

/// Start a new, elevated copy of this app through UAC. The caller should exit
/// on success. Errors when the user declines the UAC prompt.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<(), String> {
    crate::win::shell::relaunch_elevated()
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<(), String> {
    Err("Relaunching elevated is a Windows feature. On Linux, install modules ask for your password through pkexec instead.".into())
}

/// The machine's manufacturer, for routing driver/BIOS updates to the right
/// OEM tool. Read from SMBIOS (via the registry on Windows, sysfs on Linux).
#[cfg(windows)]
pub fn system_manufacturer() -> Option<String> {
    crate::win::registry::read_hklm_string(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer")
}

#[cfg(not(windows))]
pub fn system_manufacturer() -> Option<String> {
    std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
