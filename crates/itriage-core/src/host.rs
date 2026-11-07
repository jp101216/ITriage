//! Facts about the machine and this process that the UI needs up front: the
//! host's name, whether we're elevated, and how admin-only modules will get
//! their rights.

use crate::parse::smbios::Identity;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostContext {
    pub hostname: String,
    pub os: String,
    /// `std::env::consts::OS`: "windows", "linux", …
    pub platform: String,
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
        platform: platform.to_string(),
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

/// Open an `https://` link (a KB article) in the default browser. Anything
/// else is refused, so a link can never launch a program or a local file.
pub fn open_url(url: &str) -> Result<(), String> {
    let safe = url.starts_with("https://")
        && url.len() > "https://".len()
        && url.len() <= 2048
        && !url.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\\');
    if !safe {
        return Err("Only https:// links can be opened.".into());
    }
    open_target(url)
}

/// Show a folder in the file manager.
pub fn open_folder(path: &std::path::Path) -> Result<(), String> {
    if !path.is_dir() {
        return Err(format!("{} doesn't exist yet.", path.display()));
    }
    open_target(&path.display().to_string())
}

#[cfg(windows)]
fn open_target(target: &str) -> Result<(), String> {
    crate::win::shell::open(target)
}

#[cfg(not(windows))]
fn open_target(target: &str) -> Result<(), String> {
    if !crate::util::command_exists("xdg-open") {
        return Err("xdg-open isn't installed, so links can't be opened from here.".into());
    }
    let mut c = crate::util::cmd("xdg-open");
    c.arg(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = c.spawn().map_err(|e| format!("couldn't run xdg-open: {e}"))?;
    std::thread::spawn(move || {
        let _ = child.wait(); // reap it; xdg-open hands off and exits
    });
    Ok(())
}

/// The machine's identity from SMBIOS: make, model, serial, BIOS, board.
/// Read once; it can't change while itriage runs.
pub fn identity() -> &'static Identity {
    static ID: OnceLock<Identity> = OnceLock::new();
    ID.get_or_init(read_identity)
}

/// The machine's manufacturer, for routing driver/BIOS updates to the right
/// OEM tool.
pub fn system_manufacturer() -> Option<String> {
    identity().manufacturer.clone()
}

#[cfg(windows)]
fn read_identity() -> Identity {
    use crate::parse::smbios::{clean, normalize_date};
    use crate::win::registry::read_hklm_string;
    let mut id = crate::win::smbios::identity().unwrap_or_default();
    // The registry copy of the same SMBIOS strings fills any gaps (no serial).
    const BIOS: &str = r"HARDWARE\DESCRIPTION\System\BIOS";
    let reg = |v: &str| read_hklm_string(BIOS, v).and_then(|s| clean(&s));
    id.manufacturer = id.manufacturer.or_else(|| reg("SystemManufacturer"));
    id.model = id.model.or_else(|| reg("SystemProductName"));
    id.family = id.family.or_else(|| reg("SystemFamily"));
    id.bios_vendor = id.bios_vendor.or_else(|| reg("BIOSVendor"));
    id.bios_version = id.bios_version.or_else(|| reg("BIOSVersion"));
    id.bios_date = id.bios_date.or_else(|| reg("BIOSReleaseDate").and_then(|d| normalize_date(&d)));
    id.board_maker = id.board_maker.or_else(|| reg("BaseBoardManufacturer"));
    id.board_product = id.board_product.or_else(|| reg("BaseBoardProduct"));
    id
}

#[cfg(not(windows))]
fn read_identity() -> Identity {
    use crate::parse::smbios::{clean, normalize_date};
    let dmi = |f: &str| {
        std::fs::read_to_string(format!("/sys/class/dmi/id/{f}"))
            .ok()
            .and_then(|s| clean(&s))
    };
    Identity {
        manufacturer: dmi("sys_vendor"),
        model: dmi("product_name"),
        family: dmi("product_family"),
        serial: dmi("product_serial"),
        bios_vendor: dmi("bios_vendor"),
        bios_version: dmi("bios_version"),
        bios_date: dmi("bios_date").and_then(|d| normalize_date(&d)),
        board_maker: dmi("board_vendor"),
        board_product: dmi("board_name"),
        chassis: dmi("chassis_type").and_then(|c| c.parse().ok()),
    }
}

/// Who is signed in at the console (Windows) or the local seat (Linux), as
/// opposed to the account itriage runs under.
#[cfg(windows)]
pub fn signed_in_user() -> Option<String> {
    crate::win::session::console_user()
}

#[cfg(not(windows))]
pub fn signed_in_user() -> Option<String> {
    use crate::util::{capture, cmd, command_exists};
    if command_exists("loginctl") {
        let mut c = cmd("loginctl");
        c.args(["list-sessions", "--no-legend"]).env("LC_ALL", "C");
        if let Some(user) = capture(c)
            .ok()
            .filter(|o| o.success())
            .and_then(|o| crate::parse::route::loginctl_seat_user(&o.stdout))
        {
            return Some(user);
        }
    }
    std::env::var("SUDO_USER").or_else(|_| std::env::var("USER")).ok().filter(|u| !u.is_empty())
}

/// Why a restart is pending, if it is: Invoke-NetTriage's three Windows
/// sources (servicing, Windows Update, pending file renames); on Linux the
/// package manager's flag. `Err` when it couldn't be checked.
#[cfg(windows)]
pub fn pending_restart() -> Result<Vec<&'static str>, String> {
    use crate::win::registry::{key_exists, value_size, HKLM};
    let mut reasons = Vec::new();
    if key_exists(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        reasons.push("Servicing");
    }
    if key_exists(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        reasons.push("Windows Update");
    }
    // An empty REG_MULTI_SZ is a terminator or two (2–4 bytes).
    if value_size(HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations")
        .is_some_and(|n| n > 4)
    {
        reasons.push("Pending file rename");
    }
    Ok(reasons)
}

#[cfg(not(windows))]
pub fn pending_restart() -> Result<Vec<&'static str>, String> {
    use crate::util::{capture, cmd, command_exists};
    let mut reasons = Vec::new();
    if std::path::Path::new("/var/run/reboot-required").exists() {
        reasons.push("Package updates");
    } else if command_exists("needs-restarting") {
        // dnf-utils: exit 1 means a core package changed since boot.
        let mut c = cmd("needs-restarting");
        c.arg("-r");
        if capture(c).is_ok_and(|o| o.code == Some(1)) {
            reasons.push("Package updates");
        }
    }
    Ok(reasons)
}

/// Is the machine on mains power? `Some(true)` for desktops without a
/// battery; `None` when it can't tell.
#[cfg(windows)]
pub fn on_ac_power() -> Option<bool> {
    let (ac, _, has_battery) = crate::win::domain::power()?;
    if has_battery {
        ac
    } else {
        Some(true)
    }
}

#[cfg(not(windows))]
pub fn on_ac_power() -> Option<bool> {
    let entries = std::fs::read_dir("/sys/class/power_supply").ok()?;
    let (mut mains, mut battery) = (None::<bool>, false);
    for e in entries.flatten() {
        let read = |f: &str| std::fs::read_to_string(e.path().join(f)).map(|s| s.trim().to_string()).unwrap_or_default();
        match read("type").as_str() {
            "Mains" | "USB" => mains = Some(mains.unwrap_or(false) || read("online") == "1"),
            "Battery" if read("scope") != "Device" => battery = true,
            _ => {}
        }
    }
    match (mains, battery) {
        (Some(on), _) => Some(on),
        (None, false) => Some(true),
        (None, true) => None,
    }
}
