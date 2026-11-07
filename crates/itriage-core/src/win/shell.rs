//! Relaunch this executable elevated, through the standard UAC prompt.

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn relaunch_elevated() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("can't locate itriage.exe: {e}"))?;
    let exe = HSTRING::from(exe.as_os_str());
    // SAFETY: all string arguments are valid, NUL-terminated wide strings that
    // outlive the call; the "runas" verb is what triggers the UAC prompt.
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            &exe,
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute returns a value greater than 32 on success.
    if result.0 as isize > 32 {
        Ok(())
    } else {
        Err("Elevation was cancelled, so itriage is still running as a standard user.".into())
    }
}
