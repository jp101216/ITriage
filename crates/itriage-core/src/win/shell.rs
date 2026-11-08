//! ShellExecute: relaunch elevated through the UAC prompt, and open a URL or
//! folder with its default handler.

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Open a URL in the default browser, or a folder in Explorer.
pub fn open(target: &str) -> Result<(), String> {
    let target = HSTRING::from(target);
    // SAFETY: valid NUL-terminated wide strings that outlive the call.
    let result = unsafe { ShellExecuteW(None, w!("open"), &target, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
    if result.0 as isize > 32 {
        Ok(())
    } else {
        Err(format!("Windows couldn't open it (ShellExecute {})", result.0 as isize))
    }
}

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
        Err("Elevation was cancelled, so ITriage is still running as a standard user.".into())
    }
}
