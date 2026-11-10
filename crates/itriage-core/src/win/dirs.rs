//! Where Windows and its standard folders really are, asked of Windows
//! itself. Environment variables (`%SystemRoot%`, `%ProgramFiles%`, `PATH`)
//! can be set by the user who started the app, so nothing that runs with
//! administrator rights is located through them.

use std::path::PathBuf;
use windows::core::GUID;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
};

fn from_buffer(fill: impl Fn(&mut [u16]) -> u32, fallback: &str) -> PathBuf {
    let mut buf = [0u16; 512];
    let len = fill(&mut buf) as usize;
    if len == 0 || len >= buf.len() {
        return PathBuf::from(fallback);
    }
    PathBuf::from(String::from_utf16_lossy(&buf[..len]))
}

/// `C:\Windows\System32`.
pub fn system32() -> PathBuf {
    // SAFETY: the buffer is a live local of the length passed.
    from_buffer(|b| unsafe { GetSystemDirectoryW(Some(b)) }, r"C:\Windows\System32")
}

/// `C:\Windows` (the real one, also inside a Remote Desktop session).
pub fn windows() -> PathBuf {
    // SAFETY: as above.
    from_buffer(|b| unsafe { GetSystemWindowsDirectoryW(Some(b)) }, r"C:\Windows")
}

/// The system drive: `C:`.
pub fn system_drive() -> String {
    let win = windows();
    let text = win.to_string_lossy();
    match text.get(..2) {
        Some(drive) if drive.ends_with(':') => drive.to_string(),
        _ => "C:".to_string(),
    }
}

fn known(id: &GUID) -> Option<PathBuf> {
    // SAFETY: the returned string is copied out and then freed, as the API asks.
    unsafe {
        let path = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let text = path.to_string().ok();
        CoTaskMemFree(Some(path.0 as *const _));
        text.filter(|t| !t.is_empty()).map(PathBuf::from)
    }
}

/// `C:\Program Files`.
pub fn program_files() -> Option<PathBuf> {
    known(&FOLDERID_ProgramFiles)
}

/// `C:\Program Files (x86)`.
pub fn program_files_x86() -> Option<PathBuf> {
    known(&FOLDERID_ProgramFilesX86)
}

/// `C:\ProgramData`.
pub fn program_data() -> PathBuf {
    known(&FOLDERID_ProgramData).unwrap_or_else(|| PathBuf::from(format!(r"{}\ProgramData", system_drive())))
}

/// One of Windows' own command-line tools, by its full path. `None` when
/// Windows doesn't ship a tool of that name.
pub fn system_tool(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains(['\\', '/', ':']) {
        return None;
    }
    let sys = system32();
    let exe = if name.to_ascii_lowercase().ends_with(".exe") { name.to_string() } else { format!("{name}.exe") };
    [sys.join(&exe), sys.join("WindowsPowerShell").join("v1.0").join(&exe), sys.join("wbem").join(&exe)]
        .into_iter()
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_windows_and_its_tools() {
        assert!(system32().join("kernel32.dll").is_file(), "{}", system32().display());
        assert!(windows().join("System32").is_dir());
        assert_eq!(system_drive().len(), 2);
        assert!(program_files().is_some_and(|p| p.is_dir()));
        assert!(program_data().is_dir());
        for tool in ["netsh", "ipconfig", "sfc", "dism", "shutdown", "gpupdate", "defrag", "powershell.exe", "w32tm", "nbtstat"] {
            let found = system_tool(tool);
            assert!(found.as_ref().is_some_and(|p| p.starts_with(windows())), "{tool}: {found:?}");
        }
        assert!(system_tool("no-such-tool-xyz").is_none());
        assert!(system_tool(r"..\..\evil").is_none() && system_tool("").is_none());
    }
}
