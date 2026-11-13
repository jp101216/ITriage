//! Installed programs, as Settings → Apps lists them: the Uninstall keys
//! (64-bit, 32-bit and per-user).

use super::registry::{read_dword, read_string, subkeys, HKCU, HKLM};

#[derive(Clone, Debug)]
pub struct Program {
    pub name: String,
    pub version: String,
}

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const UNINSTALL_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

pub fn installed() -> Vec<Program> {
    let mut out: Vec<Program> = Vec::new();
    for (root, base) in [(HKLM, UNINSTALL), (HKLM, UNINSTALL_32), (HKCU, UNINSTALL)] {
        for sub in subkeys(root, base) {
            let path = format!(r"{base}\{sub}");
            let Some(name) = read_string(root, &path, "DisplayName") else { continue };
            // Components and patches that Settings hides.
            if read_dword(root, &path, "SystemComponent") == Some(1)
                || read_string(root, &path, "ParentKeyName").is_some()
            {
                continue;
            }
            let version = read_string(root, &path, "DisplayVersion").unwrap_or_default();
            if out.iter().any(|p| p.name == name && p.version == version) {
                continue;
            }
            out.push(Program { name, version });
        }
    }
    out
}

/// A file's version resource (`FILEVERSION`), as `a.b.c.d`.
pub fn file_version(path: &std::path::Path) -> Option<String> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO};
    let name = HSTRING::from(path.as_os_str());
    // SAFETY: the buffer is sized by GetFileVersionInfoSizeW; VerQueryValueW
    // returns a pointer into it, checked for null and length before reading.
    unsafe {
        let size = GetFileVersionInfoSizeW(&name, None);
        if size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        GetFileVersionInfoW(&name, None, size, data.as_mut_ptr() as *mut _).ok()?;
        let mut info: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        if !VerQueryValueW(data.as_ptr() as *const _, &HSTRING::from("\\"), &mut info, &mut len).as_bool()
            || info.is_null()
            || (len as usize) < std::mem::size_of::<VS_FIXEDFILEINFO>()
        {
            return None;
        }
        let fixed = std::ptr::read_unaligned(info as *const VS_FIXEDFILEINFO);
        Some(format!(
            "{}.{}.{}.{}",
            fixed.dwFileVersionMS >> 16,
            fixed.dwFileVersionMS & 0xffff,
            fixed.dwFileVersionLS >> 16,
            fixed.dwFileVersionLS & 0xffff
        ))
    }
}
