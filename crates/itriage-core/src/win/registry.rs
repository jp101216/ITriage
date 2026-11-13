//! Registry reads (and one write: registering the audit event source).

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_NOEXPAND,
    RRF_RT_ANY, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};

pub use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER as HKCU, HKEY_LOCAL_MACHINE as HKLM, HKEY_USERS as HKU,
};

/// Does this key exist (and can we open it)?
pub fn key_exists(root: HKEY, subkey: &str) -> bool {
    let path = HSTRING::from(subkey);
    let mut key = HKEY::default();
    // SAFETY: open and close a handle; nothing is read.
    unsafe {
        if RegOpenKeyExW(root, &path, None, KEY_READ, &mut key) != ERROR_SUCCESS {
            return false;
        }
        let _ = RegCloseKey(key);
    }
    true
}

/// The size in bytes of a value of any type, if it exists.
pub fn value_size(root: HKEY, subkey: &str, value: &str) -> Option<u32> {
    let subkey = HSTRING::from(subkey);
    let value = HSTRING::from(value);
    let mut size = 0u32;
    // SAFETY: a size-only query (no data buffer).
    let status = unsafe { RegGetValueW(root, &subkey, &value, RRF_RT_ANY, None, None, Some(&mut size)) };
    (status == ERROR_SUCCESS).then_some(size)
}

/// Read a REG_BINARY value.
pub fn read_binary(root: HKEY, subkey: &str, value: &str) -> Option<Vec<u8>> {
    let subkey = HSTRING::from(subkey);
    let value = HSTRING::from(value);
    let mut buf = vec![0u8; 4096];
    let mut size = buf.len() as u32;
    // SAFETY: `buf` is writable for `size` bytes and outlives the call.
    let status = unsafe {
        RegGetValueW(
            root,
            &subkey,
            &value,
            RRF_RT_REG_BINARY,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    buf.truncate(size as usize);
    Some(buf)
}

/// Read a REG_SZ value. `None` if it's missing or empty.
pub fn read_string(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let subkey = HSTRING::from(subkey);
    let value = HSTRING::from(value);
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32; // in bytes
    // SAFETY: `buf` is writable for `size` bytes and outlives the call.
    let status = unsafe {
        RegGetValueW(
            root,
            &subkey,
            &value,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..len]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Read a REG_SZ value under HKEY_LOCAL_MACHINE.
pub fn read_hklm_string(subkey: &str, value: &str) -> Option<String> {
    read_string(HKEY_LOCAL_MACHINE, subkey, value)
}

/// Read a REG_DWORD value.
pub fn read_dword(root: HKEY, subkey: &str, value: &str) -> Option<u32> {
    let subkey = HSTRING::from(subkey);
    let value = HSTRING::from(value);
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: `data` is a 4-byte writable location.
    let status = unsafe {
        RegGetValueW(
            root,
            &subkey,
            &value,
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut u32 as *mut core::ffi::c_void),
            Some(&mut size),
        )
    };
    (status == ERROR_SUCCESS).then_some(data)
}

/// Names of a key's direct subkeys (empty if the key doesn't exist).
pub fn subkeys(root: HKEY, subkey: &str) -> Vec<String> {
    let path = HSTRING::from(subkey);
    let mut key = HKEY::default();
    // SAFETY: standard open/enumerate/close; the name buffer is sized to the
    // registry's 255-character key-name limit.
    unsafe {
        if RegOpenKeyExW(root, &path, None, KEY_READ, &mut key) != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut names = Vec::new();
        let mut index = 0u32;
        loop {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            let status = RegEnumKeyExW(
                key,
                index,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            );
            if status != ERROR_SUCCESS {
                break; // ERROR_NO_MORE_ITEMS
            }
            names.push(String::from_utf16_lossy(&buf[..len as usize]));
            index += 1;
        }
        let _ = RegCloseKey(key);
        names
    }
}

/// Every value of a key: its name, and its data when it's a string.
pub fn values(root: HKEY, subkey: &str) -> Vec<(String, Option<String>)> {
    let path = HSTRING::from(subkey);
    let mut key = HKEY::default();
    // SAFETY: standard open/enumerate/close; name and data buffers are sized
    // to the registry's limits for names and to 16 KB of data.
    unsafe {
        if RegOpenKeyExW(root, &path, None, KEY_READ, &mut key) != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = [0u16; 16_384];
            let mut name_len = name.len() as u32;
            let mut kind = 0u32;
            let mut data = vec![0u8; 16 * 1024];
            let mut data_len = data.len() as u32;
            let status = RegEnumValueW(
                key,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            );
            if status != ERROR_SUCCESS {
                break; // ERROR_NO_MORE_ITEMS
            }
            index += 1;
            let text = (kind == REG_SZ.0 || kind == REG_EXPAND_SZ.0).then(|| {
                // A byte buffer has no u16 alignment: decode pairs instead.
                let wide: Vec<u16> = data[..data_len as usize].as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).take_while(|&c| c != 0).collect();
                String::from_utf16_lossy(&wide)
            });
            out.push((String::from_utf16_lossy(&name[..name_len as usize]), text));
        }
        let _ = RegCloseKey(key);
        out
    }
}

/// A REG_SZ or REG_EXPAND_SZ value as stored, with `%VARIABLES%` left in.
/// For a value in another user's hive: expanding it here would use this
/// process's environment, not theirs.
pub fn read_string_unexpanded(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let subkey = HSTRING::from(subkey);
    let value = HSTRING::from(value);
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: `buf` is writable for `size` bytes and outlives the call.
    let status = unsafe {
        RegGetValueW(
            root,
            &subkey,
            &value,
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..len]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Register an Application event-log source backed by .NET's
/// EventLogMessages.dll (what PowerShell's `New-EventLog` does), so events
/// render cleanly in Event Viewer. Needs admin; a no-op if it already exists.
pub fn ensure_event_source(source: &str) {
    let subkey = format!(r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{source}");
    if read_string(HKEY_LOCAL_MACHINE, &subkey, "EventMessageFile").is_some() {
        return;
    }
    let windir = super::dirs::windows();
    let Some(dll) = [
        r"Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll",
        r"Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll",
    ]
    .iter()
    .map(|rel| windir.join(rel))
    .find(|p| p.is_file())
    .map(|p| p.display().to_string()) else {
        return;
    };

    let path = HSTRING::from(subkey.as_str());
    let mut key = HKEY::default();
    // SAFETY: create/set/close on a key we own; value buffers outlive the calls.
    unsafe {
        if RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            &path,
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        ) != ERROR_SUCCESS
        {
            return;
        }
        let wide: Vec<u16> = dll.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
        let _ = RegSetValueExW(key, &HSTRING::from("EventMessageFile"), None, REG_EXPAND_SZ, Some(bytes));
        let types: u32 = 7; // error | warning | information
        let _ = RegSetValueExW(key, &HSTRING::from("TypesSupported"), None, REG_DWORD, Some(&types.to_le_bytes()));
        let _ = RegCloseKey(key);
    }
}
