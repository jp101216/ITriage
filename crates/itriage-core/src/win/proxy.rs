//! Proxy configuration: the machine-wide WinHTTP proxy (`netsh winhttp show
//! proxy`) and a user's WinINet settings (Internet Options → LAN settings),
//! read from their own hive the way Invoke-NetTriage does.

use super::registry::{read_binary, read_dword, read_string, HKCU, HKU};
use windows::core::PWSTR;
use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::{
    WinHttpGetDefaultProxyConfiguration, WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_PROXY_INFO,
};

/// `None` = direct.
pub struct WinHttp {
    pub proxy: Option<String>,
    pub bypass: Option<String>,
}

pub fn winhttp() -> Result<WinHttp, String> {
    let mut info = WINHTTP_PROXY_INFO::default();
    // SAFETY: WinHTTP allocates the strings with GlobalAlloc; each is freed
    // once with GlobalFree.
    unsafe {
        WinHttpGetDefaultProxyConfiguration(&mut info).map_err(|e| super::err("reading the WinHTTP proxy", &e))?;
        let take = |p: PWSTR| -> Option<String> {
            if p.is_null() {
                return None;
            }
            let s = p.to_string().ok();
            let _ = GlobalFree(Some(HGLOBAL(p.0 as *mut _)));
            s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        };
        let proxy = take(info.lpszProxy);
        let bypass = take(info.lpszProxyBypass);
        Ok(WinHttp {
            proxy: proxy.filter(|_| info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY),
            bypass,
        })
    }
}

/// A user's WinINet proxy settings.
pub struct UserProxy {
    pub server: Option<String>,
    pub pac: Option<String>,
    pub bypass: Option<String>,
    /// "Automatically detect settings" (WPAD).
    pub auto_detect: bool,
}

/// From `HKU\<sid>` when given (another account's hive), else HKCU.
pub fn user(sid: Option<&str>) -> UserProxy {
    const SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let (root, path) = match sid {
        Some(s) => (HKU, format!(r"{s}\{SETTINGS}")),
        None => (HKCU, SETTINGS.to_string()),
    };
    let enabled = read_dword(root, &path, "ProxyEnable") == Some(1);
    // The Connections blob's flags byte: 0x08 = auto-detect.
    let auto_detect = read_binary(root, &format!(r"{path}\Connections"), "DefaultConnectionSettings")
        .and_then(|b| b.get(8).copied())
        .is_some_and(|flags| flags & 0x08 != 0);
    UserProxy {
        server: read_string(root, &path, "ProxyServer").filter(|_| enabled),
        pac: read_string(root, &path, "AutoConfigURL"),
        bypass: read_string(root, &path, "ProxyOverride").filter(|_| enabled),
        auto_detect,
    }
}
