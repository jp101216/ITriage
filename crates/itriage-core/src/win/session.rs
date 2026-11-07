//! The signed-in (console) user, and the SID behind an account name, for
//! reading that user's registry hive when itriage runs under another account
//! (an elevated technician login).

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};
use windows::Win32::System::RemoteDesktop::{
    WTSDomainName, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
    WTS_INFO_CLASS,
};

/// `DOMAIN\user` of whoever is signed in at the console, if anyone.
pub fn console_user() -> Option<String> {
    // SAFETY: plain query; 0xFFFFFFFF means no console session.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return None;
    }
    let name = query(session, WTSUserName).filter(|n| !n.is_empty())?;
    Some(match query(session, WTSDomainName).filter(|d| !d.is_empty()) {
        Some(domain) => format!("{domain}\\{name}"),
        None => name,
    })
}

fn query(session: u32, class: WTS_INFO_CLASS) -> Option<String> {
    let mut buf = PWSTR::null();
    let mut bytes = 0u32;
    // SAFETY: WTS allocates the buffer; it's freed with WTSFreeMemory.
    unsafe {
        WTSQuerySessionInformationW(None, session, class, &mut buf, &mut bytes).ok()?;
        let text = buf.to_string().ok();
        WTSFreeMemory(buf.0 as *mut _);
        text.map(|t| t.trim().to_string())
    }
}

/// The string SID ("S-1-5-21-…") of an account name.
pub fn sid_of(account: &str) -> Option<String> {
    let name = HSTRING::from(account);
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut kind = SID_NAME_USE::default();
    // SAFETY: the first call only reports sizes; the second fills buffers of
    // those sizes; the string SID is freed with LocalFree.
    unsafe {
        let _ = LookupAccountNameW(PCWSTR::null(), &name, None, &mut sid_len, None, &mut domain_len, &mut kind);
        if sid_len == 0 {
            return None;
        }
        let mut sid = vec![0u8; sid_len as usize];
        let mut domain = vec![0u16; domain_len.max(1) as usize];
        LookupAccountNameW(
            PCWSTR::null(),
            &name,
            Some(PSID(sid.as_mut_ptr() as *mut _)),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
        .ok()?;
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(PSID(sid.as_mut_ptr() as *mut _), &mut text).ok()?;
        let out = text.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut _)));
        out
    }
}

/// The account itriage itself runs as.
pub fn current_account() -> Option<String> {
    let user = std::env::var("USERNAME").ok()?;
    Some(match std::env::var("USERDOMAIN") {
        Ok(d) if !d.is_empty() => format!("{d}\\{user}"),
        _ => user,
    })
}
