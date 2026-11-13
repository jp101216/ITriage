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
    session_user(session)
}

/// `DOMAIN\user` of whoever owns a session, if anyone is signed in to it.
pub fn session_user(session: u32) -> Option<String> {
    let name = query(session, WTSUserName).filter(|n| !n.is_empty())?;
    Some(match query(session, WTSDomainName).filter(|d| !d.is_empty()) {
        Some(domain) => format!("{domain}\\{name}"),
        None => name,
    })
}

/// The session ITriage itself is running in.
pub fn current_session() -> Option<u32> {
    session_of(std::process::id())
}

/// The session a process runs in.
pub fn session_of(pid: u32) -> Option<u32> {
    let mut id = 0u32;
    // SAFETY: plain query; a process that's gone just fails.
    unsafe { windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut id) }.ok()?;
    Some(id)
}

/// The console session, if someone could be signed in to it.
pub fn console_session() -> Option<u32> {
    // SAFETY: plain query; 0xFFFFFFFF means no console session.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    (session != u32::MAX).then_some(session)
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

/// The person signed in at this PC, and where their settings and files
/// are, for reading them when ITriage runs as another account (an elevated
/// technician sign-in would otherwise read its own HKCU and profile).
pub struct Person {
    pub account: String,
    /// HKCU when ITriage runs as them, else HKEY_USERS with `prefix`.
    pub root: windows::Win32::System::Registry::HKEY,
    pub prefix: String,
    pub profile: std::path::PathBuf,
    pub session: Option<u32>,
}

impl Person {
    /// A key under this person's hive.
    pub fn key(&self, subkey: &str) -> String {
        format!("{}{subkey}", self.prefix)
    }
}

/// Whoever is at the console, else the account ITriage runs as.
pub fn person() -> Result<Person, String> {
    use crate::win::registry::{read_hklm_string, HKCU, HKU};
    let me = current_account();
    let account = console_user().or_else(|| me.clone()).ok_or("Nobody is signed in to check.")?;
    let same = me.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(&account));
    let sid = sid_of(&account);
    let profile = sid
        .as_deref()
        .and_then(|s| read_hklm_string(&format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{s}"), "ProfileImagePath"))
        .map(std::path::PathBuf::from)
        .or_else(|| if same { std::env::var_os("USERPROFILE").map(std::path::PathBuf::from) } else { None })
        .ok_or_else(|| format!("Can't find {account}'s profile folder."))?;
    let (root, prefix) = if same {
        (HKCU, String::new())
    } else {
        (HKU, format!(r"{}\", sid.ok_or_else(|| format!("Can't find {account}'s registry hive."))?))
    };
    let session = if same { current_session() } else { console_session() };
    Ok(Person { account, root, prefix, profile, session })
}

/// Is a program with this file name (`ms-teams.exe`) running, in that
/// session when one is given?
pub fn running_in(exe: &str, session: Option<u32>) -> bool {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    sys.processes().values().any(|p| {
        p.name().to_string_lossy().eq_ignore_ascii_case(exe) && session.is_none_or(|s| session_of(p.pid().as_u32()) == Some(s))
    })
}
