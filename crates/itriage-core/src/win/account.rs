//! Accounts (NetAPI), the Credential Manager and sign-in sessions: what the
//! sign-in check reads, and the three things its fixes change.
//!
//! Saved credentials are listed by name only. The secret each one holds is
//! never read, copied or logged.

use crate::desk::account::{Policy, SavedCredential, Session, UserInfo};
use std::time::Duration;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGetAnyDCName, NetGetDCName, NetUserGetInfo, NetUserModalsGet, NetUserSetInfo, UF_ACCOUNTDISABLE,
    UF_DONT_EXPIRE_PASSWD, UF_LOCKOUT, UF_PASSWD_CANT_CHANGE, UF_SMARTCARD_REQUIRED, USER_ACCOUNT_FLAGS, USER_INFO_1008,
    USER_INFO_3, USER_MODALS_INFO_0, USER_MODALS_INFO_3,
};
use windows::Win32::Security::Credentials::{CredDeleteW, CredEnumerateW, CredFree, CREDENTIALW, CRED_TYPE};
use windows::Win32::System::RemoteDesktop::{
    WTSEnumerateSessionsW, WTSFreeMemory, WTSLogoffSession, WTS_SESSION_INFOW,
};

/// "Forever" in NetAPI's second counts.
const FOREVER: u32 = u32::MAX;

/// Frees a NetAPI buffer.
struct NetBuffer(*mut u8);

impl Drop for NetBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by the NetAPI call that filled it in; freed once.
            unsafe {
                let _ = NetApiBufferFree(Some(self.0 as *const core::ffi::c_void));
            }
        }
    }
}

fn server_ptr(server: &Option<HSTRING>) -> PCWSTR {
    server.as_ref().map_or(PCWSTR::null(), |h| PCWSTR(h.as_ptr()))
}

/// `NetUserGetInfo` level 3. `server` is `\\DC01`, or `None` for this PC.
/// The error is the NetAPI status code.
pub fn user_info(server: Option<&str>, user: &str) -> Result<UserInfo, u32> {
    let server = server.map(HSTRING::from);
    let user = HSTRING::from(user);
    let mut raw: *mut u8 = std::ptr::null_mut();
    // SAFETY: NetAPI allocates the buffer, which `NetBuffer` frees; it's
    // read as the level-3 structure the call was asked for.
    unsafe {
        let rc = NetUserGetInfo(server_ptr(&server), &user, 3, &mut raw);
        let buffer = NetBuffer(raw);
        if rc != 0 || buffer.0.is_null() {
            return Err(if rc == 0 { 1 } else { rc });
        }
        let info = &*(buffer.0 as *const USER_INFO_3);
        let has = |flag: USER_ACCOUNT_FLAGS| info.usri3_flags.0 & flag.0 != 0;
        Ok(UserInfo {
            locked: has(UF_LOCKOUT),
            disabled: has(UF_ACCOUNTDISABLE),
            password_never_expires: has(UF_DONT_EXPIRE_PASSWD),
            password_expired: info.usri3_password_expired != 0,
            cannot_change_password: has(UF_PASSWD_CANT_CHANGE),
            smartcard_required: has(UF_SMARTCARD_REQUIRED),
            password_age_secs: u64::from(info.usri3_password_age),
            bad_password_count: info.usri3_bad_pw_count,
        })
    }
}

pub fn policy(server: Option<&str>) -> Result<Policy, u32> {
    let server = server.map(HSTRING::from);
    // SAFETY: as in `user_info`; each buffer is read as the level asked for.
    unsafe {
        let mut raw: *mut u8 = std::ptr::null_mut();
        let rc = NetUserModalsGet(server_ptr(&server), 0, &mut raw);
        let passwords = NetBuffer(raw);
        if rc != 0 || passwords.0.is_null() {
            return Err(if rc == 0 { 1 } else { rc });
        }
        let max_age = (*(passwords.0 as *const USER_MODALS_INFO_0)).usrmod0_max_passwd_age;

        let mut raw: *mut u8 = std::ptr::null_mut();
        let rc = NetUserModalsGet(server_ptr(&server), 3, &mut raw);
        let lockout = NetBuffer(raw);
        if rc != 0 || lockout.0.is_null() {
            return Err(if rc == 0 { 1 } else { rc });
        }
        let l = &*(lockout.0 as *const USER_MODALS_INFO_3);
        Ok(Policy {
            max_password_age_secs: (max_age != FOREVER && max_age != 0).then_some(u64::from(max_age)),
            lockout_threshold: l.usrmod3_lockout_threshold,
            lockout_duration_secs: (l.usrmod3_lockout_duration != FOREVER).then_some(u64::from(l.usrmod3_lockout_duration)),
            lockout_window_secs: u64::from(l.usrmod3_lockout_observation_window),
        })
    }
}

/// A domain controller for `domain`, as `\\DC01`: whichever one this PC is
/// already talking to, else the primary. Looking for one off the network
/// can take a long time, so the search is given up after `timeout`.
pub fn domain_controller(domain: &str, timeout: Duration) -> Option<String> {
    let domain = domain.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let name = HSTRING::from(domain.as_str());
        let find = |any: bool| -> Option<String> {
            let mut raw: *mut u8 = std::ptr::null_mut();
            // SAFETY: NetAPI allocates a wide string, freed by `NetBuffer`.
            unsafe {
                let rc = if any {
                    NetGetAnyDCName(PCWSTR::null(), &name, &mut raw)
                } else {
                    NetGetDCName(PCWSTR::null(), &name, &mut raw)
                };
                let buffer = NetBuffer(raw);
                if rc != 0 || buffer.0.is_null() {
                    return None;
                }
                PCWSTR(buffer.0 as *const u16).to_string().ok().filter(|s| !s.trim_matches('\\').is_empty())
            }
        };
        let _ = tx.send(find(true).or_else(|| find(false)));
    });
    rx.recv_timeout(timeout).ok().flatten()
}

/// Clear an account's lockout. `Ok(false)` when it wasn't locked.
pub fn unlock(server: Option<&str>, user: &str) -> Result<bool, u32> {
    let server_name = server.map(HSTRING::from);
    let user_name = HSTRING::from(user);
    // SAFETY: the flags are read from the level-3 buffer, then written back
    // through a level-1008 structure that lives until the call returns.
    unsafe {
        let mut raw: *mut u8 = std::ptr::null_mut();
        let rc = NetUserGetInfo(server_ptr(&server_name), &user_name, 3, &mut raw);
        let buffer = NetBuffer(raw);
        if rc != 0 || buffer.0.is_null() {
            return Err(if rc == 0 { 1 } else { rc });
        }
        let flags = (*(buffer.0 as *const USER_INFO_3)).usri3_flags;
        if flags.0 & UF_LOCKOUT.0 == 0 {
            return Ok(false);
        }
        let update = USER_INFO_1008 { usri1008_flags: USER_ACCOUNT_FLAGS(flags.0 & !UF_LOCKOUT.0) };
        let rc = NetUserSetInfo(server_ptr(&server_name), &user_name, 1008, &update as *const USER_INFO_1008 as *const u8, None);
        if rc != 0 {
            return Err(rc);
        }
        Ok(true)
    }
}

/// A NetAPI status as people say it.
pub fn net_error(code: u32) -> String {
    match code {
        5 => "access denied".into(),
        53 | 1722 | 1723 | 2453 | 1355 | 1311 => "no domain controller could be reached".into(),
        2221 => "the account doesn't exist there".into(),
        2351 | 1210 => "the server name isn't valid".into(),
        other => format!("error {other}: {}", std::io::Error::from_raw_os_error(other as i32)),
    }
}

/// The credentials saved for the account ITriage runs as. Names only.
pub fn saved_credentials() -> Result<Vec<SavedCredential>, String> {
    let mut count = 0u32;
    let mut list: *mut *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: Windows allocates the array, freed with CredFree after the
    // names are copied out. `CredentialBlob` (the secret) is never touched.
    unsafe {
        if let Err(e) = CredEnumerateW(PCWSTR::null(), None, &mut count, &mut list) {
            if e.code() == ERROR_NOT_FOUND.to_hresult() {
                return Ok(Vec::new());
            }
            return Err(super::err("can't list saved credentials", &e));
        }
        let mut out = Vec::new();
        if !list.is_null() {
            for &entry in std::slice::from_raw_parts(list, count as usize) {
                if entry.is_null() {
                    continue;
                }
                let c = &*entry;
                let text = |p: windows::core::PWSTR| if p.is_null() { String::new() } else { p.to_string().unwrap_or_default() };
                let written = (u64::from(c.LastWritten.dwHighDateTime) << 32) | u64::from(c.LastWritten.dwLowDateTime);
                out.push(SavedCredential {
                    target: text(c.TargetName),
                    user: text(c.UserName),
                    kind: c.Type.0,
                    saved: crate::parse::time::filetime_to_epoch(written),
                });
            }
            CredFree(list as *const core::ffi::c_void);
        }
        Ok(out)
    }
}

/// Remove one saved credential.
pub fn delete_credential(target: &str, kind: u32) -> Result<(), String> {
    let name = HSTRING::from(target);
    // SAFETY: plain call with a valid wide string.
    unsafe { CredDeleteW(&name, CRED_TYPE(kind), None) }.map_err(|e| super::err(&format!("couldn't remove {target}"), &e))
}

pub fn sessions() -> Vec<Session> {
    let mut list: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: WTS allocates the array, freed with WTSFreeMemory after the
    // fields are copied out.
    unsafe {
        if WTSEnumerateSessionsW(None, 0, 1, &mut list, &mut count).is_err() || list.is_null() {
            return Vec::new();
        }
        let out = std::slice::from_raw_parts(list, count as usize)
            .iter()
            .map(|s| Session {
                id: s.SessionId,
                account: super::session::session_user(s.SessionId).unwrap_or_default(),
                state: s.State.0,
                station: if s.pWinStationName.is_null() { String::new() } else { s.pWinStationName.to_string().unwrap_or_default() },
            })
            .collect();
        WTSFreeMemory(list as *mut core::ffi::c_void);
        out
    }
}

/// Sign a session out. Doesn't wait for it to finish.
pub fn logoff(id: u32) -> Result<(), String> {
    // SAFETY: plain call; the default server handle is this PC.
    unsafe { WTSLogoffSession(None, id, false) }.map_err(|e| super::err(&format!("couldn't sign out session {id}"), &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CI runner is a workgroup PC, so this is the local-account path: the
    /// same calls a domain PC makes against its domain controller.
    #[test]
    fn reads_the_account_this_runs_as() {
        let user = std::env::var("USERNAME").expect("Windows sets USERNAME");
        let info = user_info(None, &user).unwrap_or_else(|code| panic!("{user}: {}", net_error(code)));
        assert!(!info.disabled && !info.locked, "this account is running the test: {info:?}");
        let rules = policy(None).unwrap_or_else(|code| panic!("{}", net_error(code)));
        assert!(rules.lockout_threshold < 1000, "{rules:?}");
        assert_eq!(user_info(None, "no-such-user-xyz"), Err(2221));
        assert_eq!(unlock(None, &user), Ok(false), "it isn't locked, so nothing is changed");
        assert!(net_error(5).contains("denied") && net_error(2221).contains("doesn't exist"));
    }

    #[test]
    fn lists_sessions_and_saved_credentials() {
        let all = sessions();
        assert!(!all.is_empty(), "there's always at least the services session");
        // Whatever is saved, it lists without error and without secrets.
        let saved = saved_credentials().unwrap();
        assert!(saved.iter().all(|c| !c.target.is_empty()), "{saved:?}");
        assert!(delete_credential("itriage-test-no-such-credential", 1).is_err());
        assert!(domain_controller("NO-SUCH-DOMAIN-XYZ", Duration::from_secs(15)).is_none());
    }
}
