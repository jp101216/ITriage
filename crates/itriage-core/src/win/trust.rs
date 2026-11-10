//! Reading and setting file security: who owns a file and who its access
//! list lets write to it (for [`crate::trust`]), and making a folder that
//! only administrators can touch.

use crate::trust::Ace;
use std::path::Path;
use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetAce, GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const INHERIT_ONLY_ACE: u8 = 0x08;

/// Frees a buffer Windows allocated with LocalAlloc.
struct Local(*mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by the API that filled it in; freed once.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

/// # Safety
/// `sid` must point at a valid SID.
unsafe fn sid_string(sid: PSID) -> Option<String> {
    let mut text = PWSTR::null();
    ConvertSidToStringSidW(sid, &mut text).ok()?;
    let _free = Local(text.0 as *mut _);
    text.to_string().ok()
}

/// A file or folder's owner and access list. The list is `None` when the
/// object has none (which Windows reads as "everyone, everything").
pub fn security(path: &Path) -> Result<(String, Option<Vec<Ace>>), String> {
    let name = HSTRING::from(path.as_os_str());
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: out-pointers are live locals; `owner` and `dacl` point into
    // `descriptor`, which is freed when `_free` drops, after they're read.
    unsafe {
        let rc = GetNamedSecurityInfoW(
            &name,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        );
        if rc != ERROR_SUCCESS {
            return Err(format!("can't read who may change {} (error {})", path.display(), rc.0));
        }
        let _free = Local(descriptor.0);
        let owner = sid_string(owner).ok_or_else(|| format!("{} has no readable owner", path.display()))?;
        if dacl.is_null() {
            return Ok((owner, None));
        }
        let mut aces = Vec::new();
        for index in 0..u32::from((*dacl).AceCount) {
            let mut raw: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl, index, &mut raw).is_err() || raw.is_null() {
                return Err(format!("can't read the access list of {}", path.display()));
            }
            let header = &*(raw as *const ACE_HEADER);
            match header.AceType {
                ACCESS_DENIED_ACE_TYPE => continue,
                ACCESS_ALLOWED_ACE_TYPE => {
                    let ace = raw as *const ACCESS_ALLOWED_ACE;
                    let sid = PSID(std::ptr::addr_of!((*ace).SidStart) as *mut _);
                    aces.push(Ace {
                        allow: true,
                        inherit_only: header.AceFlags & INHERIT_ONLY_ACE != 0,
                        mask: (*ace).Mask,
                        sid: sid_string(sid).unwrap_or_else(|| "an unreadable account".into()),
                    });
                }
                // Object, callback and other rarer entry types: their layout
                // differs, so rather than misread one, count it as granting
                // everything to someone unknown.
                other => aces.push(Ace {
                    allow: true,
                    inherit_only: header.AceFlags & INHERIT_ONLY_ACE != 0,
                    mask: u32::MAX,
                    sid: format!("an access entry of type {other}"),
                }),
            }
        }
        Ok((owner, Some(aces)))
    }
}

/// Replace a folder's access list with "Administrators and SYSTEM: full
/// control", inherited by everything created inside, and cut it off from
/// its parent's list. The caller must own the folder (it just made it).
pub fn admins_only(dir: &Path) -> Result<(), String> {
    // D: a DACL, P: protected (no inheritance from the parent), AI: children
    // inherit; full access for Built-in Administrators and Local System.
    let sddl = HSTRING::from("D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)");
    let name = HSTRING::from(dir.as_os_str());
    let fail = |what: &str, detail: String| format!("can't lock down {} ({what}: {detail})", dir.display());
    // SAFETY: the descriptor is freed when `_free` drops; `dacl` points into
    // it and is only used before that.
    unsafe {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, SDDL_REVISION_1, &mut descriptor, None)
            .map_err(|e| fail("building the access list", e.message()))?;
        let _free = Local(descriptor.0);
        let mut present = windows::core::BOOL::default();
        let mut defaulted = windows::core::BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            .map_err(|e| fail("reading the access list", e.message()))?;
        if !present.as_bool() || dacl.is_null() {
            return Err(fail("building the access list", "it came back empty".into()));
        }
        let rc = SetNamedSecurityInfoW(
            &name,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        );
        if rc != ERROR_SUCCESS {
            return Err(fail("setting it", format!("error {}", rc.0)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{untrusted_writers, Kind};

    #[test]
    fn a_locked_down_folder_admits_only_administrators() {
        let dir = std::env::temp_dir().join(format!("itriage-lockdown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        // As created, it inherits this account's own rights.
        let (_, before) = security(&dir).unwrap();
        assert!(before.is_some_and(|a| !a.is_empty()));
        // Only meaningful when this process may set security, as the CI
        // runner (an administrator) can.
        if admins_only(&dir).is_ok() {
            let (_, aces) = security(&dir).unwrap();
            let aces = aces.expect("it has an access list");
            // Whoever owns it, the list itself now names only administrators.
            assert!(untrusted_writers("S-1-5-18", Some(&aces), Kind::Folder).is_empty(), "{aces:?}");
            assert_eq!(aces.len(), 2);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
