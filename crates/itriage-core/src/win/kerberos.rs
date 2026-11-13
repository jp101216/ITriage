//! The Kerberos ticket cache of the logon session ITriage runs in, through
//! LSA (what `klist` and `klist purge` do). An untrusted LSA connection only
//! reaches the caller's own session (LogonId 0), so an elevated run sees the
//! elevated token's session, not the person's: callers check that first.

use crate::parse::kerberos::Ticket;
use windows::core::PSTR;
use windows::Win32::Foundation::{HANDLE, LUID, NTSTATUS};
use windows::Win32::Security::Authentication::Identity::{
    KerbPurgeTicketCacheMessage, KerbQueryTicketCacheEx3Message, LsaCallAuthenticationPackage, LsaConnectUntrusted,
    LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaLookupAuthenticationPackage, KERB_PURGE_TKT_CACHE_REQUEST,
    KERB_QUERY_TKT_CACHE_EX3_RESPONSE, KERB_QUERY_TKT_CACHE_REQUEST, KERB_TICKET_CACHE_INFO_EX3, LSA_STRING,
    LSA_UNICODE_STRING,
};

struct Lsa {
    handle: HANDLE,
    package: u32,
}

impl Drop for Lsa {
    fn drop(&mut self) {
        // SAFETY: a handle LsaConnectUntrusted gave us, closed once.
        unsafe {
            let _ = LsaDeregisterLogonProcess(self.handle);
        }
    }
}

fn status(what: &str, s: NTSTATUS) -> Result<(), String> {
    if s.is_ok() {
        Ok(())
    } else {
        Err(format!("{what} (NTSTATUS 0x{:08X})", s.0 as u32))
    }
}

fn connect() -> Result<Lsa, String> {
    let mut handle = HANDLE::default();
    // SAFETY: out-parameter; the handle is closed by Lsa's Drop.
    status("can't connect to the Local Security Authority", unsafe { LsaConnectUntrusted(&mut handle) })?;
    let mut lsa = Lsa { handle, package: 0 };
    let mut name = *b"Kerberos";
    let package = LSA_STRING { Length: name.len() as u16, MaximumLength: name.len() as u16, Buffer: PSTR(name.as_mut_ptr()) };
    // SAFETY: `package` points at `name`, which outlives the call.
    status("Kerberos isn't available", unsafe { LsaLookupAuthenticationPackage(lsa.handle, &package, &mut lsa.package) })?;
    Ok(lsa)
}

unsafe fn text(s: &LSA_UNICODE_STRING) -> String {
    if s.Buffer.is_null() || s.Length == 0 {
        return String::new();
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(s.Buffer.0, usize::from(s.Length) / 2))
}

/// A FILETIME-valued LARGE_INTEGER as Unix seconds; 0 and "never" are `None`.
fn when(ft: i64) -> Option<u64> {
    if ft <= 0 || ft == i64::MAX {
        return None;
    }
    crate::parse::time::filetime_to_epoch(ft as u64)
}

/// Every ticket in this logon session's cache.
pub fn tickets() -> Result<Vec<Ticket>, String> {
    let lsa = connect()?;
    let request = KERB_QUERY_TKT_CACHE_REQUEST { MessageType: KerbQueryTicketCacheEx3Message, LogonId: LUID::default() };
    let mut response: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut length = 0u32;
    let mut protocol = 0i32;
    // SAFETY: the request is a live local of the size passed; LSA allocates
    // the response, which is freed with LsaFreeReturnBuffer below.
    unsafe {
        status(
            "couldn't list Kerberos tickets",
            LsaCallAuthenticationPackage(
                lsa.handle,
                lsa.package,
                &request as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
                Some(&mut response),
                Some(&mut length),
                Some(&mut protocol),
            ),
        )?;
        let listed = status("couldn't list Kerberos tickets", NTSTATUS(protocol)).and_then(|_| {
            if response.is_null() {
                return Ok(Vec::new());
            }
            let head = &*(response as *const KERB_QUERY_TKT_CACHE_EX3_RESPONSE);
            let count = head.CountOfTickets as usize;
            // The array runs past the declared one-element field; check it
            // fits in what LSA returned before reading it.
            let offset = std::mem::offset_of!(KERB_QUERY_TKT_CACHE_EX3_RESPONSE, Tickets);
            if offset + count * std::mem::size_of::<KERB_TICKET_CACHE_INFO_EX3>() > length as usize {
                return Err("LSA returned a ticket list shorter than it claimed".to_string());
            }
            let items = std::slice::from_raw_parts(head.Tickets.as_ptr(), count);
            Ok(items
                .iter()
                .map(|t| Ticket {
                    client: format!("{}@{}", text(&t.ClientName), text(&t.ClientRealm)),
                    server: text(&t.ServerName),
                    realm: text(&t.ServerRealm),
                    start: when(t.StartTime),
                    end: when(t.EndTime),
                    renew: when(t.RenewTime),
                    etype: Some(t.EncryptionType),
                    kdc: text(&t.KdcCalled),
                })
                .collect())
        });
        if !response.is_null() {
            let _ = LsaFreeReturnBuffer(response);
        }
        listed
    }
}

/// Remove every ticket from this logon session's cache (`klist purge`).
pub fn purge() -> Result<(), String> {
    let lsa = connect()?;
    // Empty server and realm names mean "all of them".
    let request = KERB_PURGE_TKT_CACHE_REQUEST {
        MessageType: KerbPurgeTicketCacheMessage,
        LogonId: LUID::default(),
        ServerName: LSA_UNICODE_STRING::default(),
        RealmName: LSA_UNICODE_STRING::default(),
    };
    let mut protocol = 0i32;
    // SAFETY: the request is a live local of the size passed; no response buffer.
    unsafe {
        status(
            "couldn't clear the Kerberos tickets",
            LsaCallAuthenticationPackage(
                lsa.handle,
                lsa.package,
                &request as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<KERB_PURGE_TKT_CACHE_REQUEST>() as u32,
                None,
                None,
                Some(&mut protocol),
            ),
        )?;
    }
    status("couldn't clear the Kerberos tickets", NTSTATUS(protocol))
}
