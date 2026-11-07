//! Machine certificates (LocalMachine\My), opened read-only.

use windows::core::w;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertGetCertificateContextProperty, CertGetNameStringW,
    CertOpenStore, CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_NAME_ISSUER_FLAG,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_LOCAL_MACHINE_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT,
};

#[derive(Clone, Debug)]
pub struct Cert {
    pub subject: String,
    pub issuer: String,
    /// Expiry as Unix seconds.
    pub not_after: Option<u64>,
    /// Has a private key: in use for authentication (802.1X, VPN, TLS).
    pub has_key: bool,
}

pub fn machine_certs() -> Result<Vec<Cert>, String> {
    let location = CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;
    let flags = CERT_OPEN_STORE_FLAGS(location | CERT_STORE_READONLY_FLAG.0 | CERT_STORE_OPEN_EXISTING_FLAG.0);
    // SAFETY: the store is closed on every path; CertEnumCertificatesInStore
    // frees the previous context itself as it advances.
    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            flags,
            Some(w!("MY").as_ptr() as *const core::ffi::c_void),
        )
        .map_err(|e| super::err("can't open the machine certificate store", &e))?;

        let mut out = Vec::new();
        let mut ctx: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            ctx = CertEnumCertificatesInStore(store, Some(ctx as *const CERT_CONTEXT));
            if ctx.is_null() {
                break;
            }
            let info = &*(*ctx).pCertInfo;
            let ft = (u64::from(info.NotAfter.dwHighDateTime) << 32) | u64::from(info.NotAfter.dwLowDateTime);
            let mut size = 0u32;
            let has_key = CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, None, &mut size).is_ok();
            out.push(Cert {
                subject: name(ctx, 0),
                issuer: name(ctx, CERT_NAME_ISSUER_FLAG),
                not_after: crate::parse::time::filetime_to_epoch(ft),
                has_key,
            });
        }
        let _ = CertCloseStore(Some(store), 0);
        Ok(out)
    }
}

unsafe fn name(ctx: *const CERT_CONTEXT, flags: u32) -> String {
    let mut buf = [0u16; 256];
    let len = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, Some(&mut buf)) as usize;
    String::from_utf16_lossy(&buf[..len.saturating_sub(1).min(buf.len())])
}
