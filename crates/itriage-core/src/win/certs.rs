//! Machine certificates (LocalMachine\My), opened read-only.

use crate::parse::revocation::{Outcome, UrlCheck, UrlKind};
use std::collections::HashMap;
use std::time::Duration;
use windows::core::{w, PCSTR};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertCreateCRLContext, CertEnumCertificatesInStore, CertFreeCRLContext, CertFreeCertificateChain,
    CertGetCertificateChain, CertGetCertificateContextProperty, CertGetNameStringW, CertOpenStore, CryptGetObjectUrl,
    CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT,
    CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_NAME_ISSUER_FLAG,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_OPEN_EXISTING_FLAG,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
    CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_GET_URL_FROM_EXTENSION, CRYPT_URL_ARRAY, HCERTCHAINENGINE,
    PKCS_7_ASN_ENCODING, URL_OID_CERTIFICATE_CRL_DIST_POINT, URL_OID_CERTIFICATE_ISSUER, URL_OID_CERTIFICATE_OCSP,
    X509_ASN_ENCODING,
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

/// One machine certificate's revocation evidence: the subject, every URL
/// it names (CRLs fetched live), and the chain check's error status.
pub struct Revocation {
    pub subject: String,
    pub urls: Vec<UrlCheck>,
    pub chain: Option<u32>,
}

/// Revocation evidence for the machine certificates that are in use for
/// authentication (they have a private key) and not expired, at most `max`
/// of them. A CRL several certificates share is fetched once.
pub fn revocation(max: usize, timeout: Duration) -> Result<Vec<Revocation>, String> {
    let location = CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;
    let flags = CERT_OPEN_STORE_FLAGS(location | CERT_STORE_READONLY_FLAG.0 | CERT_STORE_OPEN_EXISTING_FLAG.0);
    let now = crate::util::now_epoch();
    let mut fetched: HashMap<String, Outcome> = HashMap::new();
    let mut out = Vec::new();
    // SAFETY: as in machine_certs; each chain context is freed after reading
    // its status, and CRL contexts right after reading their dates.
    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            flags,
            Some(w!("MY").as_ptr() as *const core::ffi::c_void),
        )
        .map_err(|e| super::err("can't open the machine certificate store", &e))?;
        let mut ctx: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            ctx = CertEnumCertificatesInStore(store, Some(ctx as *const CERT_CONTEXT));
            if ctx.is_null() || out.len() >= max {
                break;
            }
            let info = &*(*ctx).pCertInfo;
            let ft = (u64::from(info.NotAfter.dwHighDateTime) << 32) | u64::from(info.NotAfter.dwLowDateTime);
            let mut size = 0u32;
            let has_key = CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, None, &mut size).is_ok();
            if !has_key || crate::parse::time::filetime_to_epoch(ft).is_some_and(|t| t <= now) {
                continue;
            }
            let mut urls = Vec::new();
            for (oid, kind) in [(URL_OID_CERTIFICATE_CRL_DIST_POINT, UrlKind::Crl), (URL_OID_CERTIFICATE_OCSP, UrlKind::Ocsp), (URL_OID_CERTIFICATE_ISSUER, UrlKind::Issuer)] {
                for url in object_urls(ctx, oid) {
                    let outcome = match kind {
                        UrlKind::Crl if url.to_ascii_lowercase().starts_with("http") => {
                            fetched.entry(url.clone()).or_insert_with(|| fetch_crl(&url, timeout)).clone()
                        }
                        UrlKind::Crl => Outcome::ChainOnly,
                        _ => Outcome::Listed,
                    };
                    urls.push(UrlCheck { url, kind, outcome });
                }
            }
            out.push(Revocation { subject: name(ctx, 0), urls, chain: chain_status(ctx, timeout) });
        }
        if !ctx.is_null() {
            let _ = windows::Win32::Security::Cryptography::CertFreeCertificateContext(Some(ctx));
        }
        let _ = CertCloseStore(Some(store), 0);
    }
    Ok(out)
}

/// The URLs a certificate's extension names for one purpose.
unsafe fn object_urls(ctx: *const CERT_CONTEXT, oid: PCSTR) -> Vec<String> {
    let mut size = 0u32;
    if CryptGetObjectUrl(oid, ctx as *const core::ffi::c_void, CRYPT_GET_URL_FROM_EXTENSION, None, &mut size, None, None, None).is_err() || size == 0 {
        return Vec::new();
    }
    // u64-backed so the array header and the pointers in it are aligned.
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    let array = buf.as_mut_ptr() as *mut CRYPT_URL_ARRAY;
    if CryptGetObjectUrl(oid, ctx as *const core::ffi::c_void, CRYPT_GET_URL_FROM_EXTENSION, Some(array), &mut size, None, None, None).is_err() {
        return Vec::new();
    }
    let a = &*array;
    (0..a.cUrl as usize).filter_map(|i| (*a.rgwszUrl.add(i)).to_string().ok()).filter(|u| !u.is_empty()).collect()
}

/// Fetch a CRL over HTTP(S) through the system proxy and read its dates.
fn fetch_crl(url: &str, timeout: Duration) -> Outcome {
    let bytes = match super::net::http_get_bytes(url, timeout, 20 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return Outcome::Unreachable(e),
    };
    // SAFETY: the context is created from a live buffer and freed before return.
    unsafe {
        let crl = CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &bytes);
        if crl.is_null() {
            return Outcome::Unreachable("the response isn't a revocation list Windows can read".into());
        }
        let info = &*(*crl).pCrlInfo;
        let at = |ft: windows::Win32::Foundation::FILETIME| {
            let v = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
            if v == 0 { None } else { crate::parse::time::filetime_to_epoch(v) }
        };
        let outcome = Outcome::Fetched { this_update: at(info.ThisUpdate), next_update: at(info.NextUpdate) };
        let _ = CertFreeCRLContext(Some(crl));
        outcome
    }
}

/// The local machine chain engine's verdict, revocation checked for every
/// certificate but the root, within `timeout` overall.
unsafe fn chain_status(ctx: *const CERT_CONTEXT, timeout: Duration) -> Option<u32> {
    let para = CERT_CHAIN_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
        dwUrlRetrievalTimeout: timeout.as_millis().clamp(1_000, 30_000) as u32,
        ..Default::default()
    };
    let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
    // HCCE_LOCAL_MACHINE: the machine's chain engine, as for a machine certificate.
    let engine = HCERTCHAINENGINE(std::ptr::without_provenance_mut(1));
    CertGetCertificateChain(
        Some(engine),
        ctx,
        None,
        None,
        &para,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT,
        None,
        &mut chain,
    )
    .ok()?;
    if chain.is_null() {
        return None;
    }
    let status = (*chain).TrustStatus.dwErrorStatus;
    CertFreeCertificateChain(chain);
    Some(status)
}

unsafe fn name(ctx: *const CERT_CONTEXT, flags: u32) -> String {
    let mut buf = [0u16; 256];
    let len = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, Some(&mut buf)) as usize;
    String::from_utf16_lossy(&buf[..len.saturating_sub(1).min(buf.len())])
}
