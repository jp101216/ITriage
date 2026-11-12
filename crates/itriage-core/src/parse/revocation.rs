//! Certificate revocation: can anything that checks this PC's certificate
//! (the RADIUS server for 802.1X, a VPN gateway, smart-card sign-in) still
//! check it?
//!
//! An expired revocation list (CRL) on the issuing CA breaks them all at
//! once: the classic "nobody can get on the network at 7 a.m." outage.
//! Windows caches CRLs, so a chain check on this PC can still pass on a
//! cached list while the place it's published is already down. Both are
//! reported: the list fetched live from each distribution point, and what
//! the chain check concluded.

use crate::model::{Finding, Severity};
use crate::parse::time::epoch_to_rfc3339;
use crate::util::ago;

/// What a certificate names as somewhere to check it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlKind {
    /// CRL distribution point.
    Crl,
    Ocsp,
    /// Where the issuer's certificate is published (AIA).
    Issuer,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// A CRL fetched and read: when it was issued and when the next is due.
    Fetched { this_update: Option<u64>, next_update: Option<u64> },
    /// The fetch failed.
    Unreachable(String),
    /// LDAP: not fetched here (the chain check uses it).
    ChainOnly,
    /// OCSP and issuer URLs are listed, not queried.
    Listed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UrlCheck {
    pub url: String,
    pub kind: UrlKind,
    pub outcome: Outcome,
}

/// The chain check's verdict on revocation, from CERT_TRUST_STATUS bits.
pub const IS_REVOKED: u32 = 0x4;
pub const UNTRUSTED_ROOT: u32 = 0x20;
pub const STATUS_UNKNOWN: u32 = 0x40;
pub const OFFLINE_REVOCATION: u32 = 0x0100_0000;

pub fn chain_verdict(status: u32) -> (Severity, &'static str) {
    if status & IS_REVOKED != 0 {
        (Severity::Critical, "the certificate is REVOKED")
    } else if status & OFFLINE_REVOCATION != 0 {
        (Severity::Warning, "revocation server offline")
    } else if status & STATUS_UNKNOWN != 0 {
        (Severity::Warning, "revocation status unknown")
    } else if status & UNTRUSTED_ROOT != 0 {
        (Severity::Warning, "its root isn't trusted here")
    } else {
        (Severity::Ok, "passed")
    }
}

/// One fetched CRL's state against the clock.
pub fn crl_verdict(next_update: Option<u64>, now: u64, warn_hours: u32) -> (Severity, String) {
    match next_update {
        None => (Severity::Ok, "current (no next update set)".into()),
        Some(next) if next <= now => (Severity::Critical, format!("EXPIRED {} (next update was due {} UTC)", ago(now - next), &epoch_to_rfc3339(next)[..16])),
        Some(next) if next - now <= u64::from(warn_hours) * 3_600 => (Severity::Warning, format!("expires in {}h ({} UTC) unless the CA publishes a new one", (next - now).div_ceil(3_600), &epoch_to_rfc3339(next)[..16])),
        Some(next) => (Severity::Ok, format!("current until {} UTC", &epoch_to_rfc3339(next)[..16])),
    }
}

fn worst(a: Severity, b: Severity) -> Severity {
    if b.rank() > a.rank() {
        b
    } else {
        a
    }
}

/// One row per certificate: the live CRL and the chain check together.
pub fn finding(subject: &str, urls: &[UrlCheck], chain: Option<u32>, now: u64, warn_hours: u32) -> Finding {
    let crls: Vec<&UrlCheck> = urls.iter().filter(|u| u.kind == UrlKind::Crl).collect();
    let fetched: Vec<(Severity, String)> = crls
        .iter()
        .filter_map(|u| match &u.outcome {
            Outcome::Fetched { next_update, .. } => Some(crl_verdict(*next_update, now, warn_hours)),
            _ => None,
        })
        .collect();
    let unreachable = crls.iter().filter(|u| matches!(u.outcome, Outcome::Unreachable(_))).count();
    let (mut severity, live) = if let Some((sev, words)) = fetched.iter().max_by_key(|(s, _)| s.rank()) {
        (*sev, format!("CRL {words}"))
    } else if unreachable > 0 {
        (Severity::Warning, format!("CRL unreachable ({unreachable} location{})", if unreachable == 1 { "" } else { "s" }))
    } else if !crls.is_empty() {
        (Severity::Info, "CRL is published over LDAP: checked by the chain build only".into())
    } else {
        (Severity::Info, "no revocation list named".into())
    };
    let chain_words = match chain {
        Some(status) => {
            let (sev, words) = chain_verdict(status);
            severity = worst(severity, sev);
            format!("chain check: {words}")
        }
        None => "chain check didn't run".into(),
    };
    let detail: Vec<String> = urls
        .iter()
        .map(|u| {
            let kind = match u.kind {
                UrlKind::Crl => "CRL",
                UrlKind::Ocsp => "OCSP",
                UrlKind::Issuer => "Issuer",
            };
            let what = match &u.outcome {
                Outcome::Fetched { this_update, next_update } => format!(
                    "fetched; issued {}, next update {}",
                    this_update.map(|t| format!("{} UTC", &epoch_to_rfc3339(t)[..16])).unwrap_or_else(|| "?".into()),
                    next_update.map(|t| format!("{} UTC", &epoch_to_rfc3339(t)[..16])).unwrap_or_else(|| "none set".into())
                ),
                Outcome::Unreachable(why) => format!("unreachable: {why}"),
                Outcome::ChainOnly => "LDAP, checked by the chain build only".into(),
                Outcome::Listed => "listed, not queried".into(),
            };
            format!("{kind} {}: {what}", u.url)
        })
        .collect();
    let mut detail = detail.join(" · ");
    if severity.rank() >= Severity::Warning.rank() {
        detail.push_str(if detail.is_empty() { "" } else { " · " });
        detail.push_str("An expired or unreachable revocation list makes anything that checks this certificate (the 802.1X RADIUS server, a VPN gateway) reject it, for every PC with a certificate from this CA.");
    }
    Finding::new(format!("Revocation: {subject}"), format!("{live} · {chain_words}"), severity).with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_794_496_800;

    fn crl(url: &str, next: Option<u64>) -> UrlCheck {
        UrlCheck { url: url.into(), kind: UrlKind::Crl, outcome: Outcome::Fetched { this_update: Some(NOW - 86_400), next_update: next } }
    }

    #[test]
    fn an_expired_list_is_critical_even_when_the_chain_passes_on_its_cache() {
        let f = finding("WS-07.corp.example.org", &[crl("http://pki.corp.example.org/CertEnroll/Corp-CA.crl", Some(NOW - 3 * 3_600))], Some(0), NOW, 24);
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.value.starts_with("CRL EXPIRED 3h ago") && f.value.ends_with("chain check: passed"), "{}", f.value);
        assert_eq!(f.label, "Revocation: WS-07.corp.example.org");
        assert!(f.detail.as_deref().unwrap().contains("RADIUS"));
    }

    #[test]
    fn grades_soon_current_unreachable_and_ldap() {
        assert_eq!(finding("pc", &[crl("http://a/x.crl", Some(NOW + 10 * 3_600))], Some(0), NOW, 24).severity, Severity::Warning);
        let ok = finding("pc", &[crl("http://a/x.crl", Some(NOW + 5 * 86_400))], Some(0), NOW, 24);
        assert_eq!(ok.severity, Severity::Ok);
        assert!(ok.value.starts_with("CRL current until "));
        let down = finding("pc", &[UrlCheck { url: "http://a/x.crl".into(), kind: UrlKind::Crl, outcome: Outcome::Unreachable("timed out".into()) }], Some(OFFLINE_REVOCATION), NOW, 24);
        assert_eq!((down.severity, down.value.as_str()), (Severity::Warning, "CRL unreachable (1 location) · chain check: revocation server offline"));
        let ldap = finding("pc", &[UrlCheck { url: "ldap:///CN=Corp-CA".into(), kind: UrlKind::Crl, outcome: Outcome::ChainOnly }], Some(0), NOW, 24);
        assert_eq!(ldap.severity, Severity::Info);
        assert!(finding("pc", &[], Some(IS_REVOKED), NOW, 24).value.ends_with("REVOKED"));
        assert_eq!(finding("pc", &[], Some(IS_REVOKED), NOW, 24).severity, Severity::Critical);
        let listed = finding("pc", &[UrlCheck { url: "http://ocsp.a/".into(), kind: UrlKind::Ocsp, outcome: Outcome::Listed }], None, NOW, 24);
        assert!(listed.detail.as_deref().unwrap().contains("OCSP http://ocsp.a/: listed, not queried"));
    }

    #[test]
    fn the_warning_window_comes_from_the_profile() {
        assert_eq!(crl_verdict(Some(NOW + 30 * 3_600), NOW, 24).0, Severity::Ok);
        assert_eq!(crl_verdict(Some(NOW + 30 * 3_600), NOW, 48).0, Severity::Warning);
    }
}
