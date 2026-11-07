//! Machine certificates. Read-only, Windows only.
//!
//! Certificates in LocalMachine\My, soonest expiry first. Machine certs carry
//! 802.1X Wi-Fi/wired authentication and VPN machine tunnels; when one
//! expires the device drops off the secure network, often without any
//! message a user would understand.

use crate::model::{Category, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};

pub struct MachineCerts;

impl TriageModule for MachineCerts {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.certs",
            "Machine certificates",
            Category::Workstation,
            "Computer certificates (used for 802.1X Wi-Fi and VPN) and when they expire. Warns 14 days out.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        imp::check()
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("The machine certificate store check is Windows-only.".into())
    }
}

/// Days left (negative once expired) to a severity and wording.
#[cfg_attr(not(windows), allow(dead_code))]
fn expiry(days: i64) -> (crate::model::Severity, String) {
    use crate::model::Severity;
    match days {
        d if d < 0 => (Severity::Critical, format!("expired {} day{} ago", -d, if d == -1 { "" } else { "s" })),
        0 => (Severity::Critical, "expires today".into()),
        1..=14 => (Severity::Warning, format!("expires in {days} day{}", if days == 1 { "" } else { "s" })),
        15..=30 => (Severity::Info, format!("expires in {days} days")),
        _ => (Severity::Ok, format!("valid for {days} more days")),
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::model::{Finding, Severity};
    use crate::parse::time::epoch_to_rfc3339;
    use crate::util::{now_epoch, plural};
    use crate::win::certs::machine_certs;

    pub fn check() -> Result<Output, String> {
        let mut certs = machine_certs()?;
        if certs.is_empty() {
            return Ok(Output::new(
                "No machine certificates",
                vec![Finding::info("Machine certificates", "none (no certificate-based network sign-in here)")],
            ));
        }
        certs.sort_by_key(|c| c.not_after.unwrap_or(u64::MAX));
        let now = now_epoch() as i64;
        let mut soon = 0;
        let mut findings = Vec::new();
        for c in &certs {
            let subject = if c.subject.is_empty() { "(no subject)".to_string() } else { c.subject.clone() };
            let (severity, text) = match c.not_after {
                Some(t) => {
                    let (sev, words) = expiry((t as i64 - now).div_euclid(86_400));
                    (sev, format!("{words} · {}", &epoch_to_rfc3339(t)[..10]))
                }
                None => (Severity::Info, "expiry unreadable".to_string()),
            };
            if severity.rank() >= Severity::Warning.rank() {
                soon += 1;
            }
            let detail = format!(
                "Issued by {}{}",
                if c.issuer.is_empty() { "unknown" } else { &c.issuer },
                if c.has_key { " · has a private key" } else { "" }
            );
            findings.push(Finding::new(subject, text, severity).with_detail(detail));
        }
        let summary = if soon == 0 {
            format!("{} machine certificate{}, none expiring soon", certs.len(), plural(certs.len()))
        } else {
            format!("{soon} machine certificate{} expired or expiring within 14 days", plural(soon))
        };
        Ok(Output::new(summary, findings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn grades_expiry() {
        assert_eq!(expiry(-3), (Severity::Critical, "expired 3 days ago".to_string()));
        assert_eq!(expiry(0).0, Severity::Critical);
        assert_eq!(expiry(1), (Severity::Warning, "expires in 1 day".to_string()));
        assert_eq!(expiry(21).0, Severity::Info);
        assert_eq!(expiry(200).0, Severity::Ok);
    }
}
