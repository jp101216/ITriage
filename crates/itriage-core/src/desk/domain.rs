//! Domain membership & Group Policy. Read-only, Windows only.
//!
//! Answers the first questions a desk asks about a domain PC: is it joined,
//! did a domain controller sign this user in (or were cached credentials
//! used, which means no DC was reachable), which AD site is it in, and when
//! did computer policy last apply.

use crate::model::{Category, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};

pub struct DomainPolicy;

impl TriageModule for DomainPolicy {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.domain",
            "Domain & Group Policy",
            Category::Workstation,
            "Domain membership, whether a domain controller or cached credentials signed you in, the AD site, and when Group Policy last applied.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        imp::check()
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("Domain and Group Policy checks are Windows-only.".into())
    }
}

/// How stale computer policy may get before it's flagged, in seconds.
#[cfg_attr(not(windows), allow(dead_code))]
const GP_WARN_AFTER: u64 = 24 * 3600;
#[cfg_attr(not(windows), allow(dead_code))]
const GP_CRIT_AFTER: u64 = 14 * 86_400;

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::actions::offer;
    use crate::model::{Finding, Severity};
    use crate::parse::time::{epoch_to_rfc3339, filetime_to_epoch};
    use crate::util::{ago, now_epoch};
    use crate::win::domain::{join_info, logon_server, Join};
    use crate::win::registry::{read_dword, read_string, HKLM};

    const GP_STATE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}";

    pub fn check() -> Result<Output, String> {
        let join = join_info().ok_or("Couldn't read domain membership (NetGetJoinInformation failed).")?;
        let domain = match join {
            Join::Domain(d) => d,
            Join::Workgroup(w) => {
                return Ok(Output::new(
                    format!("Not domain-joined (workgroup {w})"),
                    vec![Finding::info("Domain", format!("not joined · workgroup {w}"))],
                ))
            }
            Join::Unjoined => {
                return Ok(Output::new("Not domain-joined", vec![Finding::info("Domain", "not joined")]));
            }
        };
        let mut findings = vec![Finding::ok("Domain", domain.clone())];

        match logon_server() {
            Some(dc) => findings.push(Finding::ok("Signed in via", dc)),
            None => findings.push(
                Finding::warn("Signed in via", "cached credentials: no domain controller answered at sign-in")
                    .with_detail(
                        "Password changes, new group memberships and policy won't apply until the PC reaches a DC \
                         (wired network or VPN). Signing out and back in once connected fixes it.",
                    ),
            ),
        }

        if let Some(site) = read_string(HKLM, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "DynamicSiteName") {
            findings.push(Finding::info("AD site", site));
        }

        let mut gp_summary = "policy time unknown".to_string();
        match (read_dword(HKLM, GP_STATE, "endTimeHi"), read_dword(HKLM, GP_STATE, "endTimeLo")) {
            (Some(hi), Some(lo)) => {
                let ft = (u64::from(hi) << 32) | u64::from(lo);
                if let Some(at) = filetime_to_epoch(ft) {
                    let age = now_epoch().saturating_sub(at);
                    let status = read_dword(HKLM, GP_STATE, "Status").unwrap_or(0);
                    let severity = if age > GP_CRIT_AFTER {
                        Severity::Critical
                    } else if age > GP_WARN_AFTER || status != 0 {
                        Severity::Warning
                    } else {
                        Severity::Ok
                    };
                    let mut f = Finding::new(
                        "Group Policy (computer)",
                        format!("applied {} · {}", ago(age), epoch_to_rfc3339(at).replace('T', " ").replace('Z', " UTC")),
                        severity,
                    );
                    if status != 0 {
                        f = f.with_detail(format!(
                            "The last refresh reported an error: {}",
                            std::io::Error::from_raw_os_error(status as i32)
                        ));
                    }
                    if severity != Severity::Ok {
                        f = f.with_action(offer("gpupdate", None));
                    }
                    findings.push(f);
                    gp_summary = format!("policy applied {}", ago(age));
                }
            }
            _ => findings.push(
                Finding::info("Group Policy (computer)", "last refresh time isn't recorded")
                    .with_action(offer("gpupdate", None)),
            ),
        }

        Ok(Output::new(format!("Joined to {domain} · {gp_summary}"), findings))
    }
}
