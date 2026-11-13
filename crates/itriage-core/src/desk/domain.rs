//! Domain membership & Group Policy. Read-only.
//!
//! Answers the first questions a desk asks about a domain PC: is it joined,
//! did a domain controller sign this user in (or were cached credentials
//! used, which means no DC was reachable), which AD site is it in, and when
//! did computer policy last apply.
//!
//! On Linux: the realm realmd joined, whether SSSD sees its domain online,
//! the machine account (`adcli testjoin`) and keytab, and `sssd.conf`'s
//! permissions (SSSD won't start with the wrong ones). The SSSD service
//! itself is in Services, and clock skew in Clock & time sync.

use crate::model::{Category, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};

pub struct DomainPolicy;

impl TriageModule for DomainPolicy {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.domain",
            "Domain & Group Policy",
            Category::Workstation,
            if cfg!(windows) {
                "Domain membership, whether a domain controller or cached credentials signed you in, the AD site, and when Group Policy last applied."
            } else {
                "The realm this PC joined, whether SSSD sees the domain online, the machine account and keytab (as root), and sssd.conf's permissions."
            },
        )
    }

    #[cfg(windows)]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        imp::check()
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let facts = linux::gather();
        let rows = crate::parse::realm::findings(&facts);
        let attention = rows.iter().filter(|f| f.severity.rank() >= crate::model::Severity::Warning.rank()).count();
        let summary = match (facts.realms.first(), attention) {
            (None, 0) if facts.sssd_domains.is_empty() => "Not joined to a domain".to_string(),
            (Some(r), 0) => format!("Joined to {}", r.name),
            (_, 0) => "Domain join looks healthy".to_string(),
            (_, n) => format!("{n} domain finding{} need{} attention", crate::util::plural(n), if n == 1 { "s" } else { "" }),
        };
        Ok(Output::new(summary, rows))
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

#[cfg(not(windows))]
mod linux {
    use crate::parse::realm::{self, Facts};
    use crate::util::{capture_for, cmd, command_exists};
    use std::time::Duration;

    fn run(program: &str, args: &[&str], seconds: u64) -> Option<crate::util::CmdOutput> {
        if !command_exists(program) {
            return None;
        }
        let mut c = cmd(program);
        c.args(args).env("LC_ALL", "C");
        capture_for(c, Duration::from_secs(seconds)).ok()
    }

    pub fn gather() -> Facts {
        let mut f = Facts { root: crate::host::is_elevated(), ..Facts::default() };
        if let Some(out) = run("realm", &["list"], 10) {
            f.realms = realm::realm_list(&out.stdout);
        }
        if f.root {
            if let Some(out) = run("sssctl", &["domain-list"], 10).filter(|o| o.success()) {
                f.sssd_domains = out.stdout.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
            }
            // SSSD that won't start can't list its domains; its file can.
            if f.sssd_domains.is_empty() {
                f.sssd_domains = std::fs::read_to_string("/etc/sssd/sssd.conf").map(|t| realm::conf_domains(&t)).unwrap_or_default();
            }
        }
        let mut domains: Vec<String> = f.sssd_domains.clone();
        for r in &f.realms {
            let name = r.get("domain-name").unwrap_or(&r.name).to_string();
            if !domains.iter().any(|d| d.eq_ignore_ascii_case(&name)) {
                domains.push(name);
            }
        }
        for d in &domains {
            let status = if !f.root {
                Err("sssctl domain-status needs root".to_string())
            } else {
                match run("sssctl", &["domain-status", d], 15) {
                    None => Err("sssctl isn't installed".to_string()),
                    Some(o) if o.success() => Ok(realm::domain_status(&o.stdout)),
                    Some(o) => Err(o.combined().lines().next().unwrap_or("sssctl failed").to_string()),
                }
            };
            f.status.push((d.clone(), status));
        }
        if f.root && !domains.is_empty() {
            f.testjoin = run("adcli", &["testjoin", "-D", &domains[0]], 30).map(|o| if o.success() { Ok(o.combined()) } else { Err(o.combined()) });
            f.keytab = Some(if std::path::Path::new("/etc/krb5.keytab").exists() {
                match run("klist", &["-k", "-t", "-e", "/etc/krb5.keytab"], 10) {
                    Some(o) if o.success() => Ok(realm::keytab(&o.stdout)),
                    Some(o) => Err(o.combined()),
                    None => Err("klist isn't installed".into()),
                }
            } else {
                Err("/etc/krb5.keytab doesn't exist".into())
            });
        }
        // /etc/sssd is usually 0700, so this only works as root; a run as
        // the user says nothing about the file rather than guess.
        if let Ok(meta) = std::fs::metadata("/etc/sssd/sssd.conf") {
            use std::os::unix::fs::MetadataExt;
            f.conf = Some((meta.mode(), meta.uid()));
        }
        f
    }
}
