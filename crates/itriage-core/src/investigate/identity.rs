//! Device and SSO diagnostic status, and the Kerberos ticket cache. Never
//! tokens, ticket contents or private keys: names, times and encryption
//! types only.
use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
use std::collections::BTreeMap;

pub struct IdentityHealth;
impl TriageModule for IdentityHealth {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Device join and authentication, Windows Hello, signed-in-user PRT/WAM status, and the Kerberos tickets: TGT, RC4 tickets, the KDC, and servers that rejected a ticket. Reads no tokens."
        } else {
            "The signed-in user's Kerberos tickets: TGT, RC4 tickets and when they expire. Reads no tickets' contents."
        };
        ModuleInfo::new("desk.identity", "Entra, Kerberos & SSO sign-in", Category::Workstation, description)
    }
    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let mut findings = Vec::new();
        let mut summary = Vec::new();
        if cfg!(windows) {
            if !ctx.profile().network.public_probes {
                findings.push(Finding::info(
                    "Identity coverage",
                    "dsregcmd may contact Microsoft Entra. public_probes is disabled; local domain, account and Kerberos checks remain available.",
                ));
            } else {
                match platform() {
                    Ok(out) => {
                        summary.push(out.summary);
                        findings.extend(out.findings);
                    }
                    Err(e) => findings.push(Finding::info("Device identity", format!("couldn't be read: {e}"))),
                }
            }
        }
        let kerberos = kerberos();
        if let Some(tgt) = kerberos.iter().find(|f| f.label == "Kerberos TGT") {
            summary.push(format!("Kerberos TGT {}", tgt.value.split(" (").next().unwrap_or(&tgt.value)));
        }
        findings.extend(kerberos);
        Ok(Output::new(if summary.is_empty() { "Sign-in identity status".to_string() } else { summary.join(" · ") }, findings))
    }
}

/// Is ITriage running as the person signed in at this PC, unelevated?
/// Kerberos tickets (and the PRT) belong to a logon session, and an
/// elevated or different-user run has its own.
pub fn require_user_context() -> Result<(), String> {
    #[cfg(windows)]
    {
        if crate::host::is_elevated() {
            return Err("ITriage is running elevated, which is a separate sign-in session: it would act on that session's tickets, not the user's. Run ITriage without elevation as the signed-in user.".into());
        }
        let current = crate::win::session::current_account();
        let session = crate::win::session::current_session().and_then(crate::win::session::session_user);
        if let (Some(a), Some(b)) = (&current, &session) {
            if !a.eq_ignore_ascii_case(b) {
                return Err(format!("ITriage is running as {a}, not as {b}, who is signed in here."));
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return Err("ITriage is running as root: it would act on root's Kerberos tickets, not the user's.".into());
        }
        Ok(())
    }
}

/// The Kerberos rows: the ticket cache (only in the user's own context)
/// and, on Windows, servers that rejected a ticket in the last week.
fn kerberos() -> Vec<Finding> {
    use crate::parse::kerberos::{findings, rejections};
    let now = crate::util::now_epoch();
    let in_context = require_user_context();
    let purge = in_context.is_ok().then(|| crate::actions::offer("purge-kerberos-tickets", None));
    let mut out = match &in_context {
        Err(why) => vec![Finding::info("Kerberos tickets", "not listed in this elevated or different-user context").with_detail(format!(
            "{why} A missing ticket in an administrator's session says nothing about the user's."
        ))],
        Ok(()) => match tickets() {
            Ok(t) => findings(&t, now, purge.clone()),
            Err(e) => vec![Finding::info("Kerberos tickets", format!("couldn't be listed: {e}"))],
        },
    };
    out.extend(rejections(&modified_errors(), now, purge));
    out
}

#[cfg(windows)]
fn tickets() -> Result<Vec<crate::parse::kerberos::Ticket>, String> {
    crate::win::kerberos::tickets()
}

#[cfg(not(windows))]
fn tickets() -> Result<Vec<crate::parse::kerberos::Ticket>, String> {
    use crate::util::{capture_for, cmd, command_exists};
    if !command_exists("klist") {
        return Ok(Vec::new());
    }
    let mut c = cmd("klist");
    c.arg("-e").env("LC_ALL", "C");
    let out = capture_for(c, std::time::Duration::from_secs(10))?;
    // klist exits 1 with "No credentials cache found": that's no tickets.
    let offset = local_offset();
    Ok(crate::parse::kerberos::klist_mit(&out.stdout, &|local| (local as i64 - offset) as u64).1)
}

/// This machine's offset from UTC in seconds, now (klist prints local times).
#[cfg(not(windows))]
fn local_offset() -> i64 {
    let now = crate::util::now_epoch() as libc::time_t;
    // SAFETY: localtime_r fills a zeroed tm from a valid time_t.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff
    }
}

/// System event 4 (KRB_AP_ERR_MODIFIED) over the last week.
#[cfg(windows)]
fn modified_errors() -> Vec<(u64, String, String)> {
    const QUERY: &str = "*[System[Provider[@Name='Microsoft-Windows-Security-Kerberos'] and EventID=4 and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
    crate::win::eventlog::query_xml("System", QUERY, 100)
        .unwrap_or_default()
        .iter()
        .filter_map(|x| crate::parse::kerberos::modified_error(x))
        .collect()
}

#[cfg(not(windows))]
fn modified_errors() -> Vec<(u64, String, String)> {
    Vec::new()
}

pub fn parse(text: &str) -> BTreeMap<String, String> {
    // Only fields with diagnostic meaning are retained. dsregcmd also prints
    // URLs, device IDs and key-container IDs that aren't needed for grading.
    const FIELDS: &[&str] = &[
        "AzureAdJoined",
        "EnterpriseJoined",
        "DomainJoined",
        "WorkplaceJoined",
        "DeviceAuthStatus",
        "TpmProtected",
        "NgcSet",
        "WamDefaultSet",
        "AzureAdPrt",
        "AzureAdPrtUpdateTime",
        "AzureAdPrtExpiryTime",
        "AcquirePrtDiagnostics",
        "RefreshPrtDiagnostics",
        "Attempt Status",
        "HTTP Error",
        "HTTP status",
        "Server Error Code",
        "Server Error Description",
        "User Identity",
    ];
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.trim().split_once(" : ") {
            let key = key.trim();
            if FIELDS.contains(&key) {
                out.insert(key.into(), value.trim().chars().take(500).collect());
            }
        }
    }
    out
}

pub fn findings(values: &BTreeMap<String, String>, user_context: bool) -> Vec<Finding> {
    let get = |k: &str| values.get(k).map(String::as_str);
    let joined = get("AzureAdJoined") == Some("YES");
    let registered = get("WorkplaceJoined") == Some("YES");
    let mut out = vec![Finding::info(
        "Device join",
        match (joined, get("DomainJoined") == Some("YES")) {
            (true, true) => "Microsoft Entra hybrid joined",
            (true, false) => "Microsoft Entra joined",
            (false, true) => "Active Directory domain joined",
            _ if registered => "Microsoft Entra registered for this user",
            _ => "No Entra join reported; this may be a workgroup PC",
        },
    )];
    if joined {
        out.push(match get("DeviceAuthStatus") {
            Some("SUCCESS") => Finding::ok("Entra device authentication", "device is present and enabled"),
            Some(v) if v.contains("ERROR") => Finding::info("Entra device authentication", "test could not run").with_detail(v),
            Some(v) if v.starts_with("FAILED") => Finding::crit(
                "Entra device authentication",
                "device is disabled, deleted or could not authenticate",
            )
            .with_detail(v),
            Some(v) => Finding::info("Entra device authentication", v),
            None => Finding::info("Entra device authentication", "not reported; no tenant-side verdict is available"),
        });
    }
    if let Some(v) = get("TpmProtected") {
        out.push(Finding::info("Device key TPM protection", v));
    }
    if !user_context {
        out.push(Finding::info("User SSO checks", "not graded in this elevated or different-user context")
            .with_detail("Run ITriage without elevation as the affected signed-in user for PRT, WAM and Windows Hello status. A missing PRT in an administrator's context says nothing about that person's session."));
        return out;
    }
    if joined {
        out.push(match get("AzureAdPrt") {
            Some("YES") => Finding::ok("Primary Refresh Token status", "present for the running user"),
            Some("NO") => Finding::warn("Primary Refresh Token status", "not present for the running user")
                .with_detail("Microsoft 365 SSO may need sign-in or token renewal. The check does not read or change the token."),
            _ => Finding::info("Primary Refresh Token status", "not reported"),
        });
        for (key, label) in [
            ("AzureAdPrtUpdateTime", "PRT last updated"),
            ("AzureAdPrtExpiryTime", "PRT expires"),
        ] {
            if let Some(v) = get(key) {
                out.push(Finding::info(label, v));
            }
        }
    }
    for (key, label) in [
        ("NgcSet", "Windows Hello provisioned"),
        ("WamDefaultSet", "Web Account Manager default account"),
    ] {
        if let Some(v) = get(key) {
            out.push(Finding::info(label, v).with_detail("NO can be intentional under site policy; it is not automatically a failure."));
        }
    }
    let failure = get("AcquirePrtDiagnostics") == Some("PRESENT") || get("RefreshPrtDiagnostics") == Some("PRESENT");
    if failure {
        let detail = [
            "Attempt Status",
            "HTTP Error",
            "HTTP status",
            "Server Error Code",
            "Server Error Description",
            "User Identity",
        ]
        .iter()
        .filter_map(|k| get(k).map(|v| format!("{k}: {v}")))
        .collect::<Vec<_>>()
        .join(" · ");
        out.push(
            Finding::warn("Recent PRT diagnostic", "an acquisition or refresh failure was recorded").with_detail(format!(
                "{detail}. On shared PCs this may describe another user's attempt; compare its identity before drawing a conclusion."
            )),
        );
    }
    out
}

#[cfg(windows)]
fn platform() -> Result<Output, String> {
    use crate::util::{capture_for, cmd};
    let mut c = cmd("dsregcmd.exe");
    c.arg("/status");
    let out = capture_for(c, std::time::Duration::from_secs(20))?;
    if !out.success() {
        return Err(format!("dsregcmd /status failed ({})", crate::util::exit_label(out.code)));
    }
    let data = parse(&out.stdout);
    if !data.contains_key("AzureAdJoined") {
        return Err("dsregcmd gave no readable device state.".into());
    }
    let current = crate::win::session::current_account();
    let session = crate::win::session::current_session().and_then(crate::win::session::session_user);
    let same = current
        .as_deref()
        .zip(session.as_deref())
        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b));
    let rows = findings(&data, same && !crate::host::is_elevated());
    Ok(Output::new("Device identity and SSO diagnostic status", rows))
}
#[cfg(not(windows))]
fn platform() -> Result<Output, String> {
    Err("This check uses Windows device-registration diagnostics.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_technician_context_never_reports_the_users_token_as_missing() {
        let values = parse("AzureAdJoined : YES\nDomainJoined : YES\nDeviceAuthStatus : SUCCESS\nAzureAdPrt : NO\nDeviceId : secret-id\nKeyContainerId : private");
        assert!(!values.contains_key("DeviceId"));
        let admin = findings(&values, false);
        assert!(!admin.iter().any(|f| f.label == "Primary Refresh Token status"));
        assert!(findings(&values, true)
            .iter()
            .any(|f| f.label == "Primary Refresh Token status" && f.severity == crate::Severity::Warning));
    }
    #[test]
    fn unavailable_device_authentication_is_not_called_a_disabled_device() {
        let f = findings(&parse("AzureAdJoined : YES\nDeviceAuthStatus : FAILED. ERROR"), true);
        assert_eq!(f[1].severity, crate::Severity::Info);
        assert!(findings(&parse("AzureAdJoined : NO\nAzureAdPrt : NO"), true)
            .iter()
            .all(|f| f.severity.rank() < 2));
    }
}
