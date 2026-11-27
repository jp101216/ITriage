//! Intune enrollment, sync and app installs. Read-only, Windows only.
//!
//! "The app never arrived" and "the policy isn't here yet" both come down
//! to what the PC has heard from Intune. This reads what the PC itself
//! knows; whether Intune counts it compliant is decided by the service, and
//! isn't kept on the PC in a form Microsoft documents, so that stays in the
//! Intune admin center:
//! * enrollment: an MDM enrollment under `HKLM\SOFTWARE\Microsoft\Enrollments`
//!   whose ProviderID is `MS DM Server` (Intune's, as Microsoft's
//!   Enrollment Status Page article uses it). Windows keeps several
//!   built-in enrollments even on a PC that isn't managed (seen on a
//!   Windows Server 2025 runner: Deploy, Cloud and Local Authority), so
//!   those aren't counted;
//! * the last syncs: MDM sessions start with event 208 and end with 209
//!   ("OMA-DM session ended with status") in the
//!   DeviceManagement-Enterprise-Diagnostics-Provider/Sync log, per that
//!   publisher's manifest. Microsoft gives about every 8 hours as the
//!   normal sync interval;
//! * the Admin log's errors from the last 7 days;
//! * the Intune Management Extension service, which installs Win32 apps
//!   and runs scripts;
//! * Win32 app results it records under `...\IntuneManagementExtension\Win32Apps`
//!   (an EnforcementStateMessage per app). Microsoft doesn't document this
//!   layout; the state codes are the ones MSEndpointMgr's "Win32 app state
//!   messages demystified" lists, and the reader skips anything that
//!   doesn't match. Nothing records the apps' names, so each is shown by its
//!   Intune app ID.
//!
//! The one fix, Sync with Intune, starts an MDM session through Windows'
//! own `MdmSessionManager` API and restarts the Intune Management Extension,
//! which Microsoft documents as starting its check-in.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::{ago, plural};

pub struct IntuneHealth;

/// Intune's ProviderID on an MDM enrollment.
pub const INTUNE: &str = "MS DM Server";
/// The IME's service name (Microsoft's Intune Management Extension article).
pub const IME: &str = "IntuneManagementExtension";
pub const SYNC_CHANNEL: &str = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Sync";
pub const ADMIN_CHANNEL: &str = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin";

impl TriageModule for IntuneHealth {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.intune",
            "Intune enrollment & apps",
            Category::Workstation,
            "Whether this PC is enrolled in Intune, when it last synced and whether that worked, the week's MDM errors, the Intune Management Extension, and Win32 apps that failed to install, with a Sync with Intune fix.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let facts = imp::gather();
        let rows = findings(&facts, crate::util::now_epoch());
        Ok(Output::new(summarise(&rows), rows))
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("The Intune checks are Windows-only.".into())
    }
}

/// An MDM session that ended (event 209).
#[derive(Debug, Clone, PartialEq)]
pub struct SyncEnd {
    pub epoch: u64,
    pub ok: bool,
    /// How it ended, as Windows words it ("The operation completed
    /// successfully.") or the raw code.
    pub status: String,
}

/// One Win32 app's last result from the Intune Management Extension.
#[derive(Debug, Clone, PartialEq)]
pub struct AppResult {
    pub app: String,
    /// Assigned to the signed-in person (an Entra object ID), not the device.
    pub user: bool,
    pub state: u32,
    pub error: i64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Facts {
    /// Intune enrollments: the enrollment ID and its UPN, when recorded.
    pub intune: Vec<(String, Option<String>)>,
    /// Other MDM providers enrolled (not Intune, not Windows' own).
    pub other_mdm: Vec<String>,
    /// Ended sessions, any order.
    pub syncs: Vec<SyncEnd>,
    /// Whether the Sync log could be read at all.
    pub sync_log: bool,
    /// Admin-log errors, 7 days: event ID, time, message.
    pub errors: Vec<(u32, u64, Option<String>)>,
    /// The IME service: None when it isn't installed.
    pub ime_running: Option<bool>,
    pub apps: Vec<AppResult>,
}

/// Is a 209's status a success? It's an HRESULT, rendered as words in
/// the message.
pub fn status_ok(status: &str) -> bool {
    let s = status.trim();
    let number = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<i64>().ok(), |h| i64::from_str_radix(h, 16).ok());
    number == Some(0) || s.to_ascii_lowercase().contains("completed successfully")
}

/// "(The operation completed successfully.)" from a 209's message.
pub fn status_from_message(message: &str) -> Option<String> {
    let start = message.find("status: (")? + "status: (".len();
    let rest = &message[start..];
    let end = rest.rfind(')')?;
    Some(rest[..end].trim().to_string()).filter(|s| !s.is_empty())
}

/// The class of an EnforcementState.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Installed,
    InProgress,
    RequirementsNotMet,
    Failed,
    NotAttempted,
    Unknown,
}

pub fn outcome(state: u32) -> Outcome {
    match state {
        1000..=1999 => Outcome::Installed,
        2000..=2999 => Outcome::InProgress,
        3000 => Outcome::RequirementsNotMet,
        5000..=5999 => Outcome::Failed,
        6000..=6999 => Outcome::NotAttempted,
        _ => Outcome::Unknown,
    }
}

/// The failure states, in MSEndpointMgr's names, in words.
fn failure_text(state: u32) -> &'static str {
    match state {
        5003 => "the content didn't download",
        5006 => "a conflict prevented the install",
        5015 => "the managed installer AppLocker policy isn't applied",
        5999 => "failed, retrying immediately",
        _ => "the install failed",
    }
}

/// An app's error code: Intune's own (0x87D…), an HRESULT, or the
/// installer's exit code.
pub fn error_text(code: i64) -> String {
    let as_u32 = code as u32;
    let known = match as_u32 {
        // Microsoft's Intune app installation error reference.
        0x87D1_041C => Some("the install finished but Intune didn't detect the app afterwards (the detection rule doesn't match, or it was uninstalled)"),
        0x8000_FFFF => Some("an unexpected error during installation"),
        // Windows Installer, as an exit code and as an HRESULT.
        1603 | 0x8007_0643 => Some("the installer reported a fatal error (1603)"),
        // ERROR_INSTALL_ALREADY_RUNNING.
        1618 | 0x8007_0652 => Some("another installation was already in progress (1618)"),
        _ => None,
    };
    let number = if (0..=0xFFFF).contains(&code) { code.to_string() } else { format!("0x{as_u32:08X}") };
    match known {
        Some(k) => format!("{number}: {k}"),
        None => number,
    }
}

fn sync_action() -> crate::model::FixRef {
    crate::actions::offer("sync-intune", None)
}

pub fn findings(f: &Facts, now: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    if f.intune.is_empty() {
        out.push(match f.other_mdm.first() {
            Some(other) => Finding::info("Intune enrollment", format!("not enrolled in Intune · managed by {other}")),
            None => Finding::info("Intune enrollment", "not enrolled").with_detail("No MDM enrollment from Intune on this PC. If it should be managed, it needs enrolling (automatic enrollment via Entra join, or Settings → Accounts → Access work or school)."),
        });
        if let Some(running) = f.ime_running {
            out.push(Finding::info("Intune Management Extension", if running { "running, but this PC isn't enrolled" } else { "installed, stopped, and this PC isn't enrolled" }));
        }
        return out;
    }

    let upns: Vec<&str> = f.intune.iter().filter_map(|(_, u)| u.as_deref()).collect();
    out.push(Finding::ok("Intune enrollment", match upns.first() {
        Some(u) => format!("enrolled · {u}"),
        None => "enrolled".into(),
    }));
    if f.intune.len() > 1 {
        out.push(Finding::info("Intune enrollments", format!("{} on this PC", f.intune.len())).with_detail(
            "More than one Intune enrollment is recorded. Microsoft notes that stale entries under HKLM\\Software\\Microsoft\\Enrollments can be left behind and get in the way of enrolling again.",
        ));
    }

    // --- Sync.
    let newest = f.syncs.iter().max_by_key(|s| s.epoch);
    let last_ok = f.syncs.iter().filter(|s| s.ok).map(|s| s.epoch).max();
    let label = "Last Intune sync";
    if !f.sync_log {
        out.push(Finding::info(label, "the MDM Sync log couldn't be read").with_detail(format!("{SYNC_CHANNEL} wasn't readable from this account.")));
    } else {
        match (newest, last_ok) {
            (None, _) => out.push(
                Finding::warn(label, "none recorded")
                    .with_detail("No MDM session in the Sync log. It keeps a limited history, so on an enrolled PC this means it hasn't synced lately, or the log was cleared.")
                    .with_action(sync_action()),
            ),
            (Some(n), last_ok) => {
                let age = last_ok.map(|t| now.saturating_sub(t));
                let mut severity = match age {
                    Some(a) if a <= 86_400 => Severity::Ok,
                    Some(a) if a <= 7 * 86_400 => Severity::Warning,
                    _ => Severity::Critical,
                };
                let value = match last_ok {
                    Some(t) => format!("succeeded {}", ago(now.saturating_sub(t))),
                    None => "no successful sync in the log".into(),
                };
                let mut detail = String::from("Intune normally syncs about every 8 hours.");
                if !n.ok {
                    detail = format!("The last session, {}, ended with: {}. {detail}", ago(now.saturating_sub(n.epoch)), n.status);
                    if severity == Severity::Ok {
                        severity = Severity::Warning;
                    }
                }
                let row = Finding::new(label, value, severity).with_detail(detail);
                out.push(if severity == Severity::Ok { row } else { row.with_action(sync_action()) });
            }
        }
    }

    // --- The week's MDM errors.
    if let Some(newest) = f.errors.iter().max_by_key(|e| e.1) {
        let mut ids: Vec<(u32, usize)> = Vec::new();
        for (id, _, _) in &f.errors {
            match ids.iter_mut().find(|(i, _)| i == id) {
                Some((_, n)) => *n += 1,
                None => ids.push((*id, 1)),
            }
        }
        ids.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        out.push(
            Finding::info("MDM errors (7 days)", format!("{} · most often event {} ({}×)", f.errors.len(), ids[0].0, ids[0].1)).with_detail(format!(
                "From the DeviceManagement Admin log. Some appear on every managed PC; they matter when they name the policy or app that isn't applying. Newest, event {} {}: {}",
                newest.0,
                ago(now.saturating_sub(newest.1)),
                newest.2.as_deref().unwrap_or("(no message)")
            )),
        );
    }

    // --- The Intune Management Extension.
    out.push(match f.ime_running {
        None => Finding::info("Intune Management Extension", "not installed").with_detail("Intune installs it when a Win32 app, a script or a remediation is assigned to this PC or the person using it."),
        Some(false) => Finding::warn("Intune Management Extension", "stopped").with_detail("Win32 apps and scripts from Intune don't install or run while it's stopped.").with_action(crate::actions::offer("start-service", Some(IME))),
        Some(true) => Finding::ok("Intune Management Extension", "running"),
    });

    // --- Win32 apps.
    if !f.apps.is_empty() {
        let count = |o: Outcome| f.apps.iter().filter(|a| outcome(a.state) == o).count();
        let failed = count(Outcome::Failed);
        let mut parts = vec![format!("{} installed", count(Outcome::Installed)), format!("{failed} failed")];
        for (o, words) in [(Outcome::InProgress, "in progress"), (Outcome::RequirementsNotMet, "requirements not met"), (Outcome::NotAttempted, "not attempted")] {
            let n = count(o);
            if n > 0 {
                parts.push(format!("{n} {words}"));
            }
        }
        out.push(Finding::new("Intune Win32 apps", parts.join(" · "), if failed == 0 { Severity::Ok } else { Severity::Info }));
        for a in f.apps.iter().filter(|a| outcome(a.state) == Outcome::Failed) {
            out.push(
                Finding::warn(format!("Intune app failed: {}", a.app), format!("{} · error {}", failure_text(a.state), error_text(a.error)))
                    .with_detail(format!(
                        "Assigned to the {}. EnforcementState {}. Find the app by this ID in the Intune admin center; this PC's install log is AppWorkload.log in C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs. Sync with Intune retries it at the next check-in.",
                        if a.user { "signed-in person" } else { "device" },
                        a.state
                    ))
                    .with_action(sync_action()),
            );
        }
    }
    out
}

pub fn summarise(rows: &[Finding]) -> String {
    let get = |l: &str| rows.iter().find(|f| f.label == l);
    if get("Intune enrollment").is_some_and(|f| f.value.starts_with("not enrolled")) {
        return "Not enrolled in Intune".into();
    }
    let failed = rows.iter().filter(|f| f.label.starts_with("Intune app failed: ")).count();
    match get("Last Intune sync") {
        Some(s) if s.severity == Severity::Critical => format!("Intune sync: {}", s.value),
        Some(s) if s.severity == Severity::Warning && failed == 0 => format!("Intune sync: {}", s.value),
        _ if failed > 0 => format!("{failed} Intune app{} failed to install", plural(failed)),
        Some(s) => format!("Enrolled · sync {}", s.value),
        None => "Enrolled in Intune".into(),
    }
}

#[cfg(windows)]
pub use imp::sync_now;

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::evtxml::{parse_system, payload};
    use crate::parse::time::iso8601_utc_to_epoch;
    use crate::win::registry::{read_string, subkeys, HKLM};
    use std::time::Duration;

    const ENROLLMENTS: &str = r"SOFTWARE\Microsoft\Enrollments";
    const WIN32_APPS: &str = r"SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps";
    /// Windows' own enrollments, present on unmanaged PCs too.
    const BUILT_IN: &[&str] = &["Deploy Authority", "Cloud Authority", "Local Authority"];

    fn is_guid(s: &str) -> bool {
        crate::actions::valid_update_id(s.trim_matches(['{', '}']))
    }

    pub fn gather() -> Facts {
        let mut f = Facts::default();
        for id in subkeys(HKLM, ENROLLMENTS).into_iter().filter(|k| is_guid(k)) {
            let key = format!(r"{ENROLLMENTS}\{id}");
            let Some(provider) = read_string(HKLM, &key, "ProviderID") else { continue };
            if provider == INTUNE {
                f.intune.push((id, read_string(HKLM, &key, "UPN")));
            } else if !BUILT_IN.contains(&provider.as_str()) && !f.other_mdm.contains(&provider) {
                f.other_mdm.push(provider);
            }
        }
        f.ime_running = crate::win::scm::query(IME).ok().flatten().map(|s| s.running);
        if f.intune.is_empty() {
            return f;
        }
        const SYNC: &str = "*[System[EventID=209]]";
        match crate::win::eventlog::query_rendered(SYNC_CHANNEL, SYNC, 50) {
            Ok(events) => {
                f.sync_log = true;
                for e in events {
                    let Some(system) = parse_system(&e.xml) else { continue };
                    let Some(epoch) = system.time_created.as_deref().and_then(iso8601_utc_to_epoch) else { continue };
                    let raw = payload(&e.xml).into_iter().next().map(|(_, v)| v).unwrap_or_default();
                    let status = e.message.as_deref().and_then(status_from_message).unwrap_or(raw);
                    f.syncs.push(SyncEnd { epoch, ok: status_ok(&status), status });
                }
            }
            Err(_) => f.sync_log = false,
        }
        const ERRORS: &str = "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        for e in crate::win::eventlog::query_rendered(ADMIN_CHANNEL, ERRORS, 200).unwrap_or_default() {
            let Some(system) = parse_system(&e.xml) else { continue };
            let Some(epoch) = system.time_created.as_deref().and_then(iso8601_utc_to_epoch) else { continue };
            f.errors.push((system.event_id, epoch, e.message.map(|m| crate::parse::text::collapse_whitespace(&m))));
        }
        f.apps = apps();
        f
    }

    /// Each Win32 app's newest result: `Win32Apps\<target>\<app>_<revision>`,
    /// with the JSON in an EnforcementStateMessage value (in a subkey of
    /// that name, or on the app key itself).
    fn apps() -> Vec<AppResult> {
        let mut out: Vec<(AppResult, u32)> = Vec::new();
        for target in subkeys(HKLM, WIN32_APPS).into_iter().filter(|k| is_guid(k)) {
            let user = target != "00000000-0000-0000-0000-000000000000";
            for key in subkeys(HKLM, &format!(r"{WIN32_APPS}\{target}")) {
                let (app, revision) = match key.rsplit_once('_') {
                    Some((a, r)) if is_guid(a) => (a.to_string(), r.parse::<u32>().unwrap_or(0)),
                    _ => continue,
                };
                let base = format!(r"{WIN32_APPS}\{target}\{key}");
                let json = read_string(HKLM, &format!(r"{base}\EnforcementStateMessage"), "EnforcementStateMessage")
                    .or_else(|| read_string(HKLM, &base, "EnforcementStateMessage"));
                let Some(json) = json else { continue };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else { continue };
                let Some(state) = v.get("EnforcementState").and_then(|s| s.as_u64()) else { continue };
                let result = AppResult { app: app.clone(), user, state: state as u32, error: v.get("ErrorCode").and_then(|e| e.as_i64()).unwrap_or(0) };
                match out.iter_mut().find(|(r, _)| r.app == app && r.user == user) {
                    Some((r, rev)) if *rev < revision => {
                        *r = result;
                        *rev = revision;
                    }
                    Some(_) => {}
                    None => out.push((result, revision)),
                }
            }
        }
        out.into_iter().map(|(r, _)| r).collect()
    }

    /// Sync with Intune: an MDM session through Windows' MdmSessionManager,
    /// then a restart of the Intune Management Extension for its check-in.
    pub fn sync_now() -> Result<String, String> {
        crate::util::require_admin()?;
        let mut done = Vec::new();
        let mut failed = Vec::new();
        match mdm_session() {
            Ok(said) => done.push(said),
            Err(e) => failed.push(e),
        }
        match crate::win::scm::query(IME) {
            Ok(Some(_)) => {
                const WAIT: Duration = Duration::from_secs(30);
                match crate::win::scm::stop(IME, WAIT).and_then(|_| crate::win::scm::start(IME, WAIT)) {
                    Ok(()) => done.push("Restarted the Intune Management Extension, which checks in for Win32 apps and scripts as it starts.".to_string()),
                    Err(e) => failed.push(format!("The Intune Management Extension didn't restart: {e}")),
                }
            }
            Ok(None) => done.push("The Intune Management Extension isn't installed, so there was no app check-in to start.".to_string()),
            Err(e) => failed.push(format!("Couldn't check the Intune Management Extension: {e}")),
        }
        let all = done.iter().chain(failed.iter()).cloned().collect::<Vec<_>>().join(" ");
        if failed.is_empty() {
            Ok(all)
        } else {
            Err(all)
        }
    }

    fn mdm_session() -> Result<String, String> {
        // MdmSession isn't Send, so the whole session lives on one thread.
        let outcome = crate::util::within(Duration::from_secs(120), || {
            let _com = crate::win::com::ComGuard::init();
            let session = windows::Management::MdmSessionManager::TryCreateSession()
                .map_err(|e| format!("Windows couldn't create an MDM session (0x{:08X}); the PC may not be enrolled.", e.code().0 as u32))?;
            session.StartAsync().and_then(|a| a.join()).map_err(|e| format!("The MDM sync didn't run (0x{:08X}).", e.code().0 as u32))?;
            let error = session.ExtendedError().map(|h| h.0).unwrap_or(0);
            if error != 0 {
                return Err(format!("The MDM sync ended with error 0x{:08X}.", error as u32));
            }
            Ok("Synced with Intune (MDM session completed).".to_string())
        });
        outcome.unwrap_or_else(|| Ok("Started an Intune sync; it was still running after 2 minutes and carries on in the background.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_795_000_000;
    const HOUR: u64 = 3_600;

    fn enrolled() -> Facts {
        Facts { intune: vec![("2A4A1C35-6D5B-4C3A-9E7F-1B2C3D4E5F60".into(), Some("jparker@contoso.org".into()))], sync_log: true, ime_running: Some(true), ..Facts::default() }
    }

    fn sync(hours_ago: u64, ok: bool) -> SyncEnd {
        SyncEnd { epoch: NOW - hours_ago * HOUR, ok, status: if ok { "The operation completed successfully.".into() } else { "Unknown Win32 Error code: 0x80072f0c".into() } }
    }

    fn get<'a>(rows: &'a [Finding], label: &str) -> &'a Finding {
        rows.iter().find(|f| f.label == label).unwrap_or_else(|| panic!("{label}: {rows:#?}"))
    }

    #[test]
    fn reads_a_209_status() {
        let m = "MDM Session: OMA-DM session ended with status: (The operation completed successfully.).";
        assert_eq!(status_from_message(m).as_deref(), Some("The operation completed successfully."));
        assert!(status_ok("The operation completed successfully."));
        assert!(status_ok("0x0") && status_ok("0"));
        let bad = status_from_message("MDM Session: OMA-DM session ended with status: (Unknown Win32 Error code: 0x80072f0c).").unwrap();
        assert_eq!(bad, "Unknown Win32 Error code: 0x80072f0c");
        assert!(!status_ok(&bad) && !status_ok("0x80072F0C"));
    }

    #[test]
    fn not_enrolled_is_information_not_a_fault() {
        let rows = findings(&Facts::default(), NOW);
        assert_eq!((rows.len(), rows[0].severity, rows[0].value.as_str()), (1, Severity::Info, "not enrolled"));
        assert_eq!(summarise(&rows), "Not enrolled in Intune");
        let other = Facts { other_mdm: vec!["AirWatchMDM".into()], ime_running: Some(false), ..Facts::default() };
        let rows = findings(&other, NOW);
        assert_eq!(rows[0].value, "not enrolled in Intune · managed by AirWatchMDM");
        assert!(rows.iter().all(|f| f.action.is_none()), "nothing to fix on a PC Intune doesn't manage");
    }

    #[test]
    fn a_recent_sync_is_fine() {
        let mut f = enrolled();
        f.syncs = vec![sync(3, true), sync(11, true)];
        let rows = findings(&f, NOW);
        let s = get(&rows, "Last Intune sync");
        assert_eq!((s.severity, s.value.as_str()), (Severity::Ok, "succeeded 3h ago"));
        assert!(s.action.is_none());
        assert_eq!(get(&rows, "Intune enrollment").value, "enrolled · jparker@contoso.org");
        assert_eq!(summarise(&rows), "Enrolled · sync succeeded 3h ago");
    }

    #[test]
    fn a_failing_or_stale_sync_offers_the_fix() {
        let mut f = enrolled();
        f.syncs = vec![sync(1, false), sync(5, true)];
        let s = findings(&f, NOW).into_iter().find(|r| r.label == "Last Intune sync").unwrap();
        assert_eq!(s.severity, Severity::Warning, "a recent success, but the last one failed");
        assert!(s.detail.as_deref().unwrap().contains("0x80072f0c"));
        assert_eq!(s.action.as_ref().map(|a| a.id.as_str()), Some("sync-intune"));

        f.syncs = vec![sync(24 * 9, true)];
        let rows = findings(&f, NOW);
        assert_eq!(get(&rows, "Last Intune sync").severity, Severity::Critical);
        assert_eq!(summarise(&rows), "Intune sync: succeeded 9d ago");

        f.syncs.clear();
        let rows = findings(&f, NOW);
        let none = get(&rows, "Last Intune sync");
        assert_eq!((none.severity, none.value.as_str()), (Severity::Warning, "none recorded"));
    }

    #[test]
    fn failed_apps_are_named_by_id_with_their_error() {
        let mut f = enrolled();
        f.syncs = vec![sync(2, true)];
        f.apps = vec![
            AppResult { app: "e316127d-a9a4-4193-8f04-b07c37d1130f".into(), user: false, state: 5000, error: -2_016_345_060 },
            AppResult { app: "0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f".into(), user: true, state: 5000, error: 1603 },
            AppResult { app: "11111111-2222-3333-4444-555555555555".into(), user: false, state: 1000, error: 0 },
            AppResult { app: "66666666-7777-8888-9999-000000000000".into(), user: false, state: 3000, error: 0 },
        ];
        let rows = findings(&f, NOW);
        assert_eq!(get(&rows, "Intune Win32 apps").value, "1 installed · 2 failed · 1 requirements not met");
        let undetected = get(&rows, "Intune app failed: e316127d-a9a4-4193-8f04-b07c37d1130f");
        assert_eq!(undetected.severity, Severity::Warning);
        assert!(undetected.value.starts_with("the install failed · error 0x87D1041C: the install finished but Intune didn't detect"), "{}", undetected.value);
        assert!(undetected.detail.as_deref().unwrap().contains("Assigned to the device"));
        let msi = get(&rows, "Intune app failed: 0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f");
        assert_eq!(msi.value, "the install failed · error 1603: the installer reported a fatal error (1603)");
        assert!(msi.detail.as_deref().unwrap().contains("signed-in person"));
        assert_eq!(summarise(&rows), "2 Intune apps failed to install");
    }

    #[test]
    fn the_extension_and_the_weeks_errors() {
        let mut f = enrolled();
        f.syncs = vec![sync(2, true)];
        f.ime_running = Some(false);
        f.errors = vec![(404, NOW - HOUR, Some("MDM ConfigurationManager: Command failure status.".into())), (404, NOW - 2 * HOUR, None), (454, NOW - 3 * HOUR, None)];
        let rows = findings(&f, NOW);
        let ime = get(&rows, "Intune Management Extension");
        assert_eq!(ime.action.as_ref().and_then(|a| a.target.as_deref()), Some(IME));
        let errors = get(&rows, "MDM errors (7 days)");
        assert_eq!((errors.severity, errors.value.as_str()), (Severity::Info, "3 · most often event 404 (2×)"));
        assert!(errors.detail.as_deref().unwrap().contains("Newest, event 404 1h ago: MDM ConfigurationManager"));
        assert_eq!(outcome(2008), Outcome::InProgress);
        assert_eq!(outcome(6002), Outcome::NotAttempted);
        assert_eq!(error_text(1618), "1618: another installation was already in progress (1618)");
        assert_eq!(error_text(-2_147_024_891), "0x80070005");
    }
}
