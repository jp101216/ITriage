//! User profile and FSLogix health. Read-only, Windows only.
//!
//! "I signed in and everything's gone" is a temporary profile: Windows
//! couldn't load the person's own profile, set it aside as `<SID>.bak`, and
//! signed them in with one that's thrown away at sign-out. On shared
//! clinical PCs and virtual desktops the profile is usually an FSLogix
//! container (a VHDX on a file share), which adds its own ways to fail: not
//! attached, in use on another machine, the share unreachable, or full.
//!
//! What it reads, all local:
//! * the ProfileList key: the signed-in person's profile folder, and every
//!   profile set aside as `.bak`;
//! * the User Profiles Service events in the Application log (7 days):
//!   temporary profiles (1511), load failures (1500, 1502, 1508), and the
//!   program holding a profile's registry file (1545, 1552), which Windows
//!   names;
//! * FSLogix, when it's installed: its configuration, the frxsvc service,
//!   the signed-in person's session status (Status, Reason and ErrorCode
//!   under `HKLM\SOFTWARE\FSLogix\Profiles\Sessions\<SID>`, decoded with
//!   Microsoft's tables), the container's free space, and its own events.
//!
//! Event IDs, field names and messages were dumped from the publishers'
//! manifests on Windows Server 2025 with FSLogix 3.26.826 (November 2026);
//! the temporary-profile sequence (1508, 1509, 1545, 1502, 1515, 1511 and
//! the `.bak` key with State 0x8204) was reproduced there by locking a
//! test account's NTUSER.DAT while its profile loaded.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::profile::Band;
use crate::util::{ago, human_bytes, plural};

pub struct ProfileHealth;

impl TriageModule for ProfileHealth {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.profile",
            "User profile & FSLogix",
            Category::Workstation,
            "Whether the signed-in person got a temporary profile, profiles Windows set aside (.bak), the last 7 days of profile load failures and the program that held a profile's registry file, and FSLogix: the container's status for this sign-in, its free space and FSLogix's own errors.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let facts = imp::gather()?;
        let rows = findings(&facts, &ctx.profile().thresholds.disk_free_pct, crate::util::now_epoch());
        Ok(Output::new(summarise(&rows), rows))
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("Windows user profiles and FSLogix are Windows-only.".into())
    }
}

/// A profile in the ProfileList key.
#[derive(Debug, Clone, PartialEq)]
pub struct Listed {
    pub sid: String,
    pub path: String,
    /// The key is `<SID>.bak`: Windows set this profile aside.
    pub backup: bool,
}

/// An event from the Application log or an FSLogix channel, reduced to
/// what the rows need.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub epoch: u64,
    pub id: u32,
    /// The account it was logged for (`<Security UserID>`): the person for
    /// 1511/1515/1502, SYSTEM for 1508/1509/1545.
    pub sid: String,
    pub data: Vec<(String, String)>,
    pub message: Option<String>,
}

/// The signed-in person's FSLogix session, from `Sessions\<SID>`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Session {
    pub status: u32,
    pub reason: u32,
    pub error: u32,
    /// Windows' words for `error`, when it isn't 0.
    pub error_text: Option<String>,
    pub vhd: String,
    pub windows_temp: bool,
    /// The container's free and total bytes, when it's attached.
    pub space: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Fslogix {
    pub version: String,
    /// Profile Container's `Enabled`.
    pub enabled: bool,
    /// VHDLocations, or CCDLocations (Cloud Cache) with `cloud_cache`.
    pub locations: Vec<String>,
    pub cloud_cache: bool,
    /// frxsvc: None when it isn't there at all.
    pub service_running: Option<bool>,
    pub session: Option<Session>,
    /// Errors and warnings from FSLogix-Apps/Admin and /Operational, 7 days.
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Facts {
    pub account: String,
    pub sid: Option<String>,
    /// The signed-in person's profile folder, as ProfileList has it.
    pub path: Option<String>,
    pub listed: Vec<Listed>,
    /// User Profiles Service events, 7 days.
    pub events: Vec<Event>,
    pub fslogix: Option<Fslogix>,
}

/// The last part of a path: `C:\Users\jparker` → `jparker`.
fn leaf(path: &str) -> &str {
    path.trim_end_matches(['\\', '/']).rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Windows' temporary profile folder is `C:\Users\TEMP`, or `TEMP.<domain>`
/// with a number when one is already in use.
pub fn is_temp_folder(path: &str) -> bool {
    let name = leaf(path).to_ascii_uppercase();
    name == "TEMP" || name.starts_with("TEMP.")
}

fn field<'a>(e: &'a Event, name: &str) -> Option<&'a str> {
    e.data.iter().find(|(k, _)| k == name).map(|(_, v)| v.trim()).filter(|v| !v.is_empty())
}

/// Status codes, from Microsoft's FSLogix error codes reference.
pub fn status_text(code: u32) -> &'static str {
    match code {
        0 => "success",
        1 => "can't load the user's profile",
        2 => "the virtual disk API isn't available on this platform",
        3 => "can't retrieve the user's security identifier",
        4 => "error setting up the Office container",
        5 => "can't retrieve security information",
        6 => "can't retrieve the virtual disk location",
        7 => "can't create the destination folders",
        8 => "can't impersonate the user",
        9 => "can't create the virtual disk",
        10 => "can't release the virtual disk",
        11 => "can't open the virtual disk",
        12 => "can't attach the virtual disk",
        13 => "can't retrieve the virtual disk's physical information",
        14 => "can't open the virtual disk's volume",
        15 => "can't initialize the virtual disk",
        16 => "can't retrieve the virtual disk identifier",
        17 => "error formatting the virtual disk",
        18 => "can't retrieve the profile directory",
        19 => "can't set up the directory mount point",
        20 => "can't import registry information",
        21 => "can't retrieve the user's groups",
        22 => "error handling the profile",
        23 => "can't set up folder redirections",
        24 => "unable to create an event",
        25 => "maximum sessions reached",
        26 => "can't detach the virtual disk at the provided location",
        27 => "can't find the virtual disk at the provided location",
        28 => "no user session configuration found",
        100 => "waiting for Windows to set the profile folder",
        200 => "setup in progress",
        300 => "already attached (differencing disk)",
        _ => "an unknown status",
    }
}

/// Reason codes (they explain a normal status).
pub fn reason_text(code: u32) -> &'static str {
    match code {
        0 => "the container is attached",
        1 => "the account isn't in the include group",
        2 => "the account is in the exclude group",
        3 => "a local profile for this account already exists on this PC",
        4 => "not an appropriate account type",
        5 => "no reason recorded",
        6 => "the component isn't enabled",
        7 => "Windows gave this sign-in a temporary profile",
        8 => "not an Azure Virtual Desktop session",
        9 => "the profile failed to load",
        _ => "an unknown reason",
    }
}

fn session_row(s: &Session) -> Finding {
    const LABEL: &str = "FSLogix container for this sign-in";
    let codes = format!("Status {} · Reason {} · ErrorCode {}", s.status, s.reason, s.error);
    let error = s.error_text.as_deref().map(|t| format!(" Windows error {}: {t}", s.error)).unwrap_or_default();
    let normal = matches!(s.status, 0 | 100 | 200 | 300);
    if s.windows_temp || (normal && s.reason == 7) {
        return Finding::crit(LABEL, "not attached: Windows gave this sign-in a temporary profile")
            .with_detail(format!("{codes}. FSLogix doesn't attach a container to a temporary profile, so nothing this person changes is kept."));
    }
    if !normal {
        let detail = if s.status == 1 && s.reason == 5 && s.error == 0 {
            format!("{codes}. FSLogix recorded no reason or error for this sign-in; the day's log in C:\\ProgramData\\FSLogix\\Logs\\Profile has the steps it took.")
        } else {
            format!("{codes}.{error}")
        };
        let severity = if s.status == 1 && s.error == 0 { Severity::Warning } else { Severity::Critical };
        return Finding::new(LABEL, format!("not attached: {}", status_text(s.status)), severity).with_detail(detail);
    }
    match (s.status, s.reason) {
        (0, 0) => Finding::ok(LABEL, format!("attached{}", if s.vhd.is_empty() { String::new() } else { format!(" · {}", leaf(&s.vhd)) })).with_detail(if s.vhd.is_empty() { String::new() } else { s.vhd.clone() }),
        (_, 1) | (_, 2) | (_, 4) | (_, 8) => Finding::info(LABEL, format!("not used: {}", reason_text(s.reason))).with_detail(codes),
        (_, 3) => Finding::warn(LABEL, "not used: a local profile already exists for this account").with_detail(format!(
            "{codes}. FSLogix leaves an existing local profile alone, so this person is working in it, not in their container. Removing the local profile lets the container attach at the next sign-in (DeleteLocalProfileWhenVHDShouldApply makes FSLogix delete such profiles itself, permanently). Copy anything they need from it first."
        )),
        (_, 9) => Finding::crit(LABEL, "not attached: the profile failed to load").with_detail(format!("{codes}.{error}")),
        (100 | 200, _) => Finding::info(LABEL, status_text(s.status)).with_detail(codes),
        _ => Finding::info(LABEL, format!("{} · {}", status_text(s.status), reason_text(s.reason))).with_detail(codes),
    }
}

/// An FSLogix event ID, what it means for the person, and how bad it is.
fn fslogix_event(id: u32) -> Option<(&'static str, Severity)> {
    Some(match id {
        33 => ("container is nearly full and must be expanded", Severity::Critical),
        34 => ("container is low on free space", Severity::Warning),
        39 => ("container in use: another machine holds it, or the profile is in a bad state", Severity::Critical),
        51 => ("container in use on another machine", Severity::Warning),
        40 => ("no container location exists or is set", Severity::Critical),
        43 => ("container couldn't be found: a network problem", Severity::Critical),
        41 => ("sign-in failed while attaching the container", Severity::Critical),
        52 => ("the container couldn't be attached", Severity::Critical),
        28 => ("marked as a temporary profile", Severity::Critical),
        11 => ("frxsvc lost its connection to the FSLogix driver", Severity::Critical),
        42 => ("sign-out failed while detaching the container", Severity::Warning),
        44 => ("maximum concurrent sessions reached", Severity::Warning),
        45 | 49 | 50 => ("a container couldn't be detached", Severity::Warning),
        _ => return None,
    })
}

/// How many separate attempts a set of events stands for. Windows retries a
/// profile load many times within seconds, logging each retry (98 events
/// for one sign-in on a test runner), so events less than two minutes apart
/// count as one.
pub fn attempts(events: &[&Event]) -> usize {
    let mut at: Vec<u64> = events.iter().map(|e| e.epoch).collect();
    at.sort_unstable();
    at.dedup();
    if at.is_empty() {
        return 0;
    }
    1 + at.windows(2).filter(|w| w[1] - w[0] > 120).count()
}

fn times(n: usize) -> String {
    match n {
        1 => "once".into(),
        2 => "twice".into(),
        n => format!("{n} times"),
    }
}

pub fn findings(f: &Facts, band: &Band, now: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    let name_of = |sid: &str| -> String {
        f.listed.iter().find(|l| l.sid == sid).map(|l| leaf(&l.path).to_string()).unwrap_or_else(|| sid.to_string())
    };

    // --- The signed-in person's profile.
    let own_backup = f.sid.as_deref().and_then(|sid| f.listed.iter().find(|l| l.backup && l.sid == sid));
    match &f.path {
        Some(p) if is_temp_folder(p) => out.push(
            Finding::crit("Signed-in profile", format!("{} is on a temporary profile ({p})", f.account)).with_detail(
                "Windows couldn't load this person's own profile, so anything they save to the desktop or change in settings is deleted when they sign out. Find out why below (the events say what held the profile), fix that, then have them sign out and back in.",
            ),
        ),
        Some(p) => out.push(Finding::ok("Signed-in profile", format!("{} · {p}", f.account))),
        None => out.push(Finding::info("Signed-in profile", format!("{}: no profile folder listed", f.account))),
    }
    if let Some(b) = own_backup {
        out.push(Finding::crit("This person's profile was set aside", format!("{} · ProfileList {}.bak", b.path, b.sid)).with_detail(
            "Windows backed this profile up after it failed to load and says it will try the backup at their next sign-in. If they keep getting a temporary profile, the duplicate ProfileList entry is why.",
        ));
    }

    // --- Other profiles set aside.
    let others: Vec<&Listed> = f.listed.iter().filter(|l| l.backup && Some(l.sid.as_str()) != f.sid.as_deref()).collect();
    if !others.is_empty() {
        out.push(
            Finding::warn("Profiles set aside (.bak)", others.iter().map(|l| leaf(&l.path)).collect::<Vec<_>>().join(", "))
                .with_detail(format!(
                    "{} profile{} failed to load and {} kept under ProfileList as <SID>.bak. Each account gets a temporary profile until Windows can use its own again: {}.",
                    others.len(),
                    plural(others.len()),
                    if others.len() == 1 { "is" } else { "are" },
                    others.iter().map(|l| format!("{} ({}.bak)", leaf(&l.path), l.sid)).collect::<Vec<_>>().join("; ")
                )),
        );
    }

    // --- The week's User Profiles Service events.
    let group = |ids: &[u32]| -> Vec<&Event> {
        let mut v: Vec<&Event> = f.events.iter().filter(|e| ids.contains(&e.id)).collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.epoch));
        v
    };
    let temps = group(&[1511]);
    if let Some(last) = temps.first() {
        let mut who: Vec<String> = temps.iter().map(|e| name_of(&e.sid)).collect();
        who.dedup();
        out.push(
            Finding::warn("Temporary-profile sign-ins (7 days)", format!("{} · last {}", times(attempts(&temps)), ago(now.saturating_sub(last.epoch))))
                .with_detail(format!("Event 1511 for {}. Each of those sign-ins lost its changes at sign-out.", who.join(", "))),
        );
    }
    let failed = group(&[1500, 1502, 1508, 1542]);
    if let Some(last) = failed.first() {
        let why = field(last, "Error").map(|e| e.trim_end_matches('.').to_string());
        let file = failed.iter().find_map(|e| field(e, "File"));
        let mut detail = format!("Events 1500/1502/1508/1542, {} logged: Windows couldn't load a profile or its registry file.", failed.len());
        if let Some(w) = why {
            detail.push_str(&format!(" Last reason: {w}."));
        }
        if let Some(file) = file {
            detail.push_str(&format!(" File: {file}."));
        }
        out.push(Finding::warn("Profile load failures (7 days)", format!("{} · last {}", times(attempts(&failed)), ago(now.saturating_sub(last.epoch)))).with_detail(detail));
    }
    let locks = group(&[1545, 1552]);
    if let Some(last) = locks.first() {
        let mut programs: Vec<&str> = locks.iter().filter_map(|e| field(e, "InterferingImageName")).collect();
        programs.sort_unstable();
        programs.dedup();
        let names: Vec<&str> = programs.iter().map(|p| leaf(p)).collect();
        out.push(
            Finding::warn("Program holding a profile's registry file", if names.is_empty() { "unnamed".to_string() } else { names.join(", ") })
                .with_detail(format!(
                    "Events 1545/1552, {} in 7 days, last {}: Windows found {} open while loading a profile, and the profile couldn't load. Stop that program from opening users' NTUSER.DAT (an exclusion in it, or a fix from its vendor).",
                    times(attempts(&locks)),
                    ago(now.saturating_sub(last.epoch)),
                    if programs.is_empty() { "another program".to_string() } else { programs.join(", ") }
                )),
        );
    }
    let roaming = group(&[1521, 1543]);
    if let Some(last) = roaming.first() {
        out.push(
            Finding::warn("Roaming profile not synchronised (7 days)", format!("{} · last {}", times(roaming.len()), ago(now.saturating_sub(last.epoch))))
                .with_detail("Events 1521/1543: the server copy of a roaming profile couldn't be reached or the link was too slow, so the local copy was used and changes won't reach the server."),
        );
    }
    for (ids, label, what) in [
        (&[1530][..], "Registry file still in use at sign-out (7 days)", "Event 1530: a program still had a profile's registry open at sign-out; Windows unloads it anyway and says no action is needed."),
        (&[1504][..], "Roaming profile not fully updated (7 days)", "Event 1504: Windows couldn't update a roaming profile completely."),
        (&[1533][..], "Profile folders that couldn't be deleted (7 days)", "Event 1533: a profile folder couldn't be deleted because something had files in it open."),
    ] {
        let hits = group(ids);
        if let Some(last) = hits.first() {
            out.push(Finding::info(label, format!("{} · last {}", times(hits.len()), ago(now.saturating_sub(last.epoch)))).with_detail(what));
        }
    }
    if out.len() == 1 && out[0].severity == Severity::Ok {
        out.push(Finding::ok("Profile events (7 days)", "no temporary profiles or load failures"));
    }

    // --- FSLogix.
    if let Some(x) = &f.fslogix {
        if !x.enabled {
            out.push(Finding::info("FSLogix Profile Container", format!("{} installed · not enabled", x.version)).with_detail("FSLogix is installed but Profiles\\Enabled isn't 1, so profiles are ordinary local ones."));
        } else {
            let kind = if x.cloud_cache { "Cloud Cache" } else { "VHD locations" };
            out.push(Finding::info("FSLogix Profile Container", format!("{} · on · {kind}: {}", x.version, if x.locations.is_empty() { "none set".to_string() } else { x.locations.join("; ") })));
            if x.locations.is_empty() {
                out.push(Finding::crit("FSLogix container location", "none set").with_detail("Neither VHDLocations nor CCDLocations is set under HKLM\\SOFTWARE\\FSLogix\\Profiles, so FSLogix has nowhere to keep containers."));
            }
            match x.service_running {
                Some(false) => out.push(
                    Finding::crit("FSLogix service (frxsvc)", "not running").with_detail("Without it no container attaches at sign-in.").with_action(crate::actions::offer("start-service", Some("frxsvc"))),
                ),
                None => out.push(Finding::crit("FSLogix service (frxsvc)", "missing").with_detail("FSLogix is configured but its service isn't installed; reinstall FSLogix.")),
                Some(true) => {}
            }
            match &x.session {
                Some(s) => {
                    out.push(session_row(s));
                    if let Some((free, total)) = s.space.filter(|(_, t)| *t > 0) {
                        let pct = free as f64 / total as f64 * 100.0;
                        out.push(
                            Finding::new("FSLogix container space", format!("{} free of {} · {pct:.0}%", human_bytes(free), human_bytes(total)), band.low(pct))
                                .with_detail("Sign-in fails when the container fills up. Raising SizeInMBs extends existing containers at the person's next sign-in; otherwise clear space in the profile.")
                                .with_metric(pct, "%", false),
                        );
                    }
                }
                None => out.push(Finding::info("FSLogix container for this sign-in", "no session recorded for this account").with_detail("FSLogix keeps a Sessions entry for each account it has handled. None for this person means FSLogix didn't process their sign-in.")),
            }
        }
        // FSLogix's own events, the ones that matter for a sign-in.
        let mut seen: Vec<u32> = Vec::new();
        let mut events: Vec<&Event> = x.events.iter().collect();
        events.sort_by_key(|e| std::cmp::Reverse(e.epoch));
        for e in &events {
            let Some((what, severity)) = fslogix_event(e.id) else { continue };
            if seen.contains(&e.id) {
                continue;
            }
            seen.push(e.id);
            let n = events.iter().filter(|o| o.id == e.id).count();
            out.push(
                Finding::new(format!("FSLogix: {what}"), format!("{} in 7 days · last {}", times(n), ago(now.saturating_sub(e.epoch))), severity)
                    .with_detail(format!("FSLogix event {}{}", e.id, e.message.as_deref().map(|m| format!(": {m}")).unwrap_or_default())),
            );
        }
        let other: Vec<&&Event> = events.iter().filter(|e| fslogix_event(e.id).is_none()).collect();
        if let Some(last) = other.first() {
            out.push(Finding::info("FSLogix: other errors (7 days)", format!("{} · last {}", other.len(), ago(now.saturating_sub(last.epoch)))).with_detail(format!(
                "Newest: event {}{}",
                last.id,
                last.message.as_deref().map(|m| format!(": {m}")).unwrap_or_default()
            )));
        }
    }
    out
}

pub fn summarise(rows: &[Finding]) -> String {
    if let Some(f) = rows.iter().find(|f| f.label == "Signed-in profile" && f.severity == Severity::Critical) {
        return format!("Temporary profile: {}", f.value.split(" is on").next().unwrap_or("the signed-in person"));
    }
    if let Some(f) = rows.iter().find(|f| f.label == "FSLogix container for this sign-in" && f.severity.rank() >= Severity::Warning.rank()) {
        return format!("FSLogix container {}", f.value.split(':').next().unwrap_or("problem"));
    }
    match rows.iter().filter(|f| f.severity.rank() >= Severity::Warning.rank()).count() {
        0 => "Profile loads normally".into(),
        n => format!("{n} profile finding{} need{} attention", plural(n), if n == 1 { "s" } else { "" }),
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::evtxml::{parse_system, payload};
    use crate::parse::time::iso8601_utc_to_epoch;
    use crate::win::registry::{read_any, read_dword, read_string, subkeys, Data, HKLM};
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    const FSLOGIX: &str = r"SOFTWARE\FSLogix";

    pub fn gather() -> Result<Facts, String> {
        let person = crate::win::session::person();
        let account = match &person {
            Ok(p) => p.account.clone(),
            Err(_) => crate::win::session::console_user().or_else(crate::win::session::current_account).unwrap_or_else(|| "nobody".into()),
        };
        let sid = crate::win::session::sid_of(&account);
        let listed = list();
        let path = person
            .as_ref()
            .ok()
            .map(|p| p.profile.display().to_string())
            .or_else(|| sid.as_deref().and_then(|s| listed.iter().find(|l| l.sid == s && !l.backup)).map(|l| l.path.clone()));
        Ok(Facts { events: events(), fslogix: fslogix(sid.as_deref()), account, sid, path, listed })
    }

    /// Every user profile in ProfileList, `.bak` ones included. The
    /// service accounts (S-1-5-18/19/20) aren't people.
    fn list() -> Vec<Listed> {
        subkeys(HKLM, PROFILE_LIST)
            .into_iter()
            .filter(|k| k.starts_with("S-1-5-21-") || k.starts_with("S-1-12-1-"))
            .map(|k| {
                let backup = k.to_ascii_lowercase().ends_with(".bak");
                let sid = if backup { k[..k.len() - 4].to_string() } else { k.clone() };
                let path = read_string(HKLM, &format!(r"{PROFILE_LIST}\{k}"), "ProfileImagePath").unwrap_or_default();
                Listed { sid, path, backup }
            })
            .collect()
    }

    fn to_event(xml: &str, message: Option<String>) -> Option<Event> {
        let system = parse_system(xml)?;
        let epoch = iso8601_utc_to_epoch(system.time_created.as_deref()?)?;
        let sid = xml.split("<Security UserID='").nth(1).and_then(|r| r.split('\'').next()).unwrap_or_default().to_string();
        let mut data = payload(xml);
        data.iter_mut().for_each(|(_, v)| *v = crate::parse::text::collapse_whitespace(v));
        Some(Event { epoch, id: system.event_id, sid, data, message: message.map(|m| crate::parse::text::collapse_whitespace(&m)) })
    }

    fn events() -> Vec<Event> {
        const QUERY: &str = "*[System[Provider[@Name='Microsoft-Windows-User Profiles Service'] and (EventID=1500 or EventID=1502 or EventID=1504 or EventID=1508 or EventID=1511 or EventID=1521 or EventID=1530 or EventID=1533 or EventID=1542 or EventID=1543 or EventID=1545 or EventID=1552) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        crate::win::eventlog::query_xml("Application", QUERY, 400).unwrap_or_default().iter().filter_map(|x| to_event(x, None)).collect()
    }

    fn fslogix(sid: Option<&str>) -> Option<Fslogix> {
        let version = read_string(HKLM, &format!(r"{FSLOGIX}\Apps"), "InstallVersion")?;
        let profiles = format!(r"{FSLOGIX}\Profiles");
        let lines = |value: &str| match read_any(HKLM, &profiles, value) {
            Some(Data::Lines(l)) => l,
            Some(Data::Text(t)) => t.split(';').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
            _ => Vec::new(),
        };
        let ccd = lines("CCDLocations");
        let cloud_cache = !ccd.is_empty();
        let locations = if cloud_cache { ccd } else { lines("VHDLocations") };
        let service_running = crate::win::scm::query("frxsvc").ok().flatten().map(|s| s.running);
        let session = sid.and_then(|sid| {
            let key = format!(r"{profiles}\Sessions\{sid}");
            let status = read_dword(HKLM, &key, "Status")?;
            let error = read_dword(HKLM, &key, "ErrorCode").unwrap_or(0);
            let volume = read_string(HKLM, &key, "Volume").unwrap_or_default();
            Some(Session {
                status,
                reason: read_dword(HKLM, &key, "Reason").unwrap_or(5),
                error,
                error_text: (error != 0).then(|| {
                    let text = std::io::Error::from_raw_os_error(error as i32).to_string();
                    text.split(" (os error").next().unwrap_or(&text).trim().to_string()
                }),
                vhd: read_string(HKLM, &key, "VHDOpenedFilePath").unwrap_or_default(),
                windows_temp: read_dword(HKLM, &key, "WindowsTempProfile").unwrap_or(0) != 0,
                space: (status == 0 && !volume.is_empty()).then(|| space(&volume)).flatten(),
            })
        });
        const QUERY: &str = "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        let mut events = Vec::new();
        for channel in ["Microsoft-FSLogix-Apps/Admin", "Microsoft-FSLogix-Apps/Operational"] {
            for e in crate::win::eventlog::query_rendered(channel, QUERY, 200).unwrap_or_default() {
                events.extend(to_event(&e.xml, e.message));
            }
        }
        Some(Fslogix { version, enabled: read_dword(HKLM, &profiles, "Enabled") == Some(1), locations, cloud_cache, service_running, session, events })
    }

    /// Free and total bytes of the attached container. A volume GUID path
    /// needs its trailing backslash (without it the call fails).
    fn space(volume: &str) -> Option<(u64, u64)> {
        let mut path = volume.trim().to_string();
        if !path.ends_with('\\') {
            path.push('\\');
        }
        let (mut free, mut total) = (0u64, 0u64);
        // SAFETY: both out-pointers are valid for the call.
        unsafe { GetDiskFreeSpaceExW(&HSTRING::from(path), Some(&mut free), Some(&mut total), None) }.ok()?;
        Some((free, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_795_000_000;
    const SID: &str = "S-1-5-21-3414932011-3134797172-3625386099-1003";

    fn band() -> Band {
        Band { warn: 15.0, crit: 10.0 }
    }

    fn ev(id: u32, ago_s: u64, sid: &str, data: &[(&str, &str)]) -> Event {
        Event { epoch: NOW - ago_s, id, sid: sid.into(), data: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), message: None }
    }

    fn facts() -> Facts {
        Facts {
            account: "CORP\\jparker".into(),
            sid: Some(SID.into()),
            path: Some("C:\\Users\\jparker".into()),
            listed: vec![Listed { sid: SID.into(), path: "C:\\Users\\jparker".into(), backup: false }],
            events: Vec::new(),
            fslogix: None,
        }
    }

    fn get<'a>(rows: &'a [Finding], label: &str) -> &'a Finding {
        rows.iter().find(|f| f.label == label).unwrap_or_else(|| panic!("{label}: {rows:#?}"))
    }

    #[test]
    fn a_healthy_profile_is_quiet() {
        let rows = findings(&facts(), &band(), NOW);
        assert!(rows.iter().all(|f| f.severity == Severity::Ok), "{rows:#?}");
        assert_eq!(summarise(&rows), "Profile loads normally");
    }

    #[test]
    fn temp_folders_are_recognised() {
        for p in ["C:\\Users\\TEMP", "C:\\Users\\TEMP.CORP.000", "c:\\users\\temp\\"] {
            assert!(is_temp_folder(p), "{p}");
        }
        for p in ["C:\\Users\\temperance", "C:\\Users\\jparker", "C:\\Users\\TEMPS"] {
            assert!(!is_temp_folder(p), "{p}");
        }
    }

    /// The sequence reproduced on a Windows Server 2025 runner by holding a
    /// test account's NTUSER.DAT open while its profile loaded.
    #[test]
    fn the_reproduced_temporary_profile_reads_as_one() {
        let mut f = facts();
        f.path = Some("C:\\Users\\TEMP".into());
        f.listed = vec![Listed { sid: SID.into(), path: "C:\\Users\\jparker".into(), backup: true }];
        let file = [("Error", "The process cannot access the file because it is being used by another process."), ("File", "C:\\Users\\jparker\\ntuser.dat")];
        f.events = vec![
            ev(1508, 60, "S-1-5-18", &file),
            ev(1545, 59, "S-1-5-18", &[("InterferingImageName", "C:\\Program Files\\Vendor\\agent.exe"), ("InterferingPID", "6004"), ("ProfsvcPID", "2664")]),
            ev(1502, 59, SID, &[("Error", "The process cannot access the file because it is being used by another process.")]),
            ev(1515, 58, SID, &[]),
            ev(1511, 58, SID, &[]),
        ];
        let rows = findings(&f, &band(), NOW);
        let me = get(&rows, "Signed-in profile");
        assert_eq!((me.severity, me.value.as_str()), (Severity::Critical, "CORP\\jparker is on a temporary profile (C:\\Users\\TEMP)"));
        assert_eq!(get(&rows, "This person's profile was set aside").severity, Severity::Critical);
        let temps = get(&rows, "Temporary-profile sign-ins (7 days)");
        assert_eq!(temps.value, "once · last just now");
        assert!(temps.detail.as_deref().unwrap().contains("for jparker"), "the SID is named by its profile folder");
        let lock = get(&rows, "Program holding a profile's registry file");
        assert_eq!(lock.value, "agent.exe");
        assert!(lock.detail.as_deref().unwrap().contains("C:\\Program Files\\Vendor\\agent.exe"));
        let failed = get(&rows, "Profile load failures (7 days)");
        assert_eq!(failed.value, "once · last just now", "the 1508 and 1502 of one sign-in are one attempt");
        assert!(failed.detail.as_deref().unwrap().contains("2 logged"));
        assert!(failed.detail.as_deref().unwrap().contains("used by another process. File: C:\\Users\\jparker\\ntuser.dat"), "{:?}", failed.detail);
        assert_eq!(summarise(&rows), "Temporary profile: CORP\\jparker");
    }

    #[test]
    fn retries_count_as_one_attempt() {
        let e = |at: u64| ev(1502, at, SID, &[]);
        let burst: Vec<Event> = (0..98).map(|i| e(10_000 - i / 4)).chain([e(4_000), e(3_990)]).collect();
        let refs: Vec<&Event> = burst.iter().collect();
        assert_eq!(attempts(&refs), 2);
        assert_eq!(attempts(&[]), 0);
    }

    #[test]
    fn other_accounts_set_aside_and_benign_events() {
        let mut f = facts();
        f.listed.push(Listed { sid: "S-1-5-21-1-2-3-1104".into(), path: "C:\\Users\\nurse2".into(), backup: true });
        f.events = vec![ev(1530, 3_600, "S-1-5-18", &[]), ev(1530, 7_200, "S-1-5-18", &[])];
        let rows = findings(&f, &band(), NOW);
        let bak = get(&rows, "Profiles set aside (.bak)");
        assert_eq!((bak.severity, bak.value.as_str()), (Severity::Warning, "nurse2"));
        assert!(bak.detail.as_deref().unwrap().contains("S-1-5-21-1-2-3-1104.bak"));
        assert_eq!(get(&rows, "Registry file still in use at sign-out (7 days)").severity, Severity::Info);
        assert_eq!(get(&rows, "Signed-in profile").severity, Severity::Ok);
    }

    fn with_fslogix(session: Option<Session>) -> Facts {
        let mut f = facts();
        f.fslogix = Some(Fslogix {
            version: "3.26.826.17182".into(),
            enabled: true,
            locations: vec!["\\\\files01\\profiles$".into()],
            cloud_cache: false,
            service_running: Some(true),
            session,
            events: Vec::new(),
        });
        f
    }

    #[test]
    fn an_attached_container_and_its_space() {
        let s = Session { vhd: "\\\\files01\\profiles$\\jparker_S-1-5-21\\Profile_jparker.VHDX".into(), space: Some((1_000_000_000, 30_000_000_000)), ..Session::default() };
        let rows = findings(&with_fslogix(Some(s)), &band(), NOW);
        let c = get(&rows, "FSLogix container for this sign-in");
        assert_eq!((c.severity, c.value.as_str()), (Severity::Ok, "attached · Profile_jparker.VHDX"));
        let space = get(&rows, "FSLogix container space");
        assert_eq!(space.severity, Severity::Critical, "3% free");
        assert_eq!(space.metric.as_ref().map(|m| m.higher_is_worse), Some(false));
        assert_eq!(get(&rows, "FSLogix Profile Container").value, "3.26.826.17182 · on · VHD locations: \\\\files01\\profiles$");
    }

    #[test]
    fn container_statuses_are_decoded() {
        let row = |s: Session| session_row(&s);
        let local = row(Session { reason: 3, ..Session::default() });
        assert_eq!((local.severity, local.value.as_str()), (Severity::Warning, "not used: a local profile already exists for this account"));
        let excluded = row(Session { reason: 2, ..Session::default() });
        assert_eq!(excluded.severity, Severity::Info);
        let attach = row(Session { status: 12, reason: 5, error: 5, error_text: Some("Access is denied.".into()), ..Session::default() });
        assert_eq!((attach.severity, attach.value.as_str()), (Severity::Critical, "not attached: can't attach the virtual disk"));
        assert!(attach.detail.as_deref().unwrap().contains("Windows error 5: Access is denied."));
        let temp = row(Session { windows_temp: true, ..Session::default() });
        assert_eq!(temp.severity, Severity::Critical);
        // What a profile load without a real sign-in leaves on a runner.
        let quiet = row(Session { status: 1, reason: 5, error: 0, ..Session::default() });
        assert_eq!((quiet.severity, quiet.value.as_str()), (Severity::Warning, "not attached: can't load the user's profile"));
        assert!(quiet.detail.as_deref().unwrap().contains("FSLogix\\Logs\\Profile"));
    }

    #[test]
    fn fslogix_service_location_and_events() {
        let mut f = with_fslogix(None);
        let x = f.fslogix.as_mut().unwrap();
        x.service_running = Some(false);
        x.locations.clear();
        x.events = vec![
            Event { message: Some("The user vhd(x) (VHDPath: \\\\files01\\p\\a.VHDX) has less than 2048 MB free space left and must be expanded".into()), ..ev(33, 600, "S-1-5-18", &[]) },
            ev(33, 7_200, "S-1-5-18", &[]),
            Event { message: Some("Failed to get computer's group SIDs".into()), ..ev(26, 900, "S-1-5-18", &[]) },
        ];
        let rows = findings(&f, &band(), NOW);
        let svc = get(&rows, "FSLogix service (frxsvc)");
        assert_eq!(svc.action.as_ref().map(|a| (a.id.as_str(), a.target.as_deref())), Some(("start-service", Some("frxsvc"))));
        assert_eq!(get(&rows, "FSLogix container location").severity, Severity::Critical);
        assert_eq!(get(&rows, "FSLogix container for this sign-in").severity, Severity::Info);
        let full = get(&rows, "FSLogix: container is nearly full and must be expanded");
        assert_eq!((full.severity, full.value.as_str()), (Severity::Critical, "twice in 7 days · last 10m ago"));
        assert!(full.detail.as_deref().unwrap().starts_with("FSLogix event 33: The user vhd(x)"));
        assert_eq!(get(&rows, "FSLogix: other errors (7 days)").severity, Severity::Info, "event 26 shows up on any install");
    }
}
