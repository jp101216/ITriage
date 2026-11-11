//! Change evidence and temporal correlation. Nearby changes are candidates,
//! never automatically labelled the cause of the user's problem.
use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
use crate::parse::evtxml::EvtSystem;
use crate::parse::time::{epoch_to_rfc3339, iso8601_utc_to_epoch};
use serde::{Deserialize, Serialize};

/// Rows kept in a report. Bursts are folded into one row first (see
/// `group_bursts`), so this is rarely reached.
const MAX_ROWS: usize = 200;
/// Events of one kind closer together than this are one burst…
const BURST_GAP_SECS: u64 = 120;
/// …when there are at least this many of them…
const BURST_MIN: usize = 4;
/// …and a burst is cut off after this long, so its start still says when.
const BURST_MAX_SECS: u64 = 1800;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeEvent {
    /// UTC, to the second: `2026-11-10T12:00:00Z`.
    pub at: String,
    pub source: String,
    pub kind: String,
    pub description: String,
    pub detail: String,
    /// For a burst folded into one row: when its last event happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

pub struct ChangeTimeline;
impl TriageModule for ChangeTimeline {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "system.changes",
            "Recent changes timeline",
            Category::System,
            "Recent update, installer, driver, service, policy and restart evidence. Correlates timing without claiming causation.",
        )
    }
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let (mut events, gaps) = collect();
        events.sort_by(|a, b| b.at.cmp(&a.at));
        let found = events.len();
        let mut events = group_bursts(events);
        let rows_before = events.len();
        events.truncate(MAX_ROWS);
        let mut rows = events.iter().map(finding).collect::<Vec<_>>();
        if rows_before > MAX_ROWS {
            rows.push(Finding::info(
                "Timeline coverage",
                format!("The {MAX_ROWS} most recent rows are shown; {} older ones were left out.", rows_before - MAX_ROWS),
            ));
        }
        rows.extend(gaps.into_iter().map(|g| Finding::info("Timeline coverage", g)));
        rows.push(Finding::info("Interpretation", "A nearby change is a possible temporal link. Confirm the failure's onset and the affected component before deciding it caused the problem."));
        Ok(Output::new(format!("{found} change event(s) in the last 7 days"), rows))
    }
}

fn finding(e: &ChangeEvent) -> Finding {
    let detail = if e.detail.is_empty() { e.source.clone() } else { format!("{} · {}", e.source, e.detail) };
    Finding::info(format!("{} · {}", e.at, e.kind), &e.description).with_detail(detail)
}

/// An event's time to the second. Windows writes seven decimal places;
/// rows, sorting and the onset search all want one form.
fn whole_seconds(at: &str) -> Option<String> {
    at.trim().ends_with('Z').then(|| iso8601_utc_to_epoch(at)).flatten().map(epoch_to_rfc3339)
}

fn clip(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(max.saturating_sub(1)).collect::<String>().trim_end())
    }
}

/// What a row is filed under. Unknown providers (the Setup log has several)
/// are a system event, not a restart.
pub fn kind_of(provider: &str, event_id: u32) -> &'static str {
    let p = provider.to_ascii_lowercase();
    if p.contains("windowsupdate") || p.contains("servicing") || p.contains("wusa") {
        "Windows update"
    } else if p.contains("msiinstaller") {
        "Application installer"
    } else if p.contains("userpnp") || p.contains("kernel-pnp") {
        "Driver or device"
    } else if p.contains("grouppolicy") {
        "Group Policy"
    } else if p.contains("service control") {
        "Service configuration"
    } else if p.contains("kernel-power") || (p == "eventlog" && event_id == 6008) {
        "Unexpected shutdown"
    } else if p == "user32" || p.contains("kernel-general") {
        "Restart"
    } else {
        "System event"
    }
}

/// Events that say nothing about a change: BITS switches itself between
/// automatic and manual start many times a day.
fn noise(system: &EvtSystem, data: &[(String, String)]) -> bool {
    let value = |name: &str| data.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    system.provider == "Service Control Manager" && system.event_id == 7040 && value("param4") == Some("BITS")
}

/// A sentence for the events worth recognising. `None` leaves it to the
/// message Windows has for the event.
fn known(system: &EvtSystem, data: &[(String, String)]) -> Option<String> {
    let value = |name: &str| data.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let provider = system.provider.to_ascii_lowercase();
    let id = system.event_id;
    let text = if provider.contains("windowsupdateclient") {
        let title = value("updateTitle").or(value("updateList"))?;
        match id {
            19 => format!("Installed: {title}"),
            20 => format!("Failed to install: {title}{}", value("errorCode").map(|c| format!(" (error {c})")).unwrap_or_default()),
            21 | 22 => format!("Restart needed to finish: {title}"),
            _ => return None,
        }
    } else if provider == "msiinstaller" {
        // Product, version, language, status, manufacturer: by position.
        let product = value("1")?;
        let version = value("2").map(|v| format!(" {v}")).unwrap_or_default();
        let failed = value("4").filter(|s| *s != "0").map(|s| format!(": failed (status {s})")).unwrap_or_default();
        match id {
            1033 => format!("Installed {product}{version}{failed}"),
            1034 => format!("Removed {product}{version}{failed}"),
            1036 => format!("Updated {product}{version}{failed}"),
            1038 => format!("{product} needs a restart to finish"),
            _ => return None,
        }
    } else if provider == "service control manager" {
        match id {
            7045 => format!(
                "Service installed: {}{}",
                value("ServiceName")?,
                value("StartType").map(|s| format!(" ({s})")).unwrap_or_default()
            ),
            7040 => format!("Service {}: start type changed from {} to {}", value("param1")?, value("param2")?, value("param3")?),
            _ => return None,
        }
    } else if provider == "user32" && id == 1074 {
        // Process, computer, reason, reason code, type, comment, user.
        let process = value("1").map(|p| p.rsplit(['\\', '/']).next().unwrap_or(p).split(" (").next().unwrap_or(p).to_string())?;
        let what = value("5").unwrap_or("restart");
        let mut what = what.to_string();
        if let Some(first) = what.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        format!(
            "{what} started by {process}{}{}",
            value("7").map(|u| format!(" for {u}")).unwrap_or_default(),
            value("3").map(|r| format!(": {r}")).unwrap_or_default()
        )
    } else if provider.contains("kernel-general") && id == 12 {
        "Windows started".to_string()
    } else if provider == "eventlog" && id == 6008 {
        "The shutdown before this start was unexpected".to_string()
    } else if provider.contains("kernel-power") && id == 41 {
        "The PC restarted without shutting down cleanly".to_string()
    } else if provider.contains("servicing") {
        let state = value("IntendedPackageStateTextized")?;
        let error = value("ErrorCode").filter(|e| !matches!(*e, "0x0" | "0")).map(|e| format!(" (error {e})")).unwrap_or_default();
        format!("Package {}: {state}{error}", value("PackageIdentifier")?)
    } else if provider.contains("userpnp") && id == 20001 {
        let name = value("DriverDescription").or(value("DriverName"))?;
        let version = value("DriverVersion").map(|v| format!(" {v}")).unwrap_or_default();
        let failed = value("InstallStatus").filter(|s| !matches!(*s, "0x0" | "0")).map(|s| format!(": failed (status {s})")).unwrap_or_default();
        format!("Driver installed: {name}{version}{failed}")
    } else if provider.contains("grouppolicy") && matches!(id, 8000 | 8001) {
        let whose = if id == 8000 { "Computer" } else { "User" };
        let error = value("ErrorCode").filter(|e| *e != "0").map(|e| format!(" (error {e})")).unwrap_or_default();
        format!("{whose} policy applied at {} in {} s{error}", if id == 8000 { "startup" } else { "sign-in" }, value("PolicyElaspedTimeInSeconds")?)
    } else {
        return None;
    };
    Some(text)
}

/// One event log record as a timeline row. `message` is the event as
/// Windows words it, when its provider has message text installed.
pub fn from_event(channel: &str, xml: &str, message: Option<&str>) -> Option<ChangeEvent> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    let data = crate::parse::evtxml::payload(xml);
    if noise(&system, &data) {
        return None;
    }
    let at = whole_seconds(system.time_created.as_deref()?)?;
    // Windows puts invisible direction marks around the dates in a message.
    let message = message.map(|m| m.replace(['\u{200e}', '\u{200f}'], ""));
    let first_line = message.as_deref().and_then(|m| m.lines().map(str::trim).find(|l| !l.is_empty()));
    let failed = system.level > 0 && system.level <= 2;
    let description = match (known(&system, &data), first_line) {
        (Some(text), _) => text,
        (None, Some(line)) => clip(line, 300),
        (None, None) => {
            let values = data.iter().take(3).map(|(_, v)| clip(v, 80)).collect::<Vec<_>>().join(" · ");
            format!("{} event {}{}", system.provider, system.event_id, if values.is_empty() { String::new() } else { format!(": {values}") })
        }
    };
    let fields = data
        .iter()
        .take(10)
        .map(|(k, v)| format!("{k}: {}", clip(&v.split_whitespace().collect::<Vec<_>>().join(" "), 250)))
        .collect::<Vec<_>>()
        .join(" · ");
    Some(ChangeEvent {
        at,
        source: channel.into(),
        kind: kind_of(&system.provider, system.event_id).into(),
        description: if failed && !description.to_ascii_lowercase().contains("fail") { format!("{description} (error)") } else { description },
        detail: format!(
            "{} event {}{}",
            system.provider,
            system.event_id,
            if fields.is_empty() { String::new() } else { format!(" · {fields}") }
        ),
        until: None,
    })
}

/// Fold a run of one kind of event into a single row: a cumulative update
/// or one `apt install` writes hundreds of lines, and they would push
/// everything else out of the report. `events` is newest first, and so is
/// the result. A folded row starts when its burst started, and says how
/// many events it stands for, when the last one was, and what the first
/// few were.
pub fn group_bursts(events: Vec<ChangeEvent>) -> Vec<ChangeEvent> {
    let epoch = |e: &ChangeEvent| iso8601_utc_to_epoch(&e.at).unwrap_or(0);
    let mut out = Vec::new();
    let mut run: Vec<ChangeEvent> = Vec::new();
    let flush = |run: &mut Vec<ChangeEvent>, out: &mut Vec<ChangeEvent>| {
        if run.len() < BURST_MIN {
            out.append(run);
            return;
        }
        // Newest first: the burst began with the last one in the run.
        let (latest, earliest) = (run[0].clone(), run[run.len() - 1].clone());
        let mut examples: Vec<String> = Vec::new();
        for e in run.iter().rev() {
            let text = clip(&e.description, 70);
            if !examples.contains(&text) {
                examples.push(text);
            }
            if examples.len() == 3 {
                break;
            }
        }
        let more = run.len().saturating_sub(examples.len());
        out.push(ChangeEvent {
            at: earliest.at.clone(),
            source: earliest.source.clone(),
            kind: earliest.kind.clone(),
            description: format!(
                "{} events until {}: {}{}",
                run.len(),
                latest.at,
                examples.join("; "),
                if more > 0 { format!("; and {more} more") } else { String::new() }
            ),
            detail: "Events of one kind close together, shown as one row.".into(),
            until: Some(latest.at),
        });
        run.clear();
    };
    for event in events {
        let joins = run.last().is_some_and(|previous| {
            previous.kind == event.kind
                && previous.source == event.source
                && epoch(previous).abs_diff(epoch(&event)) <= BURST_GAP_SECS
                && epoch(&run[0]).abs_diff(epoch(&event)) <= BURST_MAX_SECS
        });
        if !joins {
            flush(&mut run, &mut out);
        }
        run.push(event);
    }
    flush(&mut run, &mut out);
    out
}

/// Structured rows from a saved run, including network connection history,
/// oldest first.
pub fn rows(report: &crate::Report) -> Vec<ChangeEvent> {
    let mut out = Vec::new();
    for module in report
        .results
        .iter()
        .filter(|r| matches!(r.module_id.as_str(), "system.changes" | "net.wifi-auth") && !r.preview && r.error.is_none())
    {
        for f in &module.findings {
            // "<time> · <kind>", or a time alone. 0.8.0 wrote Windows times
            // with their decimals; both read the same here.
            let (time, kind) = f.label.split_once(" · ").unwrap_or((f.label.as_str(), ""));
            let Some(at) = whole_seconds(time) else {
                continue;
            };
            let until = f
                .value
                .split_once(" events until ")
                .filter(|(count, _)| !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|(_, rest)| whole_seconds(rest.split(':').take(3).collect::<Vec<_>>().join(":").as_str()));
            out.push(ChangeEvent {
                at,
                source: module.title.clone(),
                kind: if kind.trim().is_empty() { "Recorded event".into() } else { kind.trim().into() },
                description: f.value.clone(),
                detail: f.detail.clone().unwrap_or_default(),
                until,
            });
        }
    }
    out.sort_by(|a, b| a.at.cmp(&b.at));
    out
}

/// The rows within `window_seconds` either side of `problem_at`. A folded
/// burst counts when any part of it falls inside.
pub fn near(report: &crate::Report, problem_at: u64, window_seconds: u64) -> Vec<ChangeEvent> {
    let window = window_seconds.clamp(60, 86_400);
    let (from, to) = (problem_at.saturating_sub(window), problem_at.saturating_add(window));
    rows(report)
        .into_iter()
        .filter(|e| {
            let Some(start) = iso8601_utc_to_epoch(&e.at) else {
                return false;
            };
            let end = e.until.as_deref().and_then(iso8601_utc_to_epoch).unwrap_or(start).max(start);
            start <= to && end >= from
        })
        .collect()
}

pub fn problem_time(text: &str) -> Result<u64, String> {
    let s = text.trim();
    let invalid = || "Use a valid ISO 8601 UTC problem time ending in Z.".to_string();
    let body = s.strip_suffix('Z').ok_or_else(invalid)?;
    let suffix = body.get(19..).ok_or_else(invalid)?;
    if body.as_bytes().get(10) != Some(&b'T')
        || (!suffix.is_empty() && !(suffix.starts_with('.') && suffix.len() > 1 && suffix[1..].bytes().all(|b| b.is_ascii_digit())))
    {
        return Err(invalid());
    }
    let epoch = iso8601_utc_to_epoch(s).ok_or_else(invalid)?;
    if epoch_to_utc_prefix(epoch) != body[..19] {
        return Err(invalid());
    }
    Ok(epoch)
}
fn epoch_to_utc_prefix(epoch: u64) -> String {
    epoch_to_rfc3339(epoch).chars().take(19).collect()
}

#[cfg(windows)]
fn collect() -> (Vec<ChangeEvent>, Vec<String>) {
    // One query for each kind of change, so a week of one (device events
    // after docking, say) can't push the others out of what is read. Every
    // query is the last seven days, newest first.
    const SOURCES: &[(&str, &str, usize)] = &[
        (
            "System",
            "*[System[Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (EventID=19 or EventID=20 or EventID=21 or EventID=22) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            48,
        ),
        (
            "System",
            "*[System[((Provider[@Name='User32'] and EventID=1074) or (Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12) or (Provider[@Name='EventLog'] and EventID=6008) or (Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41)) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            32,
        ),
        (
            "System",
            "*[System[Provider[@Name='Service Control Manager'] and (EventID=7040 or EventID=7045) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            64,
        ),
        (
            "System",
            "*[System[((Provider[@Name='Microsoft-Windows-UserPnp'] and (EventID=20001 or EventID=20003)) or (Provider[@Name='Microsoft-Windows-Kernel-PnP'] and EventID=219)) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            48,
        ),
        (
            "Application",
            "*[System[Provider[@Name='MsiInstaller'] and (EventID=1033 or EventID=1034 or EventID=1036 or EventID=1038 or Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            64,
        ),
        ("Setup", "*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]", 48),
        (
            "Microsoft-Windows-GroupPolicy/Operational",
            "*[System[(EventID=8000 or EventID=8001 or Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            32,
        ),
    ];
    let mut events = Vec::new();
    let mut gaps: Vec<String> = Vec::new();
    for (channel, query, most) in SOURCES {
        match crate::win::eventlog::query_rendered(channel, query, *most) {
            Ok(rows) => events.extend(rows.iter().filter_map(|r| from_event(channel, &r.xml, r.message.as_deref()))),
            Err(e) if !gaps.contains(&e) => gaps.push(e),
            Err(_) => {}
        }
    }
    gaps.push("The last seven days, and the most recent 32 to 64 events of each kind; log retention and permissions can leave gaps. Group Policy rows are startup and sign-in processing and errors, not every background refresh. An installer event is evidence of activity, not proof an upgrade succeeded.".into());
    (events, gaps)
}

#[cfg(not(windows))]
fn collect() -> (Vec<ChangeEvent>, Vec<String>) {
    use std::io::{Read, Seek, SeekFrom};
    let mut events = Vec::new();
    let mut gaps = Vec::new();
    let week_ago = crate::util::now_epoch().saturating_sub(604_800);
    match std::fs::File::open("/var/log/dpkg.log") {
        Ok(mut file) => {
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            let start = size.saturating_sub(2 * 1024 * 1024);
            let _ = file.seek(SeekFrom::Start(start));
            let mut bytes = Vec::new();
            let _ = file.take(2 * 1024 * 1024).read_to_end(&mut bytes);
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines().skip(usize::from(start > 0)) {
                if let Some(e) = dpkg_line(line) {
                    if iso8601_utc_to_epoch(&e.at).is_some_and(|s| s >= week_ago) {
                        events.push(e);
                    }
                }
            }
            gaps.push("dpkg: last 2 MiB of the current log only; rotated logs are not included. Local timestamps are converted using this machine's time zone.".into());
        }
        Err(_) => gaps.push("dpkg log is unavailable; package history may be incomplete.".into()),
    }
    if crate::util::command_exists("journalctl") {
        let mut c = crate::util::cmd("journalctl");
        c.args([
            "--since",
            "7 days ago",
            "--no-pager",
            "-o",
            "json",
            "-n",
            "100",
            "-u",
            "apt-daily-upgrade.service",
            "-u",
            "dnf-automatic.service",
            "-u",
            "packagekit.service",
        ])
        .env("LC_ALL", "C");
        if let Ok(out) = crate::util::capture_for(c, std::time::Duration::from_secs(5)) {
            for line in out.stdout.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let Some(t) = v["__REALTIME_TIMESTAMP"].as_str().and_then(|s| s.parse::<u64>().ok()) else {
                    continue;
                };
                events.push(ChangeEvent {
                    at: epoch_to_rfc3339(t / 1_000_000),
                    source: "system journal".into(),
                    kind: "Package manager activity".into(),
                    description: clip(v["MESSAGE"].as_str().unwrap_or_default(), 600),
                    detail: v["_SYSTEMD_UNIT"].as_str().unwrap_or_default().into(),
                    until: None,
                });
            }
        } else {
            gaps.push("Package-manager journal could not be read.".into());
        }
    }
    // The start that is still running. Earlier ones aren't looked for.
    let uptime = sysinfo::System::uptime();
    if uptime > 0 && uptime <= 604_800 {
        events.push(ChangeEvent {
            at: epoch_to_rfc3339(crate::util::now_epoch().saturating_sub(uptime)),
            source: "uptime".into(),
            kind: "Restart".into(),
            description: "The system started".into(),
            detail: "Worked out from how long the system has been up. Earlier restarts aren't listed.".into(),
            until: None,
        });
    }
    (events, gaps)
}

#[cfg(unix)]
fn dpkg_line(line: &str) -> Option<ChangeEvent> {
    let mut p = line.split_whitespace();
    let (date, clock, action) = (p.next()?, p.next()?, p.next()?);
    if !matches!(action, "install" | "upgrade" | "remove" | "purge") {
        return None;
    }
    let raw = format!("{date}T{clock}Z");
    let epoch = iso8601_utc_to_epoch(&raw)?;
    let (year, month, day) = crate::parse::time::civil_from_days((epoch / 86400) as i64);
    // SAFETY: initialized libc tm, mktime only normalizes its own fields.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year as i32 - 1900;
    tm.tm_mon = month as i32 - 1;
    tm.tm_mday = day as i32;
    tm.tm_hour = ((epoch % 86400) / 3600) as i32;
    tm.tm_min = ((epoch % 3600) / 60) as i32;
    tm.tm_sec = (epoch % 60) as i32;
    tm.tm_isdst = -1;
    let time = u64::try_from(unsafe { libc::mktime(&mut tm) }).ok()?;
    // "curl:amd64 8.0 8.1": the package, the version it had, the one it has.
    let (package, old, new) = (p.next()?, p.next().unwrap_or("<none>"), p.next().unwrap_or("<none>"));
    let name = package.split(':').next().unwrap_or(package);
    let had = |v: &str| v != "<none>";
    let description = match action {
        "install" => format!("Installed {name}{}", if had(new) { format!(" {new}") } else { String::new() }),
        "upgrade" if had(old) && had(new) => format!("Upgraded {name} {old} → {new}"),
        "upgrade" => format!("Upgraded {name}"),
        _ => format!("Removed {name}{}", if had(old) { format!(" {old}") } else { String::new() }),
    };
    Some(ChangeEvent {
        at: epoch_to_rfc3339(time),
        source: "dpkg.log".into(),
        kind: "Package change".into(),
        description,
        detail: format!("{action} {package}. Package-manager record; timing alone does not establish causation."),
        until: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_of(findings: Vec<Finding>) -> crate::Report {
        let mut m = crate::ModuleResult::failed(&crate::ModuleInfo::new("system.changes", "Changes", crate::Category::System, ""), "");
        m.error = None;
        m.findings = findings;
        crate::Report::new(crate::host_context(), None, vec![m], false)
    }

    fn event(at: &str, kind: &str, description: &str) -> ChangeEvent {
        ChangeEvent {
            at: at.into(),
            source: "System".into(),
            kind: kind.into(),
            description: description.into(),
            detail: String::new(),
            until: None,
        }
    }

    #[test]
    fn onset_requires_a_real_utc_time_and_nearby_events_are_bounded() {
        for s in [
            "2026-02-31T12:00:00Z",
            "2026-11-10T12:00:00+02:00",
            "2026-11-10T12:00:00garbageZ",
            "2026-11-10T12:00:00",
        ] {
            assert!(problem_time(s).is_err(), "{s}");
        }
        assert_eq!(problem_time("2026-11-10T12:00:00.125Z"), problem_time("2026-11-10T12:00:00Z"));
        let r = report_of(vec![
            Finding::info("2026-11-10T12:01:00Z · Driver", "nearby"),
            Finding::info("2026-11-10T09:00:00Z · Driver", "outside"),
        ]);
        let rows = near(&r, problem_time("2026-11-10T12:00:00Z").unwrap(), 120);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].description, "nearby");
    }

    #[test]
    fn rows_keep_their_kind_whatever_the_time_looks_like() {
        let r = report_of(vec![
            // As 0.8.0 wrote a Windows event: seven decimal places.
            Finding::info("2026-11-11T01:14:49.1809176Z · Windows update", "from Windows"),
            Finding::info("2026-11-10T12:00:00Z · Package change", "from dpkg"),
            Finding::info("2026-11-10T11:00:00Z", "a time alone"),
            Finding::info("Timeline coverage", "not an event"),
        ]);
        let rows = rows(&r);
        assert_eq!(rows.len(), 3);
        assert_eq!((rows[0].at.as_str(), rows[0].kind.as_str()), ("2026-11-10T11:00:00Z", "Recorded event"));
        assert_eq!((rows[1].at.as_str(), rows[1].kind.as_str()), ("2026-11-10T12:00:00Z", "Package change"));
        assert_eq!((rows[2].at.as_str(), rows[2].kind.as_str()), ("2026-11-11T01:14:49Z", "Windows update"));
    }

    #[test]
    fn installer_activity_is_not_assumed_success_or_causation() {
        let named = from_event("Application", "<Event><System><Provider Name='MsiInstaller'/><EventID>11708</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-10T12:00:00.5000000Z'/></System><EventData><Data>Product: App -- Installation operation failed.</Data></EventData></Event>", None).unwrap();
        assert_eq!(named.kind, "Application installer");
        assert_eq!(named.at, "2026-11-10T12:00:00Z");
        assert!(named.description.contains("failed") && !named.description.contains("(error)"), "{}", named.description);
        assert!(named.detail.contains("App"));
        // Classic installer records have no value names: product, version, language, status.
        let failed = from_event("Application", "<Event><System><Provider Name='MsiInstaller'/><EventID Qualifiers='0'>1033</EventID><Level>4</Level><TimeCreated SystemTime='2026-11-10T12:00:00Z'/></System><EventData><Data>Contoso Client</Data><Data>24.2.0.187</Data><Data>1033</Data><Data>1603</Data><Data>Contoso Ltd</Data><Data>(NULL)</Data></EventData></Event>", None).unwrap();
        assert_eq!(failed.description, "Installed Contoso Client 24.2.0.187: failed (status 1603)");
        let ok = from_event("Application", "<Event><System><Provider Name='MsiInstaller'/><EventID>1034</EventID><Level>4</Level><TimeCreated SystemTime='2026-11-10T12:00:00Z'/></System><EventData><Data>Contoso Client</Data><Data>24.2.0.187</Data><Data>1033</Data><Data>0</Data></EventData></Event>", None).unwrap();
        assert_eq!(ok.description, "Removed Contoso Client 24.2.0.187");
    }

    #[test]
    fn events_read_as_sentences_and_noise_is_left_out() {
        let event = |provider: &str, id: u32, data: &str| {
            format!("<Event><System><Provider Name='{provider}'/><EventID>{id}</EventID><Level>4</Level><TimeCreated SystemTime='2026-11-11T01:14:49.1809176Z'/></System>{data}</Event>")
        };
        let update = from_event("System", &event("Microsoft-Windows-WindowsUpdateClient", 19, "<EventData><Data Name='updateTitle'>2026-11 Cumulative Update (KB5031356)</Data><Data Name='updateGuid'>{ef19}</Data></EventData>"), Some("Installation Successful: Windows successfully installed the following update: 2026-11 Cumulative Update (KB5031356)")).unwrap();
        assert_eq!((update.kind.as_str(), update.description.as_str()), ("Windows update", "Installed: 2026-11 Cumulative Update (KB5031356)"));
        let service = from_event("System", &event("Service Control Manager", 7040, "<EventData><Data Name='param1'>Print Spooler</Data><Data Name='param2'>auto start</Data><Data Name='param3'>disabled</Data><Data Name='param4'>Spooler</Data></EventData>"), None).unwrap();
        assert_eq!(service.description, "Service Print Spooler: start type changed from auto start to disabled");
        // BITS flips its own start type all day.
        assert!(from_event("System", &event("Service Control Manager", 7040, "<EventData><Data Name='param1'>Background Intelligent Transfer Service</Data><Data Name='param2'>auto start</Data><Data Name='param3'>demand start</Data><Data Name='param4'>BITS</Data></EventData>"), None).is_none());
        let restart = from_event("System", &event("User32", 1074, "<EventData><Data>C:\\WINDOWS\\system32\\winlogon.exe (WS-07)</Data><Data>WS-07</Data><Data>Operating System: Upgrade (Planned)</Data><Data>0x80020003</Data><Data>restart</Data><Data/><Data>NT AUTHORITY\\SYSTEM</Data></EventData>"), None).unwrap();
        assert_eq!(restart.kind, "Restart");
        assert_eq!(restart.description, "Restart started by winlogon.exe for NT AUTHORITY\\SYSTEM: Operating System: Upgrade (Planned)");
        let package = from_event("Setup", &event("Microsoft-Windows-Servicing", 2, "<UserData><CbsPackageChangeState xmlns='x'><PackageIdentifier>KB5031356</PackageIdentifier><IntendedPackageStateTextized>Installed</IntendedPackageStateTextized><ErrorCode>0x0</ErrorCode></CbsPackageChangeState></UserData>"), None).unwrap();
        assert_eq!((package.kind.as_str(), package.description.as_str()), ("Windows update", "Package KB5031356: Installed"));
        assert_eq!(from_event("System", &event("Microsoft-Windows-Kernel-General", 12, ""), Some("The operating system started at system time \u{200e}2026\u{200e}-\u{200e}11\u{200e}-\u{200e}11T01:13:43.500000000Z.")).unwrap().description, "Windows started");
        // An event nobody taught it: Windows' own words, without the direction marks, and never "Restart".
        let other = from_event("Setup", &event("Microsoft-Windows-WUSA", 3, ""), Some("\r\nWindows update \u{200e}KB5031356\u{200e} could not be installed.\r\nMore text")).unwrap();
        assert_eq!((other.kind.as_str(), other.description.as_str()), ("Windows update", "Windows update KB5031356 could not be installed."));
        assert_eq!(kind_of("Some-Other-Provider", 1), "System event");
        // And with no message text installed for it: what the event carries.
        let bare = from_event("Setup", &event("Contoso-Setup", 7, "<EventData><Data Name='Step'>Finalize</Data></EventData>"), None).unwrap();
        assert_eq!(bare.description, "Contoso-Setup event 7: Finalize");
    }

    #[test]
    fn a_burst_becomes_one_row_that_still_answers_the_onset_search() {
        let mut events: Vec<ChangeEvent> = (0..40).map(|i| event(&epoch_to_rfc3339(1_794_300_000 + i * 3), "Package change", &format!("Installed lib{i} 1.0"))).collect();
        events.push(event(&epoch_to_rfc3339(1_794_300_000 - 7_200), "Restart", "The system started"));
        events.push(event(&epoch_to_rfc3339(1_794_300_000 + 4_000), "Package change", "Upgraded curl 8.0 → 8.1"));
        events.sort_by(|a, b| b.at.cmp(&a.at));
        let grouped = group_bursts(events);
        assert_eq!(grouped.len(), 3, "{grouped:#?}");
        let burst = &grouped[1];
        assert_eq!(burst.at, epoch_to_rfc3339(1_794_300_000), "a burst is filed at its start");
        assert_eq!(burst.until.as_deref(), Some(epoch_to_rfc3339(1_794_300_000 + 117).as_str()));
        assert!(burst.description.starts_with("40 events until "), "{}", burst.description);
        assert!(burst.description.contains("Installed lib0 1.0; Installed lib1 1.0; Installed lib2 1.0; and 37 more"), "{}", burst.description);
        // Through a report and back, the burst still covers its whole span.
        let r = report_of(grouped.iter().map(finding).collect());
        let back = rows(&r);
        assert_eq!(back[1].until, burst.until);
        let late = near(&r, 1_794_300_000 + 117 + 90, 120);
        assert_eq!(late.len(), 1, "the end of the burst is inside the window even though its start isn't");
        assert!(near(&r, 1_794_300_000 + 2_000, 120).is_empty());
        // Three of a kind aren't a burst, and different kinds never fold together.
        let few = group_bursts(vec![event("2026-11-10T12:00:02Z", "A", "x"), event("2026-11-10T12:00:01Z", "A", "y"), event("2026-11-10T12:00:00Z", "B", "z")]);
        assert_eq!(few.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn package_history_has_versions_and_ignores_status_noise() {
        let e = dpkg_line("2026-11-10 12:00:00 upgrade curl:amd64 8.0 8.1").unwrap();
        assert_eq!(e.description, "Upgraded curl 8.0 → 8.1");
        assert!(e.detail.starts_with("upgrade curl:amd64"));
        assert_eq!(dpkg_line("2026-11-10 12:00:00 install xdotool:amd64 <none> 1:3.2").unwrap().description, "Installed xdotool 1:3.2");
        assert_eq!(dpkg_line("2026-11-10 12:00:00 remove xdotool:amd64 1:3.2 <none>").unwrap().description, "Removed xdotool 1:3.2");
        assert!(dpkg_line("2026-11-10 12:00:00 status installed curl:amd64 8.1").is_none());
    }
}
