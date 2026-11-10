//! Change evidence and temporal correlation. Nearby changes are candidates,
//! never automatically labelled the cause of the user's problem.
use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
#[cfg(unix)]
use crate::parse::time::epoch_to_rfc3339;
use crate::parse::time::iso8601_utc_to_epoch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEvent {
    pub at: String,
    pub source: String,
    pub kind: String,
    pub description: String,
    pub detail: String,
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
        events.truncate(200);
        let mut rows = events
            .iter()
            .map(|e| Finding::info(format!("{} · {}", e.at, e.kind), &e.description).with_detail(format!("{} · {}", e.source, e.detail)))
            .collect::<Vec<_>>();
        rows.extend(gaps.into_iter().map(|g| Finding::info("Timeline coverage", g)));
        rows.push(Finding::info("Interpretation", "A nearby change is a possible temporal link. Confirm the failure's onset and the affected component before deciding it caused the problem."));
        Ok(Output::new(format!("{} recent change event(s)", events.len()), rows))
    }
}

pub fn from_xml(channel: &str, xml: &str) -> Option<ChangeEvent> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    let p = system.provider.to_ascii_lowercase();
    let kind = if p.contains("windowsupdate") || p.contains("servicing") {
        "Windows update"
    } else if p.contains("msiinstaller") {
        "Application installer"
    } else if p.contains("kernel-pnp") {
        "Device/driver activity"
    } else if p.contains("grouppolicy") {
        "Group Policy activity"
    } else if p.contains("service control") {
        "Service configuration"
    } else {
        "Restart/boot"
    };
    let detail = crate::parse::evtxml::event_data(xml)
        .into_iter()
        .take(10)
        .map(|(k, v)| format!("{k}: {}", v.chars().take(250).collect::<String>()))
        .collect::<Vec<_>>()
        .join(" · ");
    Some(ChangeEvent {
        at: system.time_created?,
        source: channel.into(),
        kind: kind.into(),
        description: format!(
            "{} event {}{}",
            system.provider,
            system.event_id,
            if system.level <= 2 && system.level > 0 { " (error)" } else { "" }
        ),
        detail,
    })
}

/// Structured rows from a saved run, including network connection history.
pub fn rows(report: &crate::Report) -> Vec<ChangeEvent> {
    let mut out = Vec::new();
    for module in report
        .results
        .iter()
        .filter(|r| matches!(r.module_id.as_str(), "system.changes" | "net.wifi-auth") && !r.preview && r.error.is_none())
    {
        for f in &module.findings {
            let Some(at) = f.label.get(..20).filter(|s| s.ends_with('Z') && iso8601_utc_to_epoch(s).is_some()) else {
                // Event XML often has fractional seconds. Take the first token.
                if let Some(at) = f
                    .label
                    .split_whitespace()
                    .next()
                    .filter(|s| s.ends_with('Z') && iso8601_utc_to_epoch(s).is_some())
                {
                    out.push(ChangeEvent {
                        at: at.into(),
                        source: module.title.clone(),
                        kind: "Recorded event".into(),
                        description: f.value.clone(),
                        detail: f.detail.clone().unwrap_or_default(),
                    });
                }
                continue;
            };
            out.push(ChangeEvent {
                at: at.into(),
                source: module.title.clone(),
                kind: f.label.get(23..).unwrap_or("Recorded event").into(),
                description: f.value.clone(),
                detail: f.detail.clone().unwrap_or_default(),
            });
        }
    }
    out.sort_by(|a, b| a.at.cmp(&b.at));
    out
}

pub fn near(report: &crate::Report, problem_at: u64, window_seconds: u64) -> Vec<ChangeEvent> {
    let window = window_seconds.clamp(60, 86_400);
    rows(report)
        .into_iter()
        .filter(|e| iso8601_utc_to_epoch(&e.at).is_some_and(|s| s.abs_diff(problem_at) <= window))
        .collect()
}

#[cfg(windows)]
fn collect() -> (Vec<ChangeEvent>, Vec<String>) {
    const SYSTEM: &str = "*[System[TimeCreated[timediff(@SystemTime) <= 604800000] and (Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] or Provider[@Name='Microsoft-Windows-Kernel-PnP'] or Provider[@Name='User32'] or (Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12) or (Provider[@Name='Service Control Manager'] and (EventID=7040 or EventID=7045)))]]";
    const INSTALLERS: &str = "*[System[Provider[@Name='MsiInstaller'] and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
    const RECENT: &str = "*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]";
    let mut events = Vec::new();
    let mut gaps = Vec::new();
    for (channel, query) in [
        ("System", SYSTEM),
        ("Application", INSTALLERS),
        ("Setup", RECENT),
        ("Microsoft-Windows-GroupPolicy/Operational", RECENT),
    ] {
        match crate::win::eventlog::query_xml(channel, query, 64) {
            Ok(rows) => events.extend(rows.iter().filter_map(|x| from_xml(channel, x))),
            Err(e) => gaps.push(e),
        }
    }
    gaps.push("Up to 64 most recent events per channel in seven days; log retention and permissions can leave gaps. An installer event is evidence of activity, not proof an upgrade succeeded.".into());
    (events, gaps)
}

#[cfg(not(windows))]
fn collect() -> (Vec<ChangeEvent>, Vec<String>) {
    use std::io::{Read, Seek, SeekFrom};
    let mut events = Vec::new();
    let mut gaps = Vec::new();
    match std::fs::File::open("/var/log/dpkg.log") {
        Ok(mut file) => {
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            let start = size.saturating_sub(2 * 1024 * 1024);
            let _ = file.seek(SeekFrom::Start(start));
            let mut text = String::new();
            let _ = file.take(2 * 1024 * 1024).read_to_string(&mut text);
            for line in text.lines().skip(usize::from(start > 0)) {
                if let Some(e) = dpkg_line(line) {
                    if iso8601_utc_to_epoch(&e.at).is_some_and(|s| s >= crate::util::now_epoch().saturating_sub(604800)) {
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
                    description: v["MESSAGE"].as_str().unwrap_or_default().chars().take(600).collect(),
                    detail: v["_SYSTEMD_UNIT"].as_str().unwrap_or_default().into(),
                });
            }
        } else {
            gaps.push("Package-manager journal could not be read.".into());
        }
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
    Some(ChangeEvent {
        at: epoch_to_rfc3339(time),
        source: "dpkg.log".into(),
        kind: "Package change".into(),
        description: format!("{action} {}", p.collect::<Vec<_>>().join(" ")),
        detail: "Package-manager record; timing alone does not establish causation.".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installer_activity_is_not_assumed_success_or_causation() {
        let e = from_xml("Application", "<Event><System><Provider Name='MsiInstaller'/><EventID>1033</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-10T12:00:00Z'/></System><EventData><Data Name='ProductName'>App</Data></EventData></Event>").unwrap();
        assert_eq!(e.kind, "Application installer");
        assert!(e.description.contains("error"));
        assert!(e.detail.contains("App"));
    }
    #[cfg(unix)]
    #[test]
    fn package_history_has_versions_and_ignores_status_noise() {
        let e = dpkg_line("2026-11-10 12:00:00 upgrade curl:amd64 8.0 8.1").unwrap();
        assert_eq!(e.description, "upgrade curl:amd64 8.0 8.1");
        assert!(dpkg_line("2026-11-10 12:00:00 status installed curl:amd64 8.1").is_none());
    }
}
