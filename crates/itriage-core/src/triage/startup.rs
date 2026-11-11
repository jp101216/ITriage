//! How long the PC takes to start, and what starts with it. Read-only.
//!
//! "It takes forever to start up" has three usual causes: too much
//! starting with Windows, one app or service that has become slow, or a
//! disk that is slow for everything. Windows times every start itself and
//! records what held it up; this reads those records.
//!
//! On Windows the times come from the Diagnostics-Performance log (event
//! 100 for each start, 101 to 110 for what slowed one down) and the list of
//! startup apps from one fixed PowerShell script. On Linux they come from
//! `systemd-analyze` and the autostart folders. The grading is plain
//! functions, tested on any OS.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::profile::Band;
use crate::util::plural;
#[cfg(any(windows, test))]
use serde::Deserialize;

pub struct Startup;

/// How far back the startup records are read.
const DAYS: u64 = 30;
/// Startup apps named in the finding before "and N more".
const NAMED: usize = 12;

impl TriageModule for Startup {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "system.startup",
            "Startup & sign-in speed",
            Category::System,
            "How long the last starts took (warns past 60 s to the desktop), what Windows recorded as slowing them down, and what starts with the PC.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::check(ctx)
    }
}

// ------------------------------------------------------------------ facts

/// One start of the PC, as Windows timed it.
#[derive(Debug, Clone, PartialEq)]
pub struct Boot {
    /// When it happened: seconds since 1970.
    pub at: u64,
    /// Power-on to a usable desktop, in milliseconds.
    pub main_ms: u64,
    /// And from there until the PC went quiet.
    pub post_ms: u64,
}

/// Something Windows recorded as making a start slower than usual.
#[derive(Debug, Clone, PartialEq)]
pub struct Delay {
    /// "Application", "Driver", "Service", "Device" or "Startup step".
    pub kind: &'static str,
    pub name: String,
    /// How much longer than usual it took, in milliseconds.
    pub extra_ms: u64,
}

/// A program that starts with the PC.
#[derive(Debug, Clone, PartialEq)]
pub struct App {
    pub name: String,
    /// Where it is set up: a registry key, a startup folder, an autostart file.
    pub location: String,
    pub enabled: bool,
}

// ----------------------------------------------------------------- parsers

/// A start, from event 100 of the Diagnostics-Performance log.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn boot_from_event(xml: &str) -> Option<Boot> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    if system.event_id != 100 {
        return None;
    }
    let data = crate::parse::evtxml::event_data(xml);
    let number = |name: &str| data.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.trim().parse::<u64>().ok());
    let total = number("BootTime");
    let main_ms = number("MainPathBootTime").or(total)?;
    Some(Boot {
        at: crate::parse::time::iso8601_utc_to_epoch(system.time_created.as_deref()?)?,
        main_ms,
        post_ms: number("BootPostBootTime").or_else(|| total.map(|t| t.saturating_sub(main_ms))).unwrap_or(0),
    })
}

/// What slowed a start down, from events 101 to 110 of the same log.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn delay_from_event(xml: &str) -> Option<Delay> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    let kind = match system.event_id {
        101 => "Application",
        102 => "Driver",
        103 => "Service",
        106 => "Startup step",
        108 | 109 => "Device",
        _ => return None,
    };
    let data = crate::parse::evtxml::event_data(xml);
    let value = |name: &str| data.iter().find(|(k, _)| k == name).map(|(_, v)| v.trim()).filter(|v| !v.is_empty());
    let name = value("FriendlyName").or(value("Name")).or(value("Description"))?;
    Some(Delay {
        kind,
        name: name.chars().take(80).collect(),
        extra_ms: value("DegradationTime").and_then(|v| v.parse().ok()).unwrap_or(0),
    })
}

/// "1min 2.345s", "15.4s", "850ms" → seconds.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_duration(text: &str) -> Option<f64> {
    let mut total = 0.0;
    let mut any = false;
    for part in text.split_whitespace() {
        let split = part.find(|c: char| c.is_ascii_alphabetic())?;
        let (number, unit) = part.split_at(split);
        let n: f64 = number.parse().ok()?;
        total += match unit {
            "h" => n * 3600.0,
            "min" => n * 60.0,
            "s" => n,
            "ms" => n / 1000.0,
            "us" | "μs" => n / 1_000_000.0,
            _ => return None,
        };
        any = true;
    }
    any.then_some(total)
}

/// `systemd-analyze time`: the whole start, and the part before anyone could
/// sign in (kernel and userspace; firmware and boot loader are the
/// machine's, not the system's).
#[cfg_attr(windows, allow(dead_code))]
pub fn analyze_time(text: &str) -> Option<(f64, f64)> {
    let line = text.lines().find(|l| l.starts_with("Startup finished in "))?;
    let (parts, total) = line.trim_start_matches("Startup finished in ").rsplit_once(" = ")?;
    let total = parse_duration(total)?;
    let mut system = 0.0;
    for part in parts.split(" + ") {
        let (time, stage) = part.rsplit_once(" (")?;
        if matches!(stage.trim_end_matches(')'), "kernel" | "initrd" | "userspace") {
            system += parse_duration(time)?;
        }
    }
    Some((total, if system > 0.0 { system } else { total }))
}

/// `systemd-analyze blame`: the slowest units first, in seconds.
#[cfg_attr(windows, allow(dead_code))]
pub fn blame(text: &str) -> Vec<(f64, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            // The time can be two words ("1min 2.345s"); the unit is the last.
            let (time, unit) = line.rsplit_once(' ')?;
            Some((parse_duration(time)?, unit.to_string()))
        })
        .collect()
}

/// One autostart file: its name, and whether it is switched off.
#[cfg_attr(windows, allow(dead_code))]
pub fn desktop_entry(text: &str, file: &str) -> App {
    let value = |key: &str| text.lines().find_map(|l| l.strip_prefix(key).and_then(|rest| rest.strip_prefix('='))).map(str::trim);
    let off = value("Hidden") == Some("true") || value("X-GNOME-Autostart-enabled") == Some("false");
    App {
        name: value("Name").filter(|n| !n.is_empty()).unwrap_or(file.trim_end_matches(".desktop")).to_string(),
        location: "autostart".into(),
        enabled: !off,
    }
}

// ----------------------------------------------------------------- grading

fn seconds(ms: u64) -> String {
    let s = ms as f64 / 1000.0;
    if s >= 100.0 {
        format!("{s:.0} s")
    } else {
        format!("{s:.1} s")
    }
}

/// The latest start against the usual one. `boots` is newest first.
pub fn boot_findings(boots: &[Boot], band: &Band, now: u64) -> Vec<Finding> {
    let Some(last) = boots.first() else {
        return Vec::new();
    };
    let to_desktop = last.main_ms as f64 / 1000.0;
    let mut detail = format!("Then {} more until the PC went quiet.", seconds(last.post_ms));
    let earlier: Vec<u64> = boots.iter().skip(1).map(|b| b.main_ms).collect();
    let mut value = format!("{} to the desktop · {}", seconds(last.main_ms), crate::util::ago(now.saturating_sub(last.at)));
    if !earlier.is_empty() {
        let mut sorted = earlier.clone();
        sorted.sort_unstable();
        let usual = sorted[sorted.len() / 2];
        detail.push_str(&format!(
            " The {} start{} before it took {} (middle value), from {} to {}.",
            earlier.len(),
            plural(earlier.len()),
            seconds(usual),
            seconds(sorted[0]),
            seconds(sorted[sorted.len() - 1])
        ));
        // Half as long again, and at least ten seconds: slower than this PC's own normal.
        if last.main_ms > usual + usual / 2 && last.main_ms > usual + 10_000 {
            value.push_str(&format!(" · usually {}", seconds(usual)));
        }
    }
    vec![Finding::new("Last start", value, band.high(to_desktop)).with_detail(detail).with_metric((to_desktop * 10.0).round() / 10.0, "s", true)]
}

/// What held starts up, most costly first. One row for each thing, however
/// many starts it slowed.
pub fn delay_findings(delays: &[Delay]) -> Vec<Finding> {
    let mut totals: Vec<(&'static str, String, usize, u64)> = Vec::new();
    for d in delays {
        match totals.iter_mut().find(|(kind, name, _, _)| *kind == d.kind && name.eq_ignore_ascii_case(&d.name)) {
            Some(row) => {
                row.2 += 1;
                row.3 += d.extra_ms;
            }
            None => totals.push((d.kind, d.name.clone(), 1, d.extra_ms)),
        }
    }
    totals.sort_by(|a, b| b.3.cmp(&a.3).then(b.2.cmp(&a.2)).then(a.1.cmp(&b.1)));
    totals
        .into_iter()
        .take(6)
        .map(|(kind, name, times, extra)| {
            let each = extra / times.max(1) as u64;
            Finding::new(
                format!("Slowed startup: {name}"),
                format!("{kind} · {times} time{} in {DAYS} days · about {} extra each time", plural(times), seconds(each)),
                if each >= 10_000 && times >= 2 { Severity::Warning } else { Severity::Info },
            )
            .with_detail("Recorded by Windows when something takes longer than it usually does while the PC starts.")
        })
        .collect()
}

/// What starts with the PC.
pub fn app_findings(apps: &[App]) -> Vec<Finding> {
    let mut on: Vec<&App> = apps.iter().filter(|a| a.enabled).collect();
    on.sort_by_key(|a| a.name.to_ascii_lowercase());
    on.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));
    let off = apps.iter().filter(|a| !a.enabled).count();
    if on.is_empty() && off == 0 {
        return vec![Finding::ok("Startup apps", "none set up")];
    }
    let mut names: Vec<String> = on.iter().take(NAMED).map(|a| a.name.clone()).collect();
    if on.len() > NAMED {
        names.push(format!("and {} more", on.len() - NAMED));
    }
    let value = format!(
        "{} start with the PC{}{}",
        on.len(),
        if off > 0 { format!(" ({off} switched off)") } else { String::new() },
        if names.is_empty() { String::new() } else { format!(": {}", names.join(", ")) }
    );
    // Many small helpers add up; the count alone is never a fault.
    let severity = if on.len() >= 15 { Severity::Warning } else { Severity::Info };
    vec![Finding::new("Startup apps", value, severity).with_detail(if cfg!(windows) {
        "Task Manager → Startup apps switches one off without uninstalling it. Sync clients, chat apps and updaters are the usual ones nobody would miss at sign-in."
    } else {
        "Each desktop's Startup Applications settings switch one off without uninstalling it."
    })]
}

pub fn summary(findings: &[Finding]) -> String {
    // A measured start has its figure with it; "couldn't be read" doesn't.
    let last = findings.iter().find(|f| f.label == "Last start" && f.metric.is_some()).map(|f| f.value.split(" · ").next().unwrap_or(&f.value).to_string());
    let apps = findings.iter().find(|f| f.label == "Startup apps").and_then(|f| f.value.split(' ').next().and_then(|n| n.parse::<usize>().ok()));
    match (last, apps) {
        (Some(last), Some(apps)) => format!("{last} · {apps} startup app{}", plural(apps)),
        (Some(last), None) => last,
        (None, Some(apps)) => format!("{apps} startup app{} · no start times recorded", plural(apps)),
        (None, None) => "No start times recorded".to_string(),
    }
}

// ---------------------------------------------------------------- Windows

/// The startup apps, as Task Manager's Startup tab knows them: everything
/// Windows runs at sign-in from the Run keys and Startup folders (for every
/// user it can see), and which of them have been switched off there.
/// `ITRIAGE_SID` is the signed-in user's, so their own list is read when
/// ITriage runs as someone else.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const STARTUP_APPS: &str = r#"
$ErrorActionPreference = 'Stop'
$r = [ordered]@{ Apps = @(); Off = @(); Error = '' }
try {
  $r.Apps = @(Get-CimInstance Win32_StartupCommand | ForEach-Object {
    [ordered]@{ Name = [string]$_.Name; Location = [string]$_.Location; User = [string]$_.User }
  })
} catch { $r.Error = [string]$_.Exception.Message }
$roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved')
if ($env:ITRIAGE_SID -match '^S-1-[0-9-]+$') {
  $roots += "Registry::HKEY_USERS\$($env:ITRIAGE_SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
} else {
  $roots += 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
}
foreach ($root in $roots) {
  foreach ($key in @('Run', 'Run32', 'StartupFolder')) {
    $path = Join-Path $root $key
    try {
      if (Test-Path -LiteralPath $path) {
        $item = Get-ItemProperty -LiteralPath $path
        foreach ($p in $item.PSObject.Properties) {
          # Twelve bytes; the first is odd when the entry is switched off.
          if ($p.Value -is [byte[]] -and $p.Value.Length -gt 0 -and ($p.Value[0] -band 1) -eq 1) { $r.Off += [string]$p.Name }
        }
      }
    } catch {}
  }
}
Send-ITriage $r
"#;

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct AppFacts {
    #[serde(deserialize_with = "crate::parse::psjson::list")]
    pub apps: Vec<StartupCommand>,
    #[serde(deserialize_with = "crate::parse::psjson::list")]
    pub off: Vec<String>,
    #[serde(deserialize_with = "crate::parse::psjson::or_default")]
    pub error: String,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct StartupCommand {
    #[serde(deserialize_with = "crate::parse::psjson::or_default")]
    pub name: String,
    #[serde(deserialize_with = "crate::parse::psjson::or_default")]
    pub location: String,
    #[serde(deserialize_with = "crate::parse::psjson::or_default")]
    pub user: String,
}

/// The script's answer as the list to grade. A startup-folder entry is
/// switched off under its file name ("Tool.lnk"), a registry one under its
/// value name.
#[cfg(any(windows, test))]
pub fn apps_from(facts: &AppFacts) -> Vec<App> {
    facts
        .apps
        .iter()
        .filter(|a| !a.name.trim().is_empty())
        .map(|a| {
            let off = facts.off.iter().any(|o| o.eq_ignore_ascii_case(&a.name) || o.eq_ignore_ascii_case(&format!("{}.lnk", a.name)));
            App {
                name: a.name.trim().to_string(),
                location: a.location.clone(),
                enabled: !off,
            }
        })
        .collect()
}

#[cfg(windows)]
mod imp {
    use super::*;

    const LOG: &str = "Microsoft-Windows-Diagnostics-Performance/Operational";
    const BOOTS: &str = "*[System[EventID=100 and TimeCreated[timediff(@SystemTime) <= 2592000000]]]";
    const DELAYS: &str = "*[System[(EventID >= 101 and EventID <= 110) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]";

    pub fn check(ctx: &RunContext) -> Result<Output, String> {
        let mut findings = Vec::new();
        let now = crate::util::now_epoch();
        match crate::win::eventlog::query_xml(LOG, BOOTS, 20) {
            Ok(events) => {
                let boots: Vec<Boot> = events.iter().filter_map(|x| boot_from_event(x)).collect();
                if boots.is_empty() {
                    findings.push(Finding::info(
                        "Last start",
                        format!("Windows hasn't recorded a start time in the last {DAYS} days"),
                    ).with_detail("Windows times its starts on desktop editions. A PC that only ever sleeps or uses Fast Startup records few of them, and a server records none."));
                }
                findings.extend(boot_findings(&boots, &ctx.profile().thresholds.startup_seconds, now));
            }
            Err(e) => findings.push(Finding::info("Last start", format!("start times couldn't be read: {e}"))),
        }
        if let Ok(events) = crate::win::eventlog::query_xml(LOG, DELAYS, 200) {
            let delays: Vec<Delay> = events.iter().filter_map(|x| delay_from_event(x)).collect();
            findings.extend(delay_findings(&delays));
        }
        let sid = crate::win::session::console_user().as_deref().and_then(crate::win::session::sid_of).unwrap_or_default();
        let apps = crate::win::ps::run_with(STARTUP_APPS, &[("ITRIAGE_SID", sid.as_str())], ctx, std::time::Duration::from_secs(60))
            .and_then(|out| crate::fixes::json::<AppFacts>(&out.stdout).map_err(|e| format!("{e} ({})", crate::util::exit_label(out.code))));
        match apps {
            Ok(facts) if !facts.error.is_empty() && facts.apps.is_empty() => {
                findings.push(Finding::info("Startup apps", format!("couldn't be listed: {}", facts.error)))
            }
            Ok(facts) => findings.extend(app_findings(&apps_from(&facts))),
            Err(e) => findings.push(Finding::info("Startup apps", format!("couldn't be listed: {e}"))),
        }
        Ok(Output::new(summary(&findings), findings))
    }
}

// ------------------------------------------------------------------ Linux

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::util::{capture_for, cmd, command_exists};
    use std::time::Duration;

    fn analyze(args: &[&str]) -> Result<String, String> {
        let mut c = cmd("systemd-analyze");
        c.args(args).env("LC_ALL", "C");
        let out = capture_for(c, Duration::from_secs(15))?;
        if out.success() {
            Ok(out.stdout)
        } else {
            // "System has not been booted with systemd", "Bootup is not yet finished"…
            Err(out.stderr.lines().chain(out.stdout.lines()).map(str::trim).find(|l| !l.is_empty()).unwrap_or("it gave no answer").to_string())
        }
    }

    /// The autostart files for this desktop session and for everyone.
    fn autostart() -> Vec<App> {
        let mut folders = vec![std::path::PathBuf::from("/etc/xdg/autostart")];
        // The person at the console, when ITriage runs as root for them.
        let home = crate::host::signed_in_user()
            .map(|user| std::path::PathBuf::from("/home").join(user))
            .filter(|p| p.is_dir())
            .or_else(|| std::env::var_os("HOME").map(std::path::PathBuf::from));
        if let Some(home) = home {
            folders.push(home.join(".config/autostart"));
        }
        let mut apps = Vec::new();
        for folder in folders {
            let Ok(entries) = std::fs::read_dir(&folder) else { continue };
            for entry in entries.flatten() {
                let file = entry.file_name().to_string_lossy().into_owned();
                if !file.ends_with(".desktop") {
                    continue;
                }
                // A small text file; a huge one isn't an autostart entry.
                if entry.metadata().is_ok_and(|m| m.len() <= 64 * 1024) {
                    if let Ok(text) = std::fs::read_to_string(entry.path()) {
                        apps.push(desktop_entry(&text, &file));
                    }
                }
            }
        }
        apps
    }

    pub fn check(ctx: &RunContext) -> Result<Output, String> {
        let mut findings = Vec::new();
        if command_exists("systemd-analyze") {
            match analyze(&["time"]).map(|text| analyze_time(&text).ok_or(text)) {
                Ok(Ok((total, system))) => {
                    let mut finding = Finding::new(
                        "Last start",
                        format!("{} to sign-in · {} with the firmware and boot loader", seconds((system * 1000.0) as u64), seconds((total * 1000.0) as u64)),
                        ctx.profile().thresholds.startup_seconds.high(system),
                    )
                    .with_metric((system * 10.0).round() / 10.0, "s", true);
                    if let Ok(text) = analyze(&["blame"]) {
                        let slowest: Vec<String> = blame(&text).into_iter().take(5).filter(|(s, _)| *s >= 1.0).map(|(s, unit)| format!("{unit} {}", seconds((s * 1000.0) as u64))).collect();
                        if !slowest.is_empty() {
                            finding = finding.with_detail(format!("Slowest to start: {}. Units start side by side, so these don't add up to the total.", slowest.join(", ")));
                        }
                    }
                    findings.push(finding);
                }
                Ok(Err(text)) => findings.push(Finding::info("Last start", text.lines().next().unwrap_or("not finished starting").trim().to_string())),
                Err(why) => findings.push(Finding::info("Last start", format!("no start time: {why}"))),
            }
        } else {
            findings.push(Finding::info("Last start", "no start time: systemd-analyze isn't installed"));
        }
        findings.extend(app_findings(&autostart()));
        Ok(Output::new(summary(&findings), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BAND: Band = Band { warn: 60.0, crit: 120.0 };

    fn boot_event(time: &str, total: u64, main: u64, post: u64) -> String {
        format!(
            "<Event><System><Provider Name='Microsoft-Windows-Diagnostics-Performance'/><EventID>100</EventID><Level>3</Level>\
             <TimeCreated SystemTime='{time}'/></System><EventData><Data Name='BootTsVersion'>2</Data>\
             <Data Name='BootTime'>{total}</Data><Data Name='MainPathBootTime'>{main}</Data><Data Name='BootPostBootTime'>{post}</Data>\
             <Data Name='BootNumStartupApps'>14</Data></EventData></Event>"
        )
    }

    #[test]
    fn reads_a_start_and_what_slowed_it() {
        let boot = boot_from_event(&boot_event("2026-11-10T12:00:00.1234567Z", 94_000, 71_500, 22_500)).unwrap();
        assert_eq!((boot.main_ms, boot.post_ms), (71_500, 22_500));
        assert_eq!(boot.at, crate::parse::time::iso8601_utc_to_epoch("2026-11-10T12:00:00Z").unwrap());
        // An older Windows records the total alone.
        let total_only = "<Event><System><Provider Name='x'/><EventID>100</EventID><TimeCreated SystemTime='2026-11-10T12:00:00Z'/></System><EventData><Data Name='BootTime'>40000</Data></EventData></Event>";
        assert_eq!(boot_from_event(total_only).unwrap().main_ms, 40_000);
        let slow = "<Event><System><Provider Name='x'/><EventID>101</EventID><TimeCreated SystemTime='2026-11-10T12:00:00Z'/></System><EventData>\
            <Data Name='Name'>OneDrive.exe</Data><Data Name='FriendlyName'>Microsoft OneDrive</Data><Data Name='TotalTime'>9000</Data><Data Name='DegradationTime'>6200</Data></EventData></Event>";
        assert_eq!(delay_from_event(slow).unwrap(), Delay { kind: "Application", name: "Microsoft OneDrive".into(), extra_ms: 6_200 });
        assert_eq!(boot_from_event(slow), None);
        assert_eq!(delay_from_event(&boot_event("2026-11-10T12:00:00Z", 1, 1, 0)), None);
    }

    #[test]
    fn grades_the_last_start_against_the_threshold_and_this_pcs_normal() {
        let now = 1_794_400_000;
        let boot = |ago: u64, main: u64| Boot { at: now - ago, main_ms: main, post_ms: 20_000 };
        // Quick, and like the ones before it.
        let fine = boot_findings(&[boot(3_600, 24_000), boot(90_000, 26_000), boot(180_000, 22_000)], &BAND, now);
        assert_eq!(fine[0].severity, Severity::Ok);
        assert_eq!(fine[0].value, "24.0 s to the desktop · 1h ago");
        assert!(fine[0].detail.as_deref().unwrap().contains("The 2 starts before it took 26.0 s (middle value), from 22.0 s to 26.0 s."));
        assert_eq!(fine[0].metric.as_ref().unwrap().value, 24.0);
        // Under the threshold, and still twice this PC's normal.
        let slower = boot_findings(&[boot(3_600, 55_000), boot(90_000, 26_000), boot(180_000, 22_000)], &BAND, now);
        assert_eq!(slower[0].severity, Severity::Ok);
        assert!(slower[0].value.ends_with("· usually 26.0 s"), "{}", slower[0].value);
        // Past the threshold.
        assert_eq!(boot_findings(&[boot(60, 75_000)], &BAND, now)[0].severity, Severity::Warning);
        assert_eq!(boot_findings(&[boot(60, 190_000)], &BAND, now)[0].severity, Severity::Critical);
        assert!(boot_findings(&[boot(60, 190_000)], &BAND, now)[0].value.starts_with("190 s to the desktop"));
        assert!(boot_findings(&[], &BAND, now).is_empty());
    }

    #[test]
    fn names_what_held_startup_up_most() {
        let delay = |kind: &'static str, name: &str, extra: u64| Delay { kind, name: name.into(), extra_ms: extra };
        let rows = delay_findings(&[
            delay("Application", "Microsoft OneDrive", 12_000),
            delay("Service", "Windows Search", 3_000),
            delay("Application", "microsoft onedrive", 14_000),
            delay("Driver", "Contoso Filter", 30_000),
        ]);
        assert_eq!(rows[0].label, "Slowed startup: Contoso Filter");
        assert_eq!(rows[0].severity, Severity::Info, "once isn't a pattern");
        assert_eq!(rows[1].label, "Slowed startup: Microsoft OneDrive");
        assert_eq!(rows[1].value, "Application · 2 times in 30 days · about 13.0 s extra each time");
        assert_eq!(rows[1].severity, Severity::Warning);
        assert_eq!(rows[2].value, "Service · 1 time in 30 days · about 3.0 s extra each time");
        assert!(delay_findings(&[]).is_empty());
    }

    #[test]
    fn lists_startup_apps_and_the_ones_switched_off() {
        let facts: AppFacts = serde_json::from_str(
            r#"{"Apps":[{"Name":"OneDrive","Location":"HKU\\S-1-5-21\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","User":"CORP\\jparker"},
                {"Name":"Teams","Location":"HKU\\S-1-5-21\\...\\Run","User":"CORP\\jparker"},
                {"Name":"Scanner Tool","Location":"Common Startup","User":"Public"},
                {"Name":"SecurityHealth","Location":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","User":"Public"},
                {"Name":" ","Location":"","User":""}],
              "Off":["Teams","Scanner Tool.lnk"],"Error":""}"#,
        )
        .unwrap();
        let apps = apps_from(&facts);
        assert_eq!(apps.len(), 4);
        let rows = app_findings(&apps);
        assert_eq!(rows[0].value, "2 start with the PC (2 switched off): OneDrive, SecurityHealth");
        assert_eq!(rows[0].severity, Severity::Info);
        // One script answer with a single app comes back as an object, not a list.
        let one: AppFacts = serde_json::from_str(r#"{"Apps":{"Name":"OneDrive","Location":"Run","User":"x"},"Off":null}"#).unwrap();
        assert_eq!(apps_from(&one).len(), 1);
        // Plenty of them is worth saying; the list stays readable.
        let many: Vec<App> = (0..18).map(|i| App { name: format!("Helper {i:02}"), location: "Run".into(), enabled: true }).collect();
        let rows = app_findings(&many);
        assert_eq!(rows[0].severity, Severity::Warning);
        assert!(rows[0].value.starts_with("18 start with the PC: Helper 00, ") && rows[0].value.ends_with(", and 6 more"), "{}", rows[0].value);
        assert_eq!(app_findings(&[])[0].value, "none set up");
    }

    #[test]
    fn reads_systemd_analyze() {
        assert_eq!(parse_duration("1min 2.345s"), Some(62.345));
        assert_eq!(parse_duration("850ms"), Some(0.85));
        assert_eq!(parse_duration("fast"), None);
        let text = "Startup finished in 8.214s (firmware) + 2.790s (loader) + 3.151s (kernel) + 12.262s (userspace) = 26.418s \ngraphical.target reached after 12.101s in userspace.\n";
        let (total, system) = analyze_time(text).unwrap();
        assert!((total - 26.418).abs() < 1e-9 && (system - 15.413).abs() < 1e-9, "{total} {system}");
        // A virtual machine has no firmware stage to report.
        assert_eq!(analyze_time("Startup finished in 1.5s (kernel) + 1min 4.5s (userspace) = 1min 6s\n"), Some((66.0, 66.0)));
        assert_eq!(analyze_time("Bootup is not yet finished (org.freedesktop.systemd1.Manager.FinishTimestampMonotonic=0).\n"), None);
        let slowest = blame("1min 2.345s NetworkManager-wait-online.service\n     12.101s snapd.seeded.service\n       850ms dev-sda1.device\n");
        assert_eq!(slowest[0], (62.345, "NetworkManager-wait-online.service".to_string()));
        assert_eq!(slowest.len(), 3);
    }

    #[test]
    fn reads_autostart_files() {
        let on = desktop_entry("[Desktop Entry]\nType=Application\nName=Nextcloud\nExec=nextcloud --background\n", "com.nextcloud.desktopclient.desktop");
        assert_eq!((on.name.as_str(), on.enabled), ("Nextcloud", true));
        let off = desktop_entry("[Desktop Entry]\nName=Old Tool\nX-GNOME-Autostart-enabled=false\n", "old.desktop");
        assert!(!off.enabled);
        assert!(!desktop_entry("[Desktop Entry]\nHidden=true\n", "hidden-thing.desktop").enabled);
        assert_eq!(desktop_entry("[Desktop Entry]\nExec=x\n", "hidden-thing.desktop").name, "hidden-thing");
    }

    #[test]
    fn the_summary_reads_at_a_glance() {
        let rows = vec![Finding::ok("Last start", "24.0 s to the desktop · 1h ago").with_metric(24.0, "s", true), Finding::info("Startup apps", "7 start with the PC: a, b")];
        assert_eq!(summary(&rows), "24.0 s to the desktop · 7 startup apps");
        assert_eq!(summary(&[Finding::ok("Startup apps", "none set up")]), "No start times recorded");
        assert_eq!(summary(&rows[1..]), "7 startup apps · no start times recorded");
        let unread = vec![Finding::info("Last start", "start times couldn't be read: access is denied"), rows[1].clone()];
        assert_eq!(summary(&unread), "7 startup apps · no start times recorded");
    }
}
