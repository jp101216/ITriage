//! Drive health and reliability over the last 30 days. Read-only.
//!
//! The things that make a PC "keep crashing" or "feel like it's dying": a
//! drive that reports itself unhealthy or worn out, blue screens, shutdowns
//! nobody asked for, disk errors in the system log, and the apps that crash
//! or hang most.
//!
//! On Windows one fixed PowerShell script gathers the facts (drives from the
//! Storage module, events from the System and Application logs). On Linux
//! they come from `/sys/block`, `smartctl` (as root), the kernel journal and
//! `coredumpctl`. The grading is plain functions, tested on any OS.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::psjson::{list, or_default};
use crate::util::{ago, human_bytes, plural};
use serde::Deserialize;

pub struct Reliability;

/// How far back the event logs are read.
pub const DAYS: u32 = 30;

impl TriageModule for Reliability {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "system.reliability",
            "Drive health & reliability",
            Category::System,
            "Each drive's health, wear and errors (SMART), and the last 30 days of blue screens, unexpected shutdowns, disk errors and the apps that crash most.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::check(ctx)
    }
}

/// Gathers the facts, changing nothing. The drive counters (wear,
/// temperature, errors) and the failure prediction only answer an
/// administrator; everything else works for a standard user.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const RELIABILITY: &str = r#"
$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddDays(-30)
$epoch = [datetime]'1970-01-01'
$r = [ordered]@{}

$r.Disks = @()
$r.DisksError = ''
try {
  $r.Disks = @(Get-PhysicalDisk | ForEach-Object {
    $d = $_
    $c = $null
    try { $c = $d | Get-StorageReliabilityCounter } catch {}
    $o = [ordered]@{
      Name = [string]$d.FriendlyName
      Media = [string]$d.MediaType
      Bus = [string]$d.BusType
      Health = [string]$d.HealthStatus
      Status = [string](@($d.OperationalStatus) -join ', ')
      Size = [uint64]$d.Size
      Wear = $null; Temperature = $null; ReadErrors = $null; WriteErrors = $null; PowerOnHours = $null
    }
    if ($c) {
      if ($null -ne $c.Wear) { $o.Wear = [int]$c.Wear }
      if ($null -ne $c.Temperature) { $o.Temperature = [int]$c.Temperature }
      if ($null -ne $c.ReadErrorsUncorrected) { $o.ReadErrors = [uint64]$c.ReadErrorsUncorrected }
      if ($null -ne $c.WriteErrorsUncorrected) { $o.WriteErrors = [uint64]$c.WriteErrorsUncorrected }
      if ($null -ne $c.PowerOnHours) { $o.PowerOnHours = [uint64]$c.PowerOnHours }
    }
    $o
  })
} catch { $r.DisksError = [string]$_.Exception.Message }

$r.Predicted = @()
try { $r.Predicted = @(Get-CimInstance -Namespace 'root/wmi' -ClassName MSStorageDriver_FailurePredictStatus | Where-Object { $_.PredictFailure } | ForEach-Object { [string]$_.InstanceName }) } catch {}

$r.System = @()
try {
  $r.System = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41, 6008, 1001, 7, 11, 51, 52, 55, 129, 153, 157; StartTime = $since } -MaxEvents 2000 -ErrorAction SilentlyContinue | ForEach-Object {
    $first = ''
    try { if ($_.Properties.Count -gt 0) { $first = [string]$_.Properties[0].Value } } catch {}
    if ($first.Length -gt 120) { $first = $first.Substring(0, 120) }
    [ordered]@{ P = [string]$_.ProviderName; I = [int]$_.Id; T = [int64]($_.TimeCreated.ToUniversalTime() - $epoch).TotalSeconds; V = $first }
  })
} catch {}

$r.Apps = @()
try {
  $r.Apps = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1002; StartTime = $since } -MaxEvents 2000 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -eq 'Application Error' -or $_.ProviderName -eq 'Application Hang' } | ForEach-Object {
      $app = ''
      try { if ($_.Properties.Count -gt 0) { $app = [string]$_.Properties[0].Value } } catch {}
      if ($app.Length -gt 120) { $app = $app.Substring(0, 120) }
      [ordered]@{ A = $app; H = ($_.Id -eq 1002); T = [int64]($_.TimeCreated.ToUniversalTime() - $epoch).TotalSeconds }
    })
} catch {}

Send-ITriage $r
"#;

// ------------------------------------------------------------------ facts

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Facts {
    #[serde(deserialize_with = "list")]
    pub disks: Vec<Disk>,
    #[serde(deserialize_with = "or_default")]
    pub disks_error: String,
    /// Drives whose own SMART logic predicts failure.
    #[serde(deserialize_with = "list")]
    pub predicted: Vec<String>,
    #[serde(deserialize_with = "list")]
    pub system: Vec<Event>,
    #[serde(deserialize_with = "list")]
    pub apps: Vec<AppEvent>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Disk {
    #[serde(deserialize_with = "or_default")]
    pub name: String,
    /// SSD, HDD, SCM or Unspecified.
    #[serde(deserialize_with = "or_default")]
    pub media: String,
    #[serde(deserialize_with = "or_default")]
    pub bus: String,
    /// Healthy, Warning or Unhealthy.
    #[serde(deserialize_with = "or_default")]
    pub health: String,
    #[serde(deserialize_with = "or_default")]
    pub status: String,
    #[serde(deserialize_with = "or_default")]
    pub size: u64,
    /// Percent of rated life used.
    pub wear: Option<i64>,
    pub temperature: Option<i64>,
    pub read_errors: Option<u64>,
    pub write_errors: Option<u64>,
    pub power_on_hours: Option<u64>,
}

/// One event from the System log.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Event {
    #[serde(rename = "P", deserialize_with = "or_default")]
    pub provider: String,
    #[serde(rename = "I")]
    pub id: u32,
    /// Unix seconds.
    #[serde(rename = "T")]
    pub time: i64,
    /// The event's first value: the stop code, the device…
    #[serde(rename = "V", deserialize_with = "or_default")]
    pub value: String,
}

/// One application crash or hang.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AppEvent {
    #[serde(rename = "A", deserialize_with = "or_default")]
    pub app: String,
    #[serde(rename = "H")]
    pub hang: bool,
    #[serde(rename = "T")]
    pub time: i64,
}

// ---------------------------------------------------------------- grading

fn since(now: u64, time: i64) -> String {
    ago(now.saturating_sub(time.max(0) as u64))
}

fn window() -> String {
    format!("({DAYS} days)")
}

/// One finding per drive, plus the failure prediction when a drive makes one.
pub fn drive_findings(disks: &[Disk], predicted: &[String], error: &str, elevated: bool) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    if !predicted.is_empty() {
        out.push(
            Finding::crit(
                "Failure predicted (SMART)",
                format!("{} drive{} report{} that failure is close", predicted.len(), plural(predicted.len()), if predicted.len() == 1 { "s" } else { "" }),
            )
            .with_detail(format!("Back up this PC's data now and replace the drive. {}", predicted.join("; "))),
        );
    }
    if disks.is_empty() {
        let why = if error.is_empty() { "none were reported".to_string() } else { error.to_string() };
        out.push(Finding::info("Drives", format!("couldn't list them: {why}")));
        return out;
    }
    for d in disks {
        let name = if d.name.trim().is_empty() { "unnamed" } else { d.name.trim() };
        let mut label = format!("Drive ({name})");
        let twins = out.iter().filter(|f| f.label == label || f.label.starts_with(&format!("{label} #"))).count();
        if twins > 0 {
            label = format!("{label} #{}", twins + 1);
        }

        let mut severity = Severity::Ok;
        let mut worse = |s: Severity| {
            if s.rank() > severity.rank() {
                severity = s;
            }
        };
        // What's wrong leads the line; the description follows.
        let mut wrong: Vec<String> = Vec::new();
        let mut notes = Vec::new();
        // Failing, as opposed to merely hot.
        let mut replace = false;
        let mut parts = Vec::new();
        match d.health.to_ascii_lowercase().as_str() {
            "healthy" => parts.push("healthy".to_string()),
            "warning" => {
                worse(Severity::Warning);
                replace = true;
                wrong.push("Windows reports a warning".to_string());
            }
            "unhealthy" => {
                worse(Severity::Critical);
                replace = true;
                wrong.push("unhealthy".to_string());
            }
            "" => {
                worse(Severity::Info);
                parts.push("health not reported".to_string());
            }
            other => {
                worse(Severity::Info);
                parts.push(other.to_string());
            }
        }
        if !d.status.is_empty() && !d.status.eq_ignore_ascii_case("OK") {
            parts.push(d.status.to_lowercase());
        }
        if !d.media.is_empty() && !d.media.eq_ignore_ascii_case("Unspecified") {
            parts.push(d.media.clone());
        }
        if !d.bus.is_empty() {
            parts.push(d.bus.clone());
        }
        if d.size > 0 {
            parts.push(human_bytes(d.size));
        }
        if let Some(wear) = d.wear.filter(|w| (0..=255).contains(w)) {
            let used = format!("{wear}% of its rated life used");
            if wear >= 70 {
                worse(if wear >= 90 { Severity::Critical } else { Severity::Warning });
                replace = true;
                wrong.push(used);
                if wear >= 90 {
                    notes.push("The drive is at the end of its rated life.".to_string());
                }
            } else {
                parts.push(used);
            }
        }
        let errors = d.read_errors.unwrap_or(0) + d.write_errors.unwrap_or(0);
        if errors > 0 {
            worse(Severity::Warning);
            replace = true;
            wrong.push(format!("{errors} error{} it couldn't correct", plural(errors as usize)));
            notes.push(format!("{} reading, {} writing.", d.read_errors.unwrap_or(0), d.write_errors.unwrap_or(0)));
        }
        if let Some(t) = d.temperature.filter(|t| *t > 0) {
            if t >= 70 {
                worse(Severity::Warning);
                wrong.push(format!("running hot at {t} °C"));
                notes.push("Check the fan and vents; a drive this hot slows itself down to cool off.".to_string());
            } else {
                parts.push(format!("{t} °C"));
            }
        }
        if let Some(h) = d.power_on_hours.filter(|h| *h > 0) {
            notes.push(format!("Powered on for {} days in total.", h / 24));
        }
        if replace {
            notes.insert(0, "Back up this drive's data and plan to replace it.".to_string());
        }
        wrong.extend(parts);
        let parts = wrong;
        let mut f = Finding::new(label, parts.join(" · "), severity).with_detail(notes.join(" "));
        if let Some(wear) = d.wear.filter(|w| (0..=255).contains(w)) {
            f = f.with_metric(wear as f64, "%", true);
        }
        out.push(f);
    }
    if !elevated && disks.iter().all(|d| d.wear.is_none() && d.temperature.is_none() && d.read_errors.is_none()) {
        out.push(Finding::info("Drive counters", "wear, temperature and error counts are only reported to an administrator"));
    }
    out
}

/// A stop code's name and what it usually points at.
fn stop_code(code: u32) -> (&'static str, &'static str) {
    match code {
        0x0A => ("IRQL_NOT_LESS_OR_EQUAL", "a driver or faulty memory"),
        0x1A => ("MEMORY_MANAGEMENT", "faulty memory or a driver"),
        0x1E => ("KMODE_EXCEPTION_NOT_HANDLED", "a driver"),
        0x3B => ("SYSTEM_SERVICE_EXCEPTION", "a driver"),
        0x50 => ("PAGE_FAULT_IN_NONPAGED_AREA", "a driver or faulty memory"),
        0x7A => ("KERNEL_DATA_INPAGE_ERROR", "the drive or its cable"),
        0x7E => ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "a driver"),
        0x9F => ("DRIVER_POWER_STATE_FAILURE", "a driver that mishandles sleep"),
        0xC2 => ("BAD_POOL_CALLER", "a driver"),
        0xD1 => ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "a driver"),
        0xEF => ("CRITICAL_PROCESS_DIED", "system files or the drive"),
        0xF4 => ("CRITICAL_OBJECT_TERMINATION", "the drive or system files"),
        0x101 => ("CLOCK_WATCHDOG_TIMEOUT", "the processor or firmware"),
        0x116 => ("VIDEO_TDR_FAILURE", "the graphics driver or card"),
        0x124 => ("WHEA_UNCORRECTABLE_ERROR", "hardware: processor, memory or motherboard"),
        0x133 => ("DPC_WATCHDOG_VIOLATION", "a driver, often storage"),
        0x139 => ("KERNEL_SECURITY_CHECK_FAILURE", "a driver or faulty memory"),
        0x154 => ("UNEXPECTED_STORE_EXCEPTION", "the drive"),
        _ => ("", ""),
    }
}

/// "0x0000009f (0x…, 0x…)" → 0x9F.
fn parse_stop(value: &str) -> Option<u32> {
    let token = value.split_whitespace().next()?;
    let hex = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X"))?;
    u32::from_str_radix(hex, 16).ok()
}

/// "name ×3" entries, most frequent first.
fn tally<K: Ord + Clone>(keys: impl Iterator<Item = K>) -> Vec<(K, usize)> {
    let mut counts = std::collections::BTreeMap::new();
    for k in keys {
        *counts.entry(k).or_insert(0usize) += 1;
    }
    let mut out: Vec<(K, usize)> = counts.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

fn is_bugcheck(e: &Event) -> bool {
    e.id == 1001 && (e.provider.contains("WER-SystemErrorReporting") || e.provider.eq_ignore_ascii_case("BugCheck"))
}

pub fn bluescreen_finding(events: &[Event], now: u64) -> Finding {
    let label = format!("Blue screens {}", window());
    let hits: Vec<&Event> = events.iter().filter(|e| is_bugcheck(e)).collect();
    if hits.is_empty() {
        return Finding::ok(label, "none").with_metric(0.0, "", true);
    }
    let last = hits.iter().map(|e| e.time).max().unwrap_or(0);
    let codes = tally(hits.iter().filter_map(|e| parse_stop(&e.value)));
    let described: Vec<String> = codes
        .iter()
        .map(|(code, n)| {
            let (name, cause) = stop_code(*code);
            let times = if *n > 1 { format!(" ×{n}") } else { String::new() };
            if name.is_empty() {
                format!("0x{code:08X}{times}")
            } else {
                format!("0x{code:08X} {name}{times} (usually {cause})")
            }
        })
        .collect();
    let severity = if hits.len() >= 3 { Severity::Critical } else { Severity::Warning };
    Finding::new(label, format!("{} · last {}", hits.len(), since(now, last)), severity)
        .with_detail(described.join("; "))
        .with_metric(hits.len() as f64, "", true)
}

pub fn shutdown_finding(events: &[Event], now: u64) -> Finding {
    let label = format!("Unexpected shutdowns {}", window());
    // Kernel-Power 41 is logged after every unclean stop, a blue screen
    // included; its first value is the stop code, 0 when there wasn't one.
    let power: Vec<&Event> = events
        .iter()
        .filter(|e| e.id == 41 && e.provider.contains("Kernel-Power"))
        .filter(|e| matches!(e.value.trim(), "" | "0"))
        .collect();
    // Older systems only log EventLog 6008 at the next start.
    let legacy: Vec<&Event> = events.iter().filter(|e| e.id == 6008 && e.provider.eq_ignore_ascii_case("EventLog")).collect();
    let any_41 = events.iter().any(|e| e.id == 41 && e.provider.contains("Kernel-Power"));
    let hits = if any_41 || legacy.is_empty() { power } else { legacy };
    if hits.is_empty() {
        return Finding::ok(label, "none").with_metric(0.0, "", true);
    }
    let last = hits.iter().map(|e| e.time).max().unwrap_or(0);
    let severity = if hits.len() >= 5 { Severity::Critical } else { Severity::Warning };
    Finding::new(label, format!("{} · last {}", hits.len(), since(now, last)), severity)
        .with_detail(
            "The PC stopped without shutting down: a power cut, a flat battery, the power button held in, or a freeze so \
             hard that someone had to. Repeats on mains power point at the power supply or overheating.",
        )
        .with_metric(hits.len() as f64, "", true)
}

/// What a storage event means, and whether one alone is serious.
fn storage_event(provider: &str, id: u32) -> Option<(&'static str, bool)> {
    let p = provider.to_ascii_lowercase();
    let storage = matches!(p.as_str(), "disk" | "ntfs" | "volmgr" | "volsnap" | "nvme" | "microsoft-windows-ntfs")
        || p.starts_with("stor")
        || p.starts_with("iastor");
    if !storage {
        return None;
    }
    Some(match (p.as_str(), id) {
        ("disk", 7) => ("bad block", true),
        ("disk", 11) => ("controller error", false),
        ("disk", 51) => ("error while paging", false),
        ("disk", 52) => ("the drive predicts its own failure", true),
        ("disk", 153) => ("an I/O request had to be retried", false),
        ("disk", 157) => ("drive removed unexpectedly", false),
        (_, 55) if p.contains("ntfs") => ("file system corruption", true),
        (_, 129) => ("the drive stopped answering and was reset", false),
        _ => return None,
    })
}

pub fn disk_error_finding(events: &[Event], now: u64) -> Finding {
    let label = format!("Disk errors {}", window());
    let hits: Vec<(&Event, &'static str, bool)> = events
        .iter()
        .filter_map(|e| storage_event(&e.provider, e.id).map(|(what, serious)| (e, what, serious)))
        .collect();
    if hits.is_empty() {
        return Finding::ok(label, "none logged").with_metric(0.0, "", true);
    }
    let last = hits.iter().map(|(e, _, _)| e.time).max().unwrap_or(0);
    let kinds = tally(hits.iter().map(|(e, what, _)| (e.provider.clone(), e.id, *what)));
    let described: Vec<String> = kinds.iter().map(|((provider, id, what), n)| format!("{provider} {id} ×{n} ({what})")).collect();
    let devices = tally(hits.iter().map(|(e, _, _)| e.value.clone()).filter(|v| v.starts_with('\\')));
    let on = devices.first().map(|(d, _)| format!(" Mostly on {d}.")).unwrap_or_default();
    let serious = hits.iter().any(|(_, _, s)| *s) || hits.len() >= 50;
    Finding::new(
        label,
        format!("{} · last {}", hits.len(), since(now, last)),
        if serious { Severity::Critical } else { Severity::Warning },
    )
    .with_detail(format!("{}.{on} Back up the data, then check the drive and its cable.", described.join("; ")))
    .with_metric(hits.len() as f64, "", true)
}

pub fn app_crash_finding(apps: &[AppEvent], now: u64) -> Finding {
    let label = format!("App crashes {}", window());
    let named: Vec<&AppEvent> = apps.iter().filter(|a| !a.app.trim().is_empty()).collect();
    if named.is_empty() {
        return Finding::ok(label, "none logged").with_metric(0.0, "", true);
    }
    struct App<'a> {
        name: &'a str,
        crashes: usize,
        hangs: usize,
        last: i64,
    }
    let mut by_app: Vec<App> = Vec::new();
    for a in &named {
        let name = a.app.trim();
        let entry = match by_app.iter().position(|x| x.name.eq_ignore_ascii_case(name)) {
            Some(i) => &mut by_app[i],
            None => {
                by_app.push(App { name, crashes: 0, hangs: 0, last: 0 });
                by_app.last_mut().expect("just pushed")
            }
        };
        if a.hang {
            entry.hangs += 1;
        } else {
            entry.crashes += 1;
        }
        entry.last = entry.last.max(a.time);
    }
    by_app.sort_by(|a, b| (b.crashes + b.hangs).cmp(&(a.crashes + a.hangs)).then(a.name.cmp(b.name)));
    let crashes: usize = by_app.iter().map(|a| a.crashes).sum();
    let hangs: usize = by_app.iter().map(|a| a.hangs).sum();
    let top: Vec<String> = by_app
        .iter()
        .take(5)
        .map(|a| {
            let what = match (a.crashes, a.hangs) {
                (c, 0) => format!("crashed {c}×"),
                (0, h) => format!("hung {h}×"),
                (c, h) => format!("crashed {c}×, hung {h}×"),
            };
            format!("{} {what}, last {}", a.name, since(now, a.last))
        })
        .collect();
    let more = if by_app.len() > 5 { format!("; and {} more", by_app.len() - 5) } else { String::new() };
    let repeat = by_app.first().is_some_and(|a| a.crashes + a.hangs >= 10);
    let mut bits = Vec::new();
    if crashes > 0 {
        bits.push(format!("{crashes} crash{}", if crashes == 1 { "" } else { "es" }));
    }
    if hangs > 0 {
        bits.push(format!("{hangs} hang{}", plural(hangs)));
    }
    Finding::new(
        label,
        format!("{} across {} app{}", bits.join(" and "), by_app.len(), plural(by_app.len())),
        if repeat { Severity::Warning } else { Severity::Info },
    )
    .with_detail(format!("{}{more}", top.join("; ")))
    .with_metric((crashes + hangs) as f64, "", true)
}

pub fn summary(findings: &[Finding]) -> String {
    let problems: Vec<String> = findings
        .iter()
        .filter(|f| f.severity.rank() >= Severity::Warning.rank())
        .map(|f| format!("{}: {}", f.label.replace(&format!(" {}", window()), ""), f.value.split(" · ").next().unwrap_or("")))
        .collect();
    if problems.is_empty() {
        format!("No failing drives, crashes or disk errors in {DAYS} days")
    } else {
        problems.join(" · ")
    }
}

/// Every finding for a Windows PC, in report order.
pub fn windows_findings(facts: &Facts, now: u64, elevated: bool) -> Vec<Finding> {
    let mut out = drive_findings(&facts.disks, &facts.predicted, &facts.disks_error, elevated);
    out.push(bluescreen_finding(&facts.system, now));
    out.push(shutdown_finding(&facts.system, now));
    out.push(disk_error_finding(&facts.system, now));
    out.push(app_crash_finding(&facts.apps, now));
    out
}

#[cfg(windows)]
mod imp {
    use super::*;

    pub fn check(ctx: &RunContext) -> Result<Output, String> {
        let out = crate::win::ps::run(RELIABILITY, ctx, std::time::Duration::from_secs(180))?;
        let facts: Facts = crate::fixes::json(&out.stdout).map_err(|e| format!("{e} ({})", crate::util::exit_label(out.code)))?;
        let findings = windows_findings(&facts, crate::util::now_epoch(), crate::host::is_elevated());
        Ok(Output::new(summary(&findings), findings))
    }
}

/// Lines of kernel log that mean a drive or file system reported an error.
#[cfg_attr(windows, allow(dead_code))]
pub fn storage_error_lines(kernel_log: &str) -> Vec<&str> {
    const MARKS: [&str; 9] = [
        "i/o error",
        "medium error",
        "ext4-fs error",
        "xfs_do_force_shutdown",
        "metadata i/o error",
        "btrfs error",
        "btrfs: error",
        "failed command:",
        "unrecovered read error",
    ];
    kernel_log
        .lines()
        .map(str::trim)
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            // Loop devices and optical drives produce these in normal use.
            !low.contains("dev loop") && !low.contains("dev sr") && MARKS.iter().any(|m| low.contains(m))
        })
        .collect()
}

/// The programs in `coredumpctl list --no-legend` output, one per crash.
#[cfg_attr(windows, allow(dead_code))]
pub fn coredump_programs(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|l| {
            let fields: Vec<&str> = l.split_whitespace().collect();
            // … PID UID GID SIG COREFILE EXE [SIZE]: the program is the first
            // field that's a path.
            fields.iter().skip(4).find(|f| f.starts_with('/')).map(|exe| exe.rsplit('/').next().unwrap_or(exe).to_string())
        })
        .collect()
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::util::{capture_for, cmd, command_exists};
    use std::time::Duration;

    pub fn check(_ctx: &RunContext) -> Result<Output, String> {
        let elevated = crate::host::is_elevated();
        let now = crate::util::now_epoch();
        let mut findings = drive_findings(&drives(elevated), &[], "no drives under /sys/block", true);
        if !elevated || !command_exists("smartctl") {
            findings.push(Finding::info(
                "Drive health (SMART)",
                if command_exists("smartctl") {
                    "only readable as root: run ITriage with sudo to include it"
                } else {
                    "smartmontools isn't installed, so drive health can't be read"
                },
            ));
        }

        let since = format!("-{DAYS}d");
        let label = format!("Disk errors {}", window());
        if command_exists("journalctl") {
            let mut c = cmd("journalctl");
            c.args(["-k", "-p", "3", "--since", &since, "--no-pager", "-o", "cat"]);
            match capture_for(c, Duration::from_secs(60)) {
                Ok(out) if out.success() => {
                    let lines = storage_error_lines(&out.stdout);
                    findings.push(if lines.is_empty() {
                        Finding::ok(label, "none logged").with_metric(0.0, "", true)
                    } else {
                        let sample: Vec<String> = lines.iter().rev().take(3).map(|l| crate::parse::text::truncate_chars(l, 160)).collect();
                        Finding::new(label, format!("{} in the kernel log", lines.len()), if lines.len() >= 50 { Severity::Critical } else { Severity::Warning })
                            .with_detail(format!("Most recent: {}. Back up the data, then check the drive and its cable.", sample.join(" | ")))
                            .with_metric(lines.len() as f64, "", true)
                    });
                }
                Ok(out) => findings.push(Finding::info(label, format!("couldn't read the kernel log: {}", crate::parse::text::first_line(&out.combined())))),
                Err(e) => findings.push(Finding::info(label, format!("couldn't read the kernel log: {e}"))),
            }
        } else {
            findings.push(Finding::info(label, "no systemd journal to read"));
        }

        if command_exists("coredumpctl") {
            let mut c = cmd("coredumpctl");
            c.args(["list", "--since", &since, "--no-legend", "--no-pager"]);
            // Exits 1 with "No coredumps found" when there are none.
            let listing = capture_for(c, Duration::from_secs(60)).map(|out| out.stdout).unwrap_or_default();
            let apps: Vec<AppEvent> = coredump_programs(&listing).into_iter().map(|app| AppEvent { app, hang: false, time: now as i64 }).collect();
            let mut f = app_crash_finding(&apps, now);
            // coredumpctl's dates are local text; the count is what matters.
            if let Some(d) = f.detail.take() {
                f.detail = Some(d.replace(", last just now", ""));
            }
            findings.push(f);
        }
        Ok(Output::new(summary(&findings), findings))
    }

    /// Physical drives from /sys/block, with SMART health and NVMe wear
    /// when root and smartctl allow.
    fn drives(elevated: bool) -> Vec<Disk> {
        let Ok(rd) = std::fs::read_dir("/sys/block") else {
            return Vec::new();
        };
        let mut names: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !["loop", "ram", "dm-", "zram", "sr", "md", "nbd", "fd"].iter().any(|p| n.starts_with(p)))
            .collect();
        names.sort();
        names
            .into_iter()
            .filter_map(|name| {
                let dir = std::path::Path::new("/sys/block").join(&name);
                let read = |rel: &str| std::fs::read_to_string(dir.join(rel)).ok().map(|s| s.trim().to_string());
                let sectors: u64 = read("size")?.parse().ok()?;
                if sectors == 0 {
                    return None;
                }
                let model = read("device/model").filter(|m| !m.is_empty()).unwrap_or_else(|| name.clone());
                // A virtual disk says "rotational" whatever it's really on.
                let virtual_disk = name.starts_with("vd") || name.starts_with("xvd");
                let mut disk = Disk {
                    name: model,
                    media: match read("queue/rotational").as_deref() {
                        _ if virtual_disk => String::new(),
                        Some("0") => "SSD".into(),
                        Some("1") => "HDD".into(),
                        _ => String::new(),
                    },
                    bus: if name.starts_with("nvme") { "NVMe".into() } else if virtual_disk { "virtual".into() } else { String::new() },
                    size: sectors * 512,
                    ..Disk::default()
                };
                if elevated && command_exists("smartctl") {
                    smart(&format!("/dev/{name}"), &mut disk);
                }
                Some(disk)
            })
            .collect()
    }

    fn smart(device: &str, disk: &mut Disk) {
        let mut c = cmd("smartctl");
        c.args(["-H", "-A", "-j", device]);
        let Ok(out) = capture_for(c, Duration::from_secs(30)) else { return };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&out.stdout) else { return };
        match v.pointer("/smart_status/passed").and_then(|p| p.as_bool()) {
            Some(true) => disk.health = "Healthy".into(),
            Some(false) => disk.health = "Unhealthy".into(),
            None => {}
        }
        let nvme = |key: &str| v.pointer(&format!("/nvme_smart_health_information_log/{key}")).and_then(|x| x.as_u64());
        disk.wear = nvme("percentage_used").map(|w| w as i64);
        disk.read_errors = nvme("media_errors");
        disk.temperature = v.pointer("/temperature/current").and_then(|x| x.as_i64());
        disk.power_on_hours = v.pointer("/power_on_time/hours").and_then(|x| x.as_u64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn ev(provider: &str, id: u32, hours_ago: i64, value: &str) -> Event {
        Event { provider: provider.into(), id, time: NOW as i64 - hours_ago * 3600, value: value.into() }
    }

    #[test]
    fn reads_what_the_script_prints() {
        // One drive arrives as a bare object, the counters as null for a
        // standard user, and no events as empty lists.
        let quiet: Facts = serde_json::from_str(
            r#"{"Disks":{"Name":"SAMSUNG MZVL2512HCJQ","Media":"SSD","Bus":"NVMe","Health":"Healthy","Status":"OK","Size":512110190592,
                "Wear":null,"Temperature":null,"ReadErrors":null,"WriteErrors":null,"PowerOnHours":null},
                "DisksError":"","Predicted":[],"System":[],"Apps":[]}"#,
        )
        .unwrap();
        let findings = windows_findings(&quiet, NOW, false);
        assert_eq!(findings[0].label, "Drive (SAMSUNG MZVL2512HCJQ)");
        assert_eq!(findings[0].value, "healthy · SSD · NVMe · 476.9 GB");
        assert_eq!(findings[1].label, "Drive counters", "a standard user is told why wear is missing");
        assert_eq!(summary(&findings), "No failing drives, crashes or disk errors in 30 days");
        assert!(findings.iter().all(|f| f.severity.rank() <= Severity::Info.rank()));
    }

    #[test]
    fn grades_drives() {
        let disk = |health: &str, wear: Option<i64>| Disk { name: "KINGSTON SA400".into(), health: health.into(), status: "OK".into(), wear, ..Disk::default() };
        let one = |d: Disk| drive_findings(&[d], &[], "", true).remove(0);
        assert_eq!(one(disk("Healthy", Some(12))).severity, Severity::Ok);
        assert_eq!(one(disk("Healthy", Some(12))).metric.unwrap().value, 12.0);
        assert_eq!(one(disk("Healthy", Some(74))).severity, Severity::Warning);
        let worn = one(disk("Healthy", Some(96)));
        assert_eq!(worn.severity, Severity::Critical);
        assert_eq!(worn.value, "96% of its rated life used · healthy", "what's wrong leads the line");
        assert!(worn.detail.unwrap().starts_with("Back up this drive's data and plan to replace it. The drive is at the end"));
        assert_eq!(one(disk("Warning", None)).severity, Severity::Warning);
        let bad = one(disk("Unhealthy", None));
        assert_eq!((bad.severity, bad.value.as_str()), (Severity::Critical, "unhealthy"));
        let errors = one(Disk { read_errors: Some(3), write_errors: Some(0), ..disk("Healthy", Some(5)) });
        assert_eq!(errors.severity, Severity::Warning);
        assert_eq!(errors.value, "3 errors it couldn't correct · healthy · 5% of its rated life used");
        assert!(errors.detail.as_deref().unwrap().contains("3 reading, 0 writing."));
        // A hot drive needs air, not replacing (seen on a CI runner at 72 °C).
        let hot = one(Disk { temperature: Some(72), ..disk("Healthy", Some(0)) });
        assert_eq!((hot.severity, hot.value.as_str()), (Severity::Warning, "running hot at 72 °C · healthy · 0% of its rated life used"));
        assert!(!hot.detail.as_deref().unwrap().contains("replace"), "{:?}", hot.detail);
        assert_eq!(one(Disk { temperature: Some(41), ..disk("Healthy", None) }).value, "healthy · 41 °C");

        let twins = drive_findings(&[disk("Healthy", None), disk("Healthy", None)], &["SCSI\\Disk&Ven_KINGSTON\\4&1".into()], "", true);
        assert_eq!(twins[0].label, "Failure predicted (SMART)");
        assert_eq!(twins[0].severity, Severity::Critical);
        assert_eq!((twins[1].label.as_str(), twins[2].label.as_str()), ("Drive (KINGSTON SA400)", "Drive (KINGSTON SA400) #2"));
        let none = drive_findings(&[], &[], "Access denied", false);
        assert_eq!(none[0].value, "couldn't list them: Access denied");
    }

    #[test]
    fn counts_blue_screens_and_names_the_stop_codes() {
        let events = vec![
            ev("Microsoft-Windows-WER-SystemErrorReporting", 1001, 30, "0x0000009f (0x0000000000000003, 0xffff, 0x0, 0x0)"),
            ev("Microsoft-Windows-WER-SystemErrorReporting", 1001, 200, "0x0000009f (0x3, 0x0, 0x0, 0x0)"),
            ev("Microsoft-Windows-WER-SystemErrorReporting", 1001, 300, "0x00000124 (0x0, 0x0, 0x0, 0x0)"),
            // A blue screen also logs Kernel-Power 41, with its stop code.
            ev("Microsoft-Windows-Kernel-Power", 41, 30, "159"),
            // Windows Error Reporting's own 1001s in other logs don't count.
            ev("Windows Error Reporting", 1001, 5, "APPCRASH"),
        ];
        let f = bluescreen_finding(&events, NOW);
        assert_eq!(f.value, "3 · last 1d ago");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(
            f.detail.as_deref(),
            Some("0x0000009F DRIVER_POWER_STATE_FAILURE ×2 (usually a driver that mishandles sleep); 0x00000124 WHEA_UNCORRECTABLE_ERROR (usually hardware: processor, memory or motherboard)")
        );
        assert_eq!(bluescreen_finding(&events[..1], NOW).severity, Severity::Warning);
        assert_eq!(shutdown_finding(&events, NOW).severity, Severity::Ok, "that 41 was the blue screen, not a power loss");
        assert_eq!(parse_stop("0x00001234"), Some(0x1234));
        assert_eq!(parse_stop("garbage"), None);
    }

    #[test]
    fn counts_power_losses() {
        let mut events = vec![ev("Microsoft-Windows-Kernel-Power", 41, 50, "0"), ev("EventLog", 6008, 49, "x"), ev("Microsoft-Windows-Kernel-Power", 41, 400, "0")];
        let f = shutdown_finding(&events, NOW);
        assert_eq!(f.value, "2 · last 2d ago", "6008 repeats what 41 already said");
        assert_eq!(f.severity, Severity::Warning);
        events.extend((0..3).map(|i| ev("Microsoft-Windows-Kernel-Power", 41, 500 + i, "0")));
        assert_eq!(shutdown_finding(&events, NOW).severity, Severity::Critical);
        let old = [ev("EventLog", 6008, 10, "x")];
        assert_eq!(shutdown_finding(&old, NOW).value, "1 · last 10h ago", "without 41s, 6008 is the evidence");
    }

    #[test]
    fn disk_errors_come_only_from_storage_drivers() {
        let mut events: Vec<Event> = (0..12).map(|i| ev("disk", 153, 2 + i, r"\Device\Harddisk0\DR0")).collect();
        events.push(ev("stornvme", 129, 5, r"\Device\RaidPort0"));
        // Same numbers from other sources: Kerberos 7 and 11 are not disks.
        events.push(ev("Microsoft-Windows-Security-Kerberos", 7, 1, "x"));
        events.push(ev("Microsoft-Windows-Kerberos-Key-Distribution-Center", 11, 1, "x"));
        let f = disk_error_finding(&events, NOW);
        assert_eq!(f.value, "13 · last 2h ago");
        assert_eq!(f.severity, Severity::Warning);
        let detail = f.detail.unwrap();
        assert!(detail.starts_with("disk 153 ×12 (an I/O request had to be retried); stornvme 129 ×1 (the drive stopped answering and was reset). Mostly on \\Device\\Harddisk0\\DR0."), "{detail}");
        events.push(ev("Ntfs", 55, 1, "C:"));
        assert_eq!(disk_error_finding(&events, NOW).severity, Severity::Critical, "corruption is serious on its own");
        assert_eq!(disk_error_finding(&[ev("disk", 7, 1, "")], NOW).severity, Severity::Critical);
        assert_eq!(disk_error_finding(&[], NOW).value, "none logged");
    }

    #[test]
    fn ranks_the_apps_that_crash_most() {
        let app = |name: &str, hang, hours_ago: i64| AppEvent { app: name.into(), hang, time: NOW as i64 - hours_ago * 3600 };
        let mut apps: Vec<AppEvent> = (0..9).map(|i| app("OUTLOOK.EXE", false, 30 + i)).collect();
        apps.push(app("outlook.exe", true, 3));
        apps.push(app("Teams.exe", false, 100));
        apps.push(app("", false, 1));
        let f = app_crash_finding(&apps, NOW);
        assert_eq!(f.value, "10 crashes and 1 hang across 2 apps");
        assert_eq!(f.severity, Severity::Warning, "one app failing ten times is a pattern");
        assert_eq!(f.detail.as_deref(), Some("OUTLOOK.EXE crashed 9×, hung 1×, last 3h ago; Teams.exe crashed 1×, last 4d ago"));
        assert_eq!(app_crash_finding(&apps[9..], NOW).severity, Severity::Info);
        assert_eq!(app_crash_finding(&[], NOW).severity, Severity::Ok);
        let all = windows_findings(&Facts { apps, disks: vec![Disk { name: "x".into(), health: "Healthy".into(), wear: Some(1), ..Disk::default() }], ..Facts::default() }, NOW, true);
        assert_eq!(summary(&all), "App crashes: 10 crashes and 1 hang across 2 apps");
    }

    #[test]
    fn reads_linux_kernel_errors_and_core_dumps() {
        let log = "blk_update_request: I/O error, dev sda, sector 123456 op 0x0:(READ)\n\
                   EXT4-fs error (device sda2): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0\n\
                   blk_update_request: I/O error, dev loop3, sector 0\n\
                   ACPI Error: AE_NOT_FOUND\n\
                   ata1.00: failed command: READ FPDMA QUEUED\n";
        let lines = storage_error_lines(log);
        assert_eq!(lines.len(), 3, "{lines:?}");
        let listing = "Mon 2026-11-02 10:11:12 EST  4242 1000 1000 SIGSEGV present  /usr/bin/gnome-shell  12.3M\n\
                       Tue 2026-11-03 09:00:00 EST   999 1000 1000 SIGABRT missing  /usr/lib/firefox/firefox\n\
                       No coredumps found.\n";
        assert_eq!(coredump_programs(listing), ["gnome-shell", "firefox"]);
    }
}
