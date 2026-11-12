//! "Why won't this app run?" Read-only.
//!
//! `sec.posture` says whether Defender and the firewall are on. This names
//! the one rule that stopped a program, a plugin or a save in the last
//! seven days: an attack surface reduction (ASR) rule, Controlled folder
//! access, an antivirus detection, AppLocker or App Control for Business
//! (WDAC) on Windows; AppArmor or SELinux on Linux. Blocks of one rule on
//! one file are folded into one row, with how many times and when.
//!
//! An audit-mode rule only records what it would have blocked, so those
//! rows are information: nothing was stopped.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::blocks::{group, names_app, BlockGroup, PolicyEvent};
use crate::parse::time::epoch_to_rfc3339;
use crate::util::{ago, now_epoch, plural};

/// Seven days, the same window as the change timeline.
pub const WINDOW_SECS: u64 = 7 * 86_400;
/// Rows shown before the rest are counted.
const MAX_ROWS: usize = 30;

pub struct PolicyBlocks;

impl TriageModule for PolicyBlocks {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Which security rule stopped a program, plugin or save in the last 7 days: Defender ASR rules, Controlled folder access, antivirus detections, AppLocker and App Control (WDAC)."
        } else {
            "Which security rule stopped a program or file access in the last 7 days: AppArmor and SELinux denials."
        };
        ModuleInfo::new("sec.blocks", "Policy blocks", Category::Security, description)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let (events, gaps) = collect();
        let apps: Vec<String> = ctx.profile().require.app.iter().map(|a| a.name.clone()).collect();
        let now = now_epoch();
        let recent: Vec<PolicyEvent> = events.into_iter().filter(|e| e.epoch + WINDOW_SECS >= now).collect();
        let groups = group(&recent);
        let mut out = findings(&groups, now, &apps);
        out.extend(gaps.into_iter().map(|g| Finding::info("Coverage", g)));
        let blocked = groups.iter().filter(|g| g.enforced).count();
        let summary = match (groups.len(), blocked) {
            (0, _) => "No policy blocks in the last 7 days".to_string(),
            (_, 0) => format!("Nothing blocked; {} rule{} in audit mode recorded activity", groups.len(), plural(groups.len())),
            (_, b) => format!("{b} program{} or file{} blocked by policy in the last 7 days", plural(b), plural(b)),
        };
        Ok(Output::new(summary, out))
    }
}

fn times(n: usize) -> String {
    match n {
        1 => "once".into(),
        2 => "twice".into(),
        n => format!("{n} times"),
    }
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(max - 1).collect::<String>().trim_end())
    }
}

/// The label a row keeps from run to run (so `--compare` and `--trends`
/// match it): where, which rule, which file.
pub fn label(g: &BlockGroup) -> String {
    format!("{}: {} · {}", g.source, clip(&g.rule, 90), g.file_name())
}

/// The rows for folded blocks, newest enforced ones first. A block in the
/// last day on a program the site requires is critical: that's the call.
pub fn findings(groups: &[BlockGroup], now: u64, required_apps: &[String]) -> Vec<Finding> {
    if groups.is_empty() {
        return vec![Finding::ok("Policy blocks", "none recorded in the last 7 days")];
    }
    let mut out = Vec::new();
    for g in groups.iter().take(MAX_ROWS) {
        let app = required_apps
            .iter()
            .find(|a| names_app(&g.path, a) || names_app(&g.process, a));
        let today = now.saturating_sub(g.last) <= 86_400;
        let severity = match (g.enforced, today && app.is_some()) {
            (true, true) => Severity::Critical,
            (true, false) => Severity::Warning,
            (false, _) => Severity::Info,
        };
        let value = if g.enforced {
            format!("blocked {} · last {}", times(g.count), ago(now.saturating_sub(g.last)))
        } else {
            format!("audit mode: would have blocked it {} · last {}", times(g.count), ago(now.saturating_sub(g.last)))
        };
        let mut detail = vec![];
        if !g.path.is_empty() {
            detail.push(format!("Blocked: {}", g.path));
        }
        if !g.process.is_empty() && g.process != g.path {
            detail.push(format!("Started by: {}", g.process));
        }
        if !g.user.is_empty() {
            detail.push(format!("Account: {}", g.user));
        }
        detail.push(if g.first == g.last {
            format!("At {} UTC", epoch_to_rfc3339(g.last))
        } else {
            format!("First {} · last {} UTC", epoch_to_rfc3339(g.first), epoch_to_rfc3339(g.last))
        });
        if let Some(a) = app {
            detail.push(format!("This is the site's required app {a}."));
        }
        detail.push(match g.source {
            crate::parse::blocks::ASR | crate::parse::blocks::FOLDERS => "If it's legitimate, ask security for an exclusion; don't turn the rule off.",
            crate::parse::blocks::APPLOCKER | crate::parse::blocks::APP_CONTROL => "If it's legitimate, it needs an allow rule in the policy.",
            crate::parse::blocks::ANTIVIRUS => "Check the detection in the Defender portal before restoring anything.",
            _ => "If it's legitimate, the profile needs a rule for it.",
        }.to_string());
        out.push(
            Finding::new(label(g), value, severity)
                .with_detail(detail.join(" · "))
                .with_metric(g.count as f64, "blocks", true),
        );
    }
    if groups.len() > MAX_ROWS {
        out.push(Finding::info("More blocks", format!("{} more rule-and-file pairs, oldest left out", groups.len() - MAX_ROWS)));
    }
    out
}

#[cfg(windows)]
fn collect() -> (Vec<PolicyEvent>, Vec<String>) {
    // Each one of ITriage's own fixed queries: the last seven days.
    const SOURCES: &[(&str, &str, &str)] = &[
        (
            "Microsoft-Windows-Windows Defender/Operational",
            "*[System[(EventID=1116 or EventID=1117 or EventID=1121 or EventID=1122 or EventID=1123 or EventID=1124) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            "Defender",
        ),
        (
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "*[System[(EventID=8003 or EventID=8004) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            "AppLocker (programs)",
        ),
        (
            "Microsoft-Windows-AppLocker/MSI and Script",
            "*[System[(EventID=8006 or EventID=8007) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            "AppLocker (installers and scripts)",
        ),
        (
            "Microsoft-Windows-CodeIntegrity/Operational",
            "*[System[(EventID=3076 or EventID=3077) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",
            "App Control",
        ),
    ];
    let mut events = Vec::new();
    let mut gaps = Vec::new();
    for (channel, query, name) in SOURCES {
        match crate::win::eventlog::query_xml(channel, query, 300) {
            Ok(rows) => events.extend(rows.iter().filter_map(|x| crate::parse::blocks::from_event(x))),
            Err(_) => gaps.push(format!("The {name} log couldn't be read here; that policy may not be in use, or reading it needs administrator rights.")),
        }
    }
    gaps.push("Up to 300 events from each log. A block shows here only if the policy logs it, and a third-party antivirus or app-control product keeps its own records.".into());
    (events, gaps)
}

#[cfg(not(windows))]
fn collect() -> (Vec<PolicyEvent>, Vec<String>) {
    use crate::parse::blocks::from_audit_line;
    use crate::util::{capture_for, cmd, command_exists};
    let mut events = Vec::new();
    let mut gaps = Vec::new();
    if command_exists("journalctl") {
        let mut c = cmd("journalctl");
        c.args(["--since", "7 days ago", "--no-pager", "-o", "json", "-n", "5000", "_TRANSPORT=audit", "+", "_TRANSPORT=kernel"])
            .env("LC_ALL", "C");
        match capture_for(c, std::time::Duration::from_secs(10)) {
            Ok(out) => {
                for line in out.stdout.lines() {
                    let Some(entry) = crate::parse::journal::parse_line(line).or_else(|| loose_entry(line)) else {
                        continue;
                    };
                    if let (Some(epoch), true) = (entry.epoch, entry.message.contains("apparmor=") || entry.message.contains("avc:")) {
                        events.extend(from_audit_line(&entry.message, epoch));
                    }
                }
            }
            Err(e) => gaps.push(format!("The kernel and audit journal couldn't be read: {e}")),
        }
    } else {
        gaps.push("journalctl isn't available, so AppArmor and SELinux denials weren't read.".into());
    }
    // With auditd running, SELinux denials go to its log instead (root only).
    match std::fs::read("/var/log/audit/audit.log") {
        Ok(bytes) => {
            let tail = &bytes[bytes.len().saturating_sub(4 * 1024 * 1024)..];
            for line in String::from_utf8_lossy(tail).lines() {
                if let Some(epoch) = audit_log_epoch(line) {
                    events.extend(from_audit_line(line, epoch));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            gaps.push("The audit log (/var/log/audit/audit.log) needs root to read; SELinux denials recorded only there aren't included.".into())
        }
        Err(_) => {}
    }
    gaps.push("The last 5,000 kernel and audit journal entries of the week. Journal access may need the adm or systemd-journal group.".into());
    (events, gaps)
}

/// A journal entry without a PRIORITY field (audit records often lack one).
#[cfg(not(windows))]
fn loose_entry(line: &str) -> Option<crate::parse::journal::JournalEntry> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(crate::parse::journal::JournalEntry {
        priority: 6,
        source: String::new(),
        message: v.get("MESSAGE")?.as_str()?.to_string(),
        epoch: v.get("__REALTIME_TIMESTAMP")?.as_str()?.parse::<u64>().ok().map(|us| us / 1_000_000),
    })
}

/// `type=AVC msg=audit(1794600000.512:90): …` → 1794600000.
#[cfg_attr(windows, allow(dead_code))]
fn audit_log_epoch(line: &str) -> Option<u64> {
    let start = line.find("audit(")? + "audit(".len();
    line[start..].split(['.', ':']).next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::blocks::{ANTIVIRUS, ASR, SELINUX};

    fn g(source: &'static str, enforced: bool, path: &str, count: usize, last: u64) -> BlockGroup {
        BlockGroup {
            source,
            rule: "Block all Office applications from creating child processes".into(),
            path: path.into(),
            process: r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE".into(),
            user: r"CORP\jparker".into(),
            enforced,
            count,
            first: last - 600,
            last,
        }
    }

    #[test]
    fn a_block_today_on_a_required_app_is_critical() {
        let now = 1_794_600_000;
        let rows = findings(
            &[
                g(ASR, true, r"C:\Program Files (x86)\Nuance\Dragon\natspeak.exe", 3, now - 3_600),
                g(ANTIVIRUS, true, r"C:\Users\jparker\Downloads\tool.exe", 1, now - 3 * 86_400),
                g(ASR, false, r"C:\Temp\macro.js", 2, now - 60),
            ],
            now,
            &["Dragon Medical One".to_string()],
        );
        assert_eq!(rows[0].severity, Severity::Critical);
        assert_eq!(rows[0].label, "ASR rule: Block all Office applications from creating child processes · natspeak.exe");
        assert_eq!(rows[0].value, "blocked 3 times · last 1h ago");
        assert!(rows[0].detail.as_deref().unwrap().contains("required app Dragon Medical One"));
        assert_eq!(rows[0].metric.as_ref().unwrap().value, 3.0);
        assert_eq!(rows[1].severity, Severity::Warning, "blocked, but not a required app");
        assert_eq!(rows[2].severity, Severity::Info, "audit mode stopped nothing");
        assert!(rows[2].value.starts_with("audit mode: would have blocked it twice"));
        // A required app blocked last week isn't today's call.
        let old = findings(&[g(ASR, true, r"C:\Nuance\Dragon\natspeak.exe", 1, now - 2 * 86_400)], now, &["Dragon".to_string()]);
        assert_eq!(old[0].severity, Severity::Warning);
    }

    #[test]
    fn labels_stay_the_same_from_run_to_run_and_nothing_is_ok() {
        let now = 1_794_600_000;
        let a = findings(&[g(SELINUX, true, "/var/www/index.html", 1, now - 10)], now, &[]);
        let b = findings(&[g(SELINUX, true, "/var/www/index.html", 9, now - 5)], now, &[]);
        assert_eq!(a[0].label, b[0].label, "the count and time live in the value");
        assert_eq!(findings(&[], now, &[])[0].severity, Severity::Ok);
        let many: Vec<BlockGroup> = (0..35).map(|i| g(ASR, true, &format!(r"C:\x{i}.exe"), 1, now - i)).collect();
        let rows = findings(&many, now, &[]);
        assert_eq!(rows.len(), MAX_ROWS + 1);
        assert_eq!(rows.last().unwrap().value, "5 more rule-and-file pairs, oldest left out");
    }

    #[test]
    fn reads_the_time_from_an_audit_log_line() {
        assert_eq!(audit_log_epoch("type=AVC msg=audit(1794600000.512:90): avc:  denied"), Some(1_794_600_000));
        assert_eq!(audit_log_epoch("no time here"), None);
    }
}
