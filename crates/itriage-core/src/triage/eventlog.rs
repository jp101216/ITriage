//! Recent critical and error events, grouped. Read-only.
//!
//! Windows: System + Application logs via the Evt* API, grouped by
//! (provider, event ID). Linux: the systemd journal at priority err and
//! above, grouped by source and a number-insensitive form of the message.
//! Each group shows how often it fired, when it last fired, and the newest
//! message.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::text::{first_line, truncate_chars};
use crate::util::{ago, now_epoch, plural};

/// How far back to look.
const HOURS: u32 = 24;
/// Groups shown before the rest are summarised in one line.
const MAX_GROUPS: usize = 12;

pub struct RecentErrors;

impl TriageModule for RecentErrors {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Critical and error events from the System and Application logs in the last 24 hours, grouped by source and event ID."
        } else {
            "Error-level and worse journal entries from the last 24 hours, grouped by source and message."
        };
        ModuleInfo::new("eventlog.errors", "Recent errors", Category::Eventlog, description)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let (groups, notes) = imp::collect(ctx)?;
        Ok(report(groups, notes))
    }
}

/// One group of related events.
struct Group {
    label: String,
    count: usize,
    latest: Option<u64>,
    severity: Severity,
    message: Option<String>,
    note: Option<&'static str>,
}

fn report(mut groups: Vec<Group>, mut notes: Vec<Finding>) -> Output {
    let critical: usize = groups
        .iter()
        .filter(|g| g.severity == Severity::Critical)
        .map(|g| g.count)
        .sum();
    let errors: usize = groups
        .iter()
        .filter(|g| g.severity != Severity::Critical)
        .map(|g| g.count)
        .sum();

    if groups.is_empty() {
        let mut findings = vec![Finding::ok(
            "Last 24 hours",
            "no critical or error events",
        )];
        findings.append(&mut notes);
        return Output::new("No critical or error events in the last 24h.", findings);
    }

    // Worst first, then the noisiest, then the most recent.
    groups.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(b.count.cmp(&a.count))
            .then(b.latest.cmp(&a.latest))
    });

    let now = now_epoch();
    let distinct = groups.len();
    let mut findings: Vec<Finding> = groups
        .iter()
        .take(MAX_GROUPS)
        .map(|g| {
            let when = g
                .latest
                .map(|t| format!("last {}", ago(now.saturating_sub(t))))
                .unwrap_or_else(|| "time unknown".into());
            let mut detail = g
                .message
                .as_deref()
                .map(|m| truncate_chars(first_line(m), 220))
                .unwrap_or_default();
            if let Some(note) = g.note {
                detail = if detail.is_empty() { note.to_string() } else { format!("{detail} ({note})") };
            }
            Finding::new(g.label.clone(), format!("{}× · {when}", g.count), g.severity).with_detail(detail)
        })
        .collect();
    if distinct > MAX_GROUPS {
        let rest = distinct - MAX_GROUPS;
        findings.push(Finding::info("More", format!("{rest} other source{}", plural(rest))));
    }
    findings.append(&mut notes);

    let summary = format!(
        "{critical} critical, {errors} error{} in the last 24h ({distinct} source{})",
        plural(errors),
        plural(distinct)
    );
    Output::new(summary, findings)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::time::iso8601_utc_to_epoch;
    use crate::win::eventlog::recent_errors;
    use std::collections::HashMap;

    /// Per channel cap. A machine with thousands of errors a day still has
    /// only a few distinct sources, and grouping needs counts, not every event.
    const PER_CHANNEL: usize = 1_000;

    pub fn collect(ctx: &RunContext) -> Result<(Vec<Group>, Vec<Finding>), String> {
        let mut groups: Vec<Group> = Vec::new();
        let mut index: HashMap<(&'static str, String, u32), usize> = HashMap::new();
        let mut notes = Vec::new();
        let mut failures = 0;

        for channel in ["System", "Application"] {
            ctx.log(format!("Reading the {channel} log…"));
            let events = match recent_errors(channel, HOURS, PER_CHANNEL) {
                Ok(events) => events,
                Err(e) => {
                    failures += 1;
                    notes.push(Finding::warn(format!("{channel} log"), e));
                    continue;
                }
            };
            for ev in events {
                let s = ev.system;
                let key = (channel, s.provider.clone(), s.event_id);
                let epoch = s.time_created.as_deref().and_then(iso8601_utc_to_epoch);
                if let Some(&i) = index.get(&key) {
                    let g = &mut groups[i];
                    g.count += 1;
                    g.latest = g.latest.max(epoch);
                    continue;
                }
                let (severity, note) = classify(&s.provider, s.event_id, s.level);
                index.insert(key, groups.len());
                groups.push(Group {
                    label: format!("{} {} · {channel}", short_provider(&s.provider), s.event_id),
                    count: 1,
                    latest: epoch,
                    severity,
                    message: ev.message,
                    note,
                });
            }
        }
        if failures == 2 {
            return Err("Couldn't read the System or Application event logs.".into());
        }
        Ok((groups, notes))
    }

    /// Level 1 → Critical, Level 2 → Warning, with known-benign noise downgraded.
    fn classify(provider: &str, id: u32, level: u8) -> (Severity, Option<&'static str>) {
        // DCOM 10016/10010 are documented by Microsoft as expected and safe to ignore.
        if provider.ends_with("DistributedCOM") && (id == 10016 || id == 10010) {
            return (Severity::Info, Some("known DCOM noise, safe to ignore"));
        }
        if level == 1 {
            (Severity::Critical, None)
        } else {
            (Severity::Warning, None)
        }
    }

    fn short_provider(p: &str) -> &str {
        p.strip_prefix("Microsoft-Windows-").unwrap_or(p)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::journal::parse_line;
    use crate::parse::text::normalize_message;
    use crate::util::{capture, cmd, command_exists};
    use std::collections::HashMap;

    pub fn collect(ctx: &RunContext) -> Result<(Vec<Group>, Vec<Finding>), String> {
        if !command_exists("journalctl") {
            return Err("journalctl not found. This check reads the systemd journal.".into());
        }
        ctx.log("Reading the systemd journal…");
        let since = format!("--since=-{HOURS}h");
        let mut c = cmd("journalctl");
        // No --quiet: it would also hide the "you can only see your own
        // journal" hint on stderr, which this module reports.
        c.args([
            "--no-pager",
            "--priority=3",
            since.as_str(),
            "--reverse",
            "--lines=2000",
            "--output=json",
            "--output-fields=PRIORITY,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,_COMM,MESSAGE",
        ])
        .env("LC_ALL", "C");
        let out = capture(c)?;

        let mut groups: Vec<Group> = Vec::new();
        let mut index: HashMap<(String, String), usize> = HashMap::new();
        let mut parsed = 0usize;
        for entry in out.stdout.lines().filter_map(parse_line) {
            parsed += 1;
            let key = (entry.source.clone(), normalize_message(&entry.message));
            if let Some(&i) = index.get(&key) {
                let g = &mut groups[i];
                g.count += 1;
                g.latest = g.latest.max(entry.epoch);
                continue;
            }
            let severity = if entry.priority <= 2 { Severity::Critical } else { Severity::Warning };
            index.insert(key, groups.len());
            groups.push(Group {
                label: entry.source,
                count: 1,
                latest: entry.epoch,
                severity,
                message: Some(entry.message),
                note: None,
            });
        }

        if parsed == 0 && !out.success() {
            return Err(format!("journalctl failed: {}", first_line(&out.combined())));
        }
        // journalctl exits 0 with no output both for "no errors" and for "no
        // journal at all", so before reporting a clean bill of health, check
        // that the journal has anything in it.
        if parsed == 0 && (out.stderr.contains("No journal files were found") || journal_is_empty()) {
            return Err("The systemd journal is empty, so journald isn't recording here (common in containers).".into());
        }

        let mut notes = Vec::new();
        if out.stderr.contains("not seeing messages from other users") {
            notes.push(Finding::info(
                "Partial view",
                "Only your own user's journal is visible. Add yourself to the systemd-journal (or adm) group to see system-wide errors.",
            ));
        }
        Ok((groups, notes))
    }

    /// True when the journal holds no entries at all, at any priority.
    fn journal_is_empty() -> bool {
        let mut c = cmd("journalctl");
        c.args(["--no-pager", "--lines=1", "--output=cat"]).env("LC_ALL", "C");
        capture(c)
            .map(|o| o.stdout.trim().is_empty())
            .unwrap_or(true)
    }
}
