//! Why updates fail. READ-ONLY: it reads Windows Update's own history (the
//! list under Settings → Windows Update → Update history) and contacts
//! nothing.
//!
//! The available-updates scan says what's waiting; this says why something
//! keeps not installing: each update that failed in the last 90 days, how
//! many times, the last error code and what Microsoft says causes it
//! (`parse::wuerror`), and whether it has installed since. When the cause is
//! a damaged component store, the next step is Clean up & check system
//! files.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::wuerror::{self, Cause};
use crate::util::{ago, plural};

pub struct UpdateHistory;

/// How far back failures count.
pub const WINDOW_DAYS: u64 = 90;
/// Failures of one update at which it "keeps failing".
pub const KEEPS_FAILING: usize = 3;
/// Label prefix of a row for an update that hasn't installed since it failed.
pub const FAILING: &str = "Failing update: ";

impl TriageModule for UpdateHistory {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "update.history",
            "Why updates fail",
            Category::Updates,
            "Windows Update installs that failed in the last 90 days: which update, how many times, the last error code and what Microsoft says causes it, and whether it has installed since. Reads the update history; contacts nothing.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        ctx.log("Reading the Windows Update history…");
        let attempts = crate::win::wua::history(1_000)?;
        let rows = findings(&attempts, crate::util::now_epoch());
        Ok(Output::new(summarise(&rows), rows))
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("Windows Update history is Windows-only. On Linux, the package manager's own log (/var/log/apt/history.log, dnf history) has it.".into())
    }
}

/// One install attempt from the history, as plain data.
#[derive(Debug, Clone, PartialEq)]
pub struct Attempt {
    pub epoch: u64,
    pub title: String,
    /// The update's identity (a GUID); empty when Windows didn't record one.
    pub update_id: String,
    pub succeeded: bool,
    /// The HRESULT, or Windows Update's unmapped code when that's all it gave.
    pub code: u32,
}

/// "KB5046617" from a title such as "2026-11 Cumulative Update for
/// Windows 11 Version 24H2 for x64-based Systems (KB5046617)".
pub fn kb_of(title: &str) -> Option<String> {
    let bytes = title.as_bytes();
    let mut i = 0;
    while let Some(at) = title[i..].find("KB") {
        let start = i + at;
        let digits: String = title[start + 2..].chars().take_while(|c| c.is_ascii_digit()).collect();
        let boundary = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        if boundary && (6..=8).contains(&digits.len()) {
            return Some(format!("KB{digits}"));
        }
        i = start + 2;
    }
    None
}

/// One update's history: what it's called, its failures and its last success.
#[derive(Debug)]
struct Group<'a> {
    key: String,
    title: &'a str,
    failures: Vec<&'a Attempt>,
    last_success: Option<u64>,
}

impl Group<'_> {
    fn last_failure(&self) -> Option<&Attempt> {
        self.failures.iter().copied().max_by_key(|a| a.epoch)
    }
    /// It failed, and hasn't installed since.
    fn unresolved(&self) -> bool {
        match (self.last_failure(), self.last_success) {
            (Some(f), Some(s)) => f.epoch > s,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// Group the window's attempts by update: by KB number when the title has
/// one (definition updates get a new identity with each version), else by
/// identity, else by title.
fn groups(attempts: &[Attempt], since: u64) -> Vec<Group<'_>> {
    let mut out: Vec<Group> = Vec::new();
    for a in attempts.iter().filter(|a| a.epoch >= since) {
        let key = kb_of(&a.title).unwrap_or_else(|| if a.update_id.is_empty() { a.title.clone() } else { a.update_id.clone() });
        let at = match out.iter().position(|g| g.key == key) {
            Some(i) => i,
            None => {
                out.push(Group { key, title: &a.title, failures: Vec::new(), last_success: None });
                out.len() - 1
            }
        };
        let g = &mut out[at];
        if a.succeeded {
            g.last_success = Some(g.last_success.map_or(a.epoch, |s| s.max(a.epoch)));
        } else {
            g.failures.push(a);
        }
    }
    out
}

fn times(n: usize) -> String {
    match n {
        1 => "once".into(),
        2 => "twice".into(),
        n => format!("{n} times"),
    }
}

pub fn findings(attempts: &[Attempt], now: u64) -> Vec<Finding> {
    let since = now.saturating_sub(WINDOW_DAYS * 86_400);
    let in_window: Vec<&Attempt> = attempts.iter().filter(|a| a.epoch >= since).collect();
    let installed = in_window.iter().filter(|a| a.succeeded).count();
    let failed = in_window.len() - installed;
    let mut out = vec![Finding::new(
        "Installs in the last 90 days",
        format!("{installed} installed · {failed} failed"),
        if failed == 0 { Severity::Ok } else { Severity::Info },
    )];
    if in_window.is_empty() {
        out[0] = Finding::info("Installs in the last 90 days", "none recorded").with_detail(
            "Windows Update's history is empty for this period. It may have been cleared (the SoftwareDistribution folder was reset), or updates come from somewhere that doesn't record here.",
        );
        return out;
    }

    let all = groups(attempts, since);
    let mut failing: Vec<&Group> = all.iter().filter(|g| g.unresolved()).collect();
    failing.sort_by_key(|g| (std::cmp::Reverse(g.failures.len()), std::cmp::Reverse(g.last_failure().map_or(0, |f| f.epoch))));
    for g in &failing {
        let last = g.last_failure().expect("unresolved groups have a failure");
        let n = g.failures.len();
        let known = wuerror::lookup(last.code);
        let codes: Vec<u32> = {
            let mut c: Vec<u32> = g.failures.iter().map(|a| a.code).collect();
            c.sort_unstable();
            c.dedup();
            c
        };
        let mut detail = format!("{}. Last error {}.", g.title.trim_end_matches('.'), wuerror::describe(last.code));
        if codes.len() > 1 {
            detail.push_str(&format!(" Earlier attempts: {}.", codes.iter().filter(|c| **c != last.code).map(|c| wuerror::hex(*c)).collect::<Vec<_>>().join(", ")));
        }
        if g.last_success.is_some() {
            detail.push_str(" It installed once before in this period and has failed since.");
        }
        let next = known.map(|k| k.cause.next()).unwrap_or(Cause::Other.next());
        detail.push_str(&format!(" Next: {next}"));
        out.push(
            Finding::new(
                format!("{FAILING}{}", if g.key.starts_with("KB") { g.key.as_str() } else { "(no KB number)" }),
                format!("failed {} · last {} · {}", times(n), ago(now.saturating_sub(last.epoch)), wuerror::hex(last.code)),
                if n >= KEEPS_FAILING { Severity::Critical } else { Severity::Warning },
            )
            .with_detail(detail)
            .with_metric(n as f64, "failures", true),
        );
    }

    let recovered: Vec<&str> = all.iter().filter(|g| !g.failures.is_empty() && !g.unresolved()).map(|g| g.key.as_str()).collect();
    if !recovered.is_empty() {
        out.push(
            Finding::info("Failed, then installed", recovered.iter().map(|k| if k.starts_with("KB") { *k } else { "an update" }).collect::<Vec<_>>().join(", "))
                .with_detail("These failed at least once in the last 90 days and have installed since, so nothing is left to do for them."),
        );
    }
    if failing.is_empty() {
        out.push(Finding::ok("Failing updates", "none: everything that failed has installed since"));
    }
    out
}

pub fn summarise(rows: &[Finding]) -> String {
    let failing: Vec<&Finding> = rows.iter().filter(|f| f.label.starts_with(FAILING)).collect();
    match failing.as_slice() {
        [] if rows.iter().any(|f| f.value == "none recorded") => "No update installs recorded in 90 days".into(),
        [] => "No failing updates".into(),
        [one] => {
            let kb = one.label.trim_start_matches(FAILING);
            let code = one.value.rsplit(" · ").next().unwrap_or_default();
            if one.severity == Severity::Critical {
                format!("{kb} keeps failing ({code})")
            } else {
                format!("{kb} failed ({code})")
            }
        }
        many => format!("{} update{} failing", many.len(), plural(many.len())),
    }
}

/// The cause behind a failing-update row, from the code at the end of its value.
pub fn cause_of(f: &Finding) -> Option<Cause> {
    let code = f.value.rsplit(" · ").next()?.strip_prefix("0x")?;
    wuerror::lookup(u32::from_str_radix(code, 16).ok()?).map(|k| k.cause)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_795_000_000;
    const DAY: u64 = 86_400;

    fn a(days_ago: u64, title: &str, ok: bool, code: u32) -> Attempt {
        Attempt { epoch: NOW - days_ago * DAY, title: title.into(), update_id: format!("id-{title}"), succeeded: ok, code }
    }

    const CU: &str = "2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617)";
    const NET: &str = "2026-11 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2 for x64 (KB5046540)";
    const DEF: &str = "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.421.1023.0) - Current Channel (Broad)";

    #[test]
    fn reads_kb_numbers_from_titles() {
        assert_eq!(kb_of(CU).as_deref(), Some("KB5046617"));
        assert_eq!(kb_of(DEF).as_deref(), Some("KB2267602"));
        assert_eq!(kb_of("Intel - System - 10.1.1.44"), None);
        assert_eq!(kb_of("WKB1234567 (KB12)"), None, "not a KB number");
    }

    #[test]
    fn an_update_that_keeps_failing_is_critical_with_its_cause() {
        let history = [
            a(1, CU, false, 0x800F_081F),
            a(3, CU, false, 0x800F_081F),
            a(6, CU, false, 0x8007_0020),
            a(2, NET, true, 0),
            a(30, "Old one (KB5040000)", false, 0x800F_081F),
            a(200, "Too old (KB5010000)", false, 0x800F_081F),
        ];
        let rows = findings(&history, NOW);
        let get = |l: &str| rows.iter().find(|f| f.label == l).unwrap_or_else(|| panic!("{l}: {rows:#?}"));
        assert_eq!(get("Installs in the last 90 days").value, "1 installed · 4 failed");
        let cu = get("Failing update: KB5046617");
        assert_eq!((cu.value.as_str(), cu.severity), ("failed 3 times · last 1d ago · 0x800F081F", Severity::Critical));
        let detail = cu.detail.as_deref().unwrap();
        assert!(detail.starts_with("2026-11 Cumulative Update for Windows 11"), "{detail}");
        assert!(detail.contains("CBS_E_SOURCE_MISSING") && detail.contains("Earlier attempts: 0x80070020"), "{detail}");
        assert!(detail.contains("Clean up & check system files"), "{detail}");
        assert_eq!(cause_of(cu), Some(Cause::Corruption));
        assert_eq!(get("Failing update: KB5040000").severity, Severity::Warning, "once is a warning");
        assert!(rows.iter().all(|f| !f.label.contains("KB5010000")), "outside 90 days");
        assert_eq!(summarise(&rows), "2 updates failing");
        // The failing ones come first, most failures first.
        let order: Vec<&str> = rows.iter().map(|f| f.label.as_str()).collect();
        assert!(order.iter().position(|l| l.ends_with("KB5046617")) < order.iter().position(|l| l.ends_with("KB5040000")));
    }

    #[test]
    fn a_failure_that_installed_later_is_resolved() {
        let history = [a(5, CU, false, 0x8024_402C), a(4, CU, false, 0x8024_402C), a(2, CU, true, 0)];
        let rows = findings(&history, NOW);
        assert!(rows.iter().all(|f| !f.label.starts_with(FAILING)), "{rows:#?}");
        assert_eq!(rows.iter().find(|f| f.label == "Failed, then installed").unwrap().value, "KB5046617");
        assert_eq!(summarise(&rows), "No failing updates");
        assert!(rows.iter().all(|f| f.severity.rank() < Severity::Warning.rank()));
    }

    #[test]
    fn failing_again_after_installing_counts() {
        // Definition updates share a KB number from version to version.
        let history = [a(10, DEF, true, 0), a(1, DEF, false, 0x8024_0022)];
        let rows = findings(&history, NOW);
        let row = rows.iter().find(|f| f.label == "Failing update: KB2267602").unwrap();
        assert_eq!(row.severity, Severity::Warning);
        assert!(row.detail.as_deref().unwrap().contains("installed once before"));
        assert_eq!(cause_of(row), Some(Cause::Blocked));
        assert_eq!(summarise(&rows), "KB2267602 failed (0x80240022)");
    }

    #[test]
    fn unknown_codes_and_updates_without_a_kb() {
        let driver = Attempt { epoch: NOW - DAY, title: "Intel - Display - 31.0.101.5590".into(), update_id: "abc".into(), succeeded: false, code: 0x8000_4005 };
        let rows = findings(&[driver.clone(), Attempt { epoch: NOW - 2 * DAY, ..driver }], NOW);
        let row = rows.iter().find(|f| f.label.starts_with(FAILING)).unwrap();
        assert_eq!(row.label, "Failing update: (no KB number)");
        assert!(row.detail.as_deref().unwrap().contains("Last error 0x80004005."), "no guess at an unknown code");
        assert_eq!(cause_of(row), None);
    }

    #[test]
    fn an_empty_history_says_so() {
        let rows = findings(&[], NOW);
        assert_eq!((rows[0].value.as_str(), rows.len()), ("none recorded", 1));
        assert_eq!(summarise(&rows), "No update installs recorded in 90 days");
        let clean = findings(&[a(3, CU, true, 0)], NOW);
        assert_eq!(clean[0].severity, Severity::Ok);
        assert_eq!(summarise(&clean), "No failing updates");
    }
}
