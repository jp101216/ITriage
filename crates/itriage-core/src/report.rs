//! Saved run reports: the history behind "what changed since last time", and
//! the format of the JSON a technician exports, opens or receives from a
//! remote run.

use crate::host::HostContext;
use crate::model::{ModuleResult, Severity};
use crate::parse::time::epoch_to_rfc3339;
use crate::util::now_epoch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Current report format version.
pub const SCHEMA: u32 = 1;
/// Saved runs kept in the history folder.
const KEEP: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    #[serde(default = "schema_default")]
    pub schema: u32,
    /// RFC 3339 UTC.
    pub generated: String,
    pub host: HostContext,
    /// Name of the site profile in force.
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub cancelled: bool,
    pub results: Vec<ModuleResult>,
}

fn schema_default() -> u32 {
    SCHEMA
}

impl Report {
    pub fn new(host: HostContext, profile: Option<String>, results: Vec<ModuleResult>, cancelled: bool) -> Self {
        Self {
            schema: SCHEMA,
            generated: epoch_to_rfc3339(now_epoch()),
            host,
            profile,
            cancelled,
            results,
        }
    }

    pub fn worst(&self) -> Severity {
        self.results
            .iter()
            .map(|r| r.status())
            .max_by_key(|s| s.rank())
            .unwrap_or(Severity::Ok)
    }
}

/// A saved report, as listed in the history panel.
#[derive(Debug, Clone, Serialize)]
pub struct ReportMeta {
    pub path: String,
    pub generated: String,
    pub hostname: String,
    pub modules: usize,
    pub worst: Severity,
    pub cancelled: bool,
}

pub fn history_dir() -> Option<PathBuf> {
    crate::paths::data_dir().map(|d| d.join("history"))
}

/// Save a report to the history folder and prune old ones. Returns its path.
pub fn save(report: &Report) -> Result<PathBuf, String> {
    let dir = history_dir().ok_or("No folder for run history on this system.")?;
    save_in(&dir, report)
}

fn save_in(dir: &Path, report: &Report) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("Can't create {}: {e}", dir.display()))?;
    let stamp = report.generated.replace([':', '-'], "");
    let host: String = report
        .host
        .hostname
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
        .collect();
    let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    // Two runs in the same second must not overwrite each other, but saving
    // the same report again (re-importing it) shouldn't duplicate it.
    let mut path = dir.join(format!("{stamp}_{host}.json"));
    let mut n = 1;
    while path.exists() {
        if std::fs::read_to_string(&path).is_ok_and(|old| old == json) {
            return Ok(path);
        }
        n += 1;
        path = dir.join(format!("{stamp}_{host}~{n}.json"));
    }
    std::fs::write(&path, json).map_err(|e| format!("Can't write {}: {e}", path.display()))?;
    prune(dir);
    Ok(path)
}

fn prune(dir: &Path) {
    let mut files = json_files(dir);
    if files.len() <= KEEP {
        return;
    }
    files.sort(); // names start with the timestamp, so this is oldest first
    for old in &files[..files.len() - KEEP] {
        let _ = std::fs::remove_file(old);
    }
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect()
        })
        .unwrap_or_default()
}

/// Saved runs, newest first.
pub fn list() -> Vec<ReportMeta> {
    let Some(dir) = history_dir() else {
        return Vec::new();
    };
    let mut metas: Vec<ReportMeta> = json_files(&dir)
        .into_iter()
        .filter_map(|p| {
            let r = load(&p).ok()?;
            Some(ReportMeta {
                path: p.display().to_string(),
                generated: r.generated.clone(),
                hostname: r.host.hostname.clone(),
                modules: r.results.len(),
                worst: r.worst(),
                cancelled: r.cancelled,
            })
        })
        .collect();
    metas.sort_by(|a, b| b.generated.cmp(&a.generated));
    metas
}

pub fn load(path: &Path) -> Result<Report, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("Can't read {}: {e}", path.display()))?;
    parse(&text)
}

/// Parse report JSON (from history, an export, or a remote run).
pub fn parse(text: &str) -> Result<Report, String> {
    serde_json::from_str(text).map_err(|e| format!("Not an itriage report: {e}"))
}

/// The most recent saved run for this host from before `generated`.
pub fn previous(hostname: &str, generated: &str) -> Option<Report> {
    list()
        .into_iter()
        .filter(|m| m.hostname == hostname && m.generated.as_str() < generated && !m.cancelled)
        .find_map(|m| load(Path::new(&m.path)).ok())
}

// ------------------------------------------------------------------ diff

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// A problem that wasn't there before.
    New,
    /// A problem that's gone.
    Resolved,
    /// Same item, different severity.
    Changed,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub module_id: String,
    pub module: String,
    pub label: String,
    pub kind: ChangeKind,
    pub before: Option<Severity>,
    pub after: Option<Severity>,
    /// The current value (or the last known one, for resolved items).
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportDiff {
    /// When the older report was generated.
    pub against: String,
    pub new_issues: usize,
    pub resolved: usize,
    pub changed: usize,
    pub changes: Vec<Change>,
}

fn is_problem(s: Severity) -> bool {
    s.rank() >= Severity::Warning.rank()
}

/// What changed between two runs. Only problems (warning and above) count,
/// so values that always move, like uptime, don't create noise. Only modules
/// that ran both times are compared.
pub fn diff(old: &Report, new: &Report) -> ReportDiff {
    const ERROR_LABEL: &str = "Module couldn't run";
    let mut changes = Vec::new();
    let old_by_module: HashMap<&str, &ModuleResult> =
        old.results.iter().map(|r| (r.module_id.as_str(), r)).collect();

    for n in &new.results {
        let Some(o) = old_by_module.get(n.module_id.as_str()) else {
            continue;
        };
        let change = |label: &str, kind, before, after, value: &str| Change {
            module_id: n.module_id.clone(),
            module: n.title.clone(),
            label: label.to_string(),
            kind,
            before,
            after,
            value: value.to_string(),
        };

        match (&o.error, &n.error) {
            (None, Some(e)) => changes.push(change(ERROR_LABEL, ChangeKind::New, None, Some(Severity::Critical), e)),
            (Some(e), None) => changes.push(change(ERROR_LABEL, ChangeKind::Resolved, Some(Severity::Critical), None, e)),
            _ => {}
        }

        let before: HashMap<&str, (Severity, &str)> = o
            .findings
            .iter()
            .map(|f| (f.label.as_str(), (f.severity, f.value.as_str())))
            .collect();
        let after: HashMap<&str, (Severity, &str)> = n
            .findings
            .iter()
            .map(|f| (f.label.as_str(), (f.severity, f.value.as_str())))
            .collect();

        for f in &n.findings {
            match before.get(f.label.as_str()) {
                None if is_problem(f.severity) => {
                    changes.push(change(&f.label, ChangeKind::New, None, Some(f.severity), &f.value))
                }
                Some((was, _)) if *was != f.severity && (is_problem(*was) || is_problem(f.severity)) => {
                    let kind = if !is_problem(*was) { ChangeKind::New } else if !is_problem(f.severity) { ChangeKind::Resolved } else { ChangeKind::Changed };
                    changes.push(change(&f.label, kind, Some(*was), Some(f.severity), &f.value))
                }
                _ => {}
            }
        }
        for f in &o.findings {
            if is_problem(f.severity) && !after.contains_key(f.label.as_str()) {
                changes.push(change(&f.label, ChangeKind::Resolved, Some(f.severity), None, &f.value));
            }
        }
    }

    let count = |k| changes.iter().filter(|c| c.kind == k).count();
    ReportDiff {
        against: old.generated.clone(),
        new_issues: count(ChangeKind::New),
        resolved: count(ChangeKind::Resolved),
        changed: count(ChangeKind::Changed),
        changes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Finding};

    fn host() -> HostContext {
        HostContext {
            hostname: "WS-1".into(),
            os: "Windows 11".into(),
            platform: "windows".into(),
            elevated: false,
            can_relaunch_elevated: true,
            elevation_note: String::new(),
        }
    }

    fn result(id: &str, findings: Vec<Finding>, error: Option<&str>) -> ModuleResult {
        ModuleResult {
            module_id: id.into(),
            title: id.into(),
            category: Category::System,
            findings,
            summary: String::new(),
            error: error.map(str::to_string),
            duration_ms: 1,
        }
    }

    fn report(results: Vec<ModuleResult>) -> Report {
        Report::new(host(), None, results, false)
    }

    #[test]
    fn finds_new_resolved_and_changed_problems() {
        let old = report(vec![
            result("proc.services", vec![
                Finding::ok("Running services", "180"),
                Finding::warn("Windows Search (WSearch)", "stopped"),
                Finding::warn("Print Spooler (Spooler)", "stopped"),
            ], None),
            result("system.disk", vec![Finding::warn("C:\\", "90% used")], None),
        ]);
        let new = report(vec![
            result("proc.services", vec![
                Finding::ok("Running services", "187"),
                Finding::crit("Print Spooler (Spooler)", "exit 1067"),
                Finding::warn("Windows Defender Firewall (mpssvc)", "stopped"),
            ], None),
            result("system.disk", vec![Finding::warn("C:\\", "91% used")], None),
            result("desk.time", vec![Finding::crit("Clock offset", "+412 s")], None),
        ]);
        let d = diff(&old, &new);
        let find = |label: &str| d.changes.iter().find(|c| c.label == label).unwrap();

        assert_eq!(find("Windows Defender Firewall (mpssvc)").kind, ChangeKind::New);
        assert_eq!(find("Windows Search (WSearch)").kind, ChangeKind::Resolved);
        let spooler = find("Print Spooler (Spooler)");
        assert_eq!(spooler.kind, ChangeKind::Changed);
        assert_eq!((spooler.before, spooler.after), (Some(Severity::Warning), Some(Severity::Critical)));
        assert!(d.changes.iter().all(|c| c.label != "C:\\"), "same severity, value drift isn't a change");
        assert!(d.changes.iter().all(|c| c.module_id != "desk.time"), "module didn't run last time");
        assert!(d.changes.iter().all(|c| c.label != "Running services"), "OK rows never count");
        assert_eq!((d.new_issues, d.resolved, d.changed), (1, 1, 1));
    }

    #[test]
    fn severity_crossing_the_problem_line_is_new_or_resolved() {
        let old = report(vec![result("m", vec![Finding::ok("a", "fine"), Finding::warn("b", "bad")], None)]);
        let new = report(vec![result("m", vec![Finding::warn("a", "bad"), Finding::ok("b", "fine")], None)]);
        let d = diff(&old, &new);
        assert_eq!(d.changes.iter().find(|c| c.label == "a").unwrap().kind, ChangeKind::New);
        assert_eq!(d.changes.iter().find(|c| c.label == "b").unwrap().kind, ChangeKind::Resolved);
    }

    #[test]
    fn module_errors_are_tracked() {
        let old = report(vec![result("m", vec![], Some("boom"))]);
        let new = report(vec![result("m", vec![Finding::ok("x", "y")], None)]);
        let d = diff(&old, &new);
        assert_eq!(d.resolved, 1);
        let d2 = diff(&new, &old);
        assert_eq!(d2.new_issues, 1);
    }

    #[test]
    fn parses_older_exports_without_schema() {
        let json = r#"{"generated":"2026-11-06T19:22:31Z","host":{"hostname":"WS-1","os":"Windows 11","platform":"windows","elevated":false,"can_relaunch_elevated":true,"elevation_note":""},"results":[]}"#;
        let r = parse(json).unwrap();
        assert_eq!(r.schema, SCHEMA);
        assert_eq!(r.host.hostname, "WS-1");
        assert!(parse("{}").is_err());
    }

    #[test]
    fn same_second_runs_keep_their_own_files() {
        let dir = std::env::temp_dir().join(format!("itriage-history-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = report(vec![result("system.disk", vec![Finding::ok("C:\\", "50% used")], None)]);
        let mut b = a.clone();
        b.results[0].findings[0] = Finding::warn("C:\\", "91% used");

        let pa = save_in(&dir, &a).unwrap();
        assert_eq!(save_in(&dir, &a).unwrap(), pa, "saving the same report again reuses its file");
        let pb = save_in(&dir, &b).unwrap();
        assert_ne!(pa, pb, "a different run in the same second gets its own file");
        assert!(pb.to_string_lossy().ends_with("~2.json"), "{}", pb.display());
        let mut names = json_files(&dir);
        names.sort();
        assert_eq!(names, vec![pa, pb], "and sorts after the first, oldest first");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
