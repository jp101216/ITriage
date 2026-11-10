//! Saved run reports: the history behind "what changed since last time", the
//! format of the JSON a technician exports, opens or receives from a remote
//! run, and the plain-text renderings (ticket summary, full transcript and the
//! before/after comparison) the CLI prints and the history folder keeps.
//!
//! The comparison is Compare-NetTriage's: problems that are new, resolved,
//! changed or still failing; every measurement that moved, and whether it got
//! better or worse; checks that ran in only one of the two runs; and the gaps
//! that make a comparison incomplete.

use crate::host::HostContext;
use crate::insight::Insight;
use crate::model::{ModuleResult, Severity};
use crate::parse::time::epoch_to_rfc3339;
use crate::util::now_epoch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Current report format version.
pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    #[serde(default = "schema_default")]
    pub schema: u32,
    /// The itriage version that made it (empty before 0.5).
    #[serde(default)]
    pub tool_version: String,
    /// RFC 3339 UTC.
    pub generated: String,
    pub host: HostContext,
    /// Name of the site profile in force.
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub cancelled: bool,
    /// The run's verdict as the command line's exit code: 0 finished, 1
    /// nothing could run, 2 incomplete, 3010 (3 on Linux) restart needed.
    /// See [`crate::module::exit_code`]. Absent before 0.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// The ticket this run was for, as the technician typed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    /// What's most likely wrong, worked out from the findings (see
    /// [`crate::insight`]). Empty before 0.7 and when nothing is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub likely: Vec<Insight>,
    pub results: Vec<ModuleResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording: Option<crate::investigate::recording::Recording>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runbook: Option<crate::investigate::guided::RunbookTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<crate::investigate::baseline::Comparison>,
}

fn schema_default() -> u32 {
    SCHEMA
}

impl Report {
    pub fn new(host: HostContext, profile: Option<String>, results: Vec<ModuleResult>, cancelled: bool) -> Self {
        Self {
            schema: SCHEMA,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            generated: epoch_to_rfc3339(now_epoch()),
            host,
            profile,
            cancelled,
            exit_code: Some(crate::module::exit_code(&results, cancelled)),
            ticket: None,
            likely: crate::insight::likely_causes(&results),
            results,
            role: None,
            recording: None,
            runbook: None,
            baseline: None,
        }
    }

    /// Attach the ticket number, cleaned up (see [`clean_ticket`]).
    pub fn with_ticket(mut self, ticket: Option<&str>) -> Self {
        self.ticket = ticket.and_then(clean_ticket);
        self
    }

    pub fn with_role(mut self, role: &str) -> Self {
        self.role = (!role.trim().is_empty()).then(|| role.trim().chars().take(100).collect());
        self
    }

    /// Rebuild derived fields after a check has replaced one of the results.
    /// The original run time and cancellation state still describe this run.
    pub fn refresh(&mut self) {
        self.exit_code = Some(crate::module::exit_code(&self.results, self.cancelled));
        self.likely = crate::insight::likely_causes(&self.results);
        if let Some(trace) = &mut self.runbook {
            if trace.finished { trace.conclusion = crate::investigate::guided::conclusion(&self.results); }
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

/// A ticket reference as it's kept: letters, digits and the few marks
/// ticket systems use, at most 40 characters. `None` when nothing is left.
pub fn clean_ticket(text: &str) -> Option<String> {
    let kept: String = text.trim().chars().filter(|c| c.is_alphanumeric() || "-_#./: ".contains(*c)).take(40).collect();
    let kept = kept.trim().to_string();
    (!kept.is_empty()).then_some(kept)
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
    pub ticket: Option<String>,
}

pub fn history_dir() -> Option<PathBuf> {
    crate::paths::data_dir().map(|d| d.join("history"))
}

/// Save a report to the history folder, with a plain-text transcript beside
/// it, and prune old runs past `keep` (0 keeps everything). Returns the JSON
/// file's path.
pub fn save(report: &Report, keep: usize) -> Result<PathBuf, String> {
    let dir = history_dir().ok_or("No folder for run history on this system.")?;
    save_in(&dir, report, keep)
}

fn save_in(dir: &Path, report: &Report, keep: usize) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("Can't create {}: {e}", dir.display()))?;
    // Both parts come from the report, and an opened report is someone
    // else's data: neither may name a folder or a drive.
    let stamp = file_part(&report.generated.replace([':', '-'], ""), "", "run");
    let host = file_part(&report.host.hostname, "-", "host");
    // The ticket goes on the end, so sorting by name is still by time.
    let ticket = report.ticket.as_deref().map(|t| format!("_{}", file_part(t, "-", "ticket"))).unwrap_or_default();
    let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    // Two runs in the same second must not overwrite each other, but saving
    // the same report again (re-importing it) shouldn't duplicate it.
    let mut path = dir.join(format!("{stamp}_{host}{ticket}.json"));
    let mut n = 1;
    loop {
        // Claim the name atomically: an import, another app instance or a
        // CLI run can save at the same time as the desktop's current run.
        match std::fs::File::create_new(&path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(json.as_bytes()) {
                    drop(file);
                    let _ = std::fs::remove_file(&path);
                    return Err(format!("Can't write {}: {e}", path.display()));
                }
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if std::fs::read_to_string(&path).is_ok_and(|old| old == json) {
                    return Ok(path);
                }
                n += 1;
                path = dir.join(format!("{stamp}_{host}{ticket}~{n}.json"));
            }
            Err(e) => return Err(format!("Can't write {}: {e}", path.display())),
        }
    }
    // The transcript is a convenience; the JSON is the record.
    let _ = std::fs::write(path.with_extension("txt"), render_text(report, None, true));
    if keep > 0 {
        prune(dir, keep);
    }
    Ok(path)
}

/// A piece of a history file name: letters and digits (plus `also`), the
/// rest replaced, and never empty or overlong. "20261107T141203Z" and
/// "WS-FLINT-07" come through unchanged.
fn file_part(text: &str, also: &str, fallback: &str) -> String {
    let part: String = text
        .chars()
        .take(64)
        .map(|c| if c.is_ascii_alphanumeric() || also.contains(c) { c } else { '_' })
        .collect();
    if part.is_empty() {
        fallback.to_string()
    } else {
        part
    }
}

fn prune(dir: &Path, keep: usize) {
    let mut files = json_files(dir);
    if files.len() <= keep {
        return;
    }
    files.sort(); // names start with the timestamp, so this is oldest first
    for old in &files[..files.len() - keep] {
        let _ = std::fs::remove_file(old);
        let _ = std::fs::remove_file(old.with_extension("txt"));
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

// ------------------------------------------------------------------ index

/// The history's index: what the list and the "compare with the last run"
/// lookup need to know about each saved run, so neither has to read and
/// parse every report (with their full logs) each time. It's a cache: built
/// from the reports, rebuilt for any whose file has changed, and safe to
/// delete.
const INDEX_FILE: &str = "index.v2.cache";
/// The index of 0.6, without measurements or tickets. Removed when seen.
const OLD_INDEX_FILE: &str = "index.cache";
static INDEX_WRITE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct IndexEntry {
    /// The report file's size and modified time when this was read from it.
    size: u64,
    modified: u64,
    generated: String,
    hostname: String,
    modules: usize,
    worst: Severity,
    cancelled: bool,
    /// The modules that really ran (not as a preview).
    checks: Vec<String>,
    #[serde(default)]
    ticket: Option<String>,
    /// Every measurement the run took, for the trend charts.
    #[serde(default)]
    metrics: Vec<IndexMetric>,
}

/// One measurement in the index. Short names: there are a few dozen per run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct IndexMetric {
    #[serde(rename = "m")]
    module_id: String,
    #[serde(rename = "l")]
    label: String,
    #[serde(rename = "v")]
    value: f64,
    #[serde(rename = "u")]
    unit: String,
    #[serde(rename = "w")]
    higher_is_worse: bool,
    #[serde(rename = "s")]
    severity: Severity,
}

type Index = std::collections::BTreeMap<String, IndexEntry>;

impl IndexEntry {
    fn of(report: &Report, size: u64, modified: u64) -> Self {
        Self {
            size,
            modified,
            generated: report.generated.clone(),
            hostname: report.host.hostname.clone(),
            modules: report.results.len(),
            worst: report.worst(),
            cancelled: report.cancelled,
            checks: report.results.iter().filter(|r| !r.preview).map(|r| r.module_id.clone()).collect(),
            ticket: report.ticket.clone(),
            metrics: report
                .results
                .iter()
                .filter(|r| !r.preview && r.error.is_none())
                .flat_map(|r| {
                    r.findings.iter().filter_map(|f| {
                        f.metric.as_ref().map(|m| IndexMetric {
                            module_id: r.module_id.clone(),
                            label: f.label.clone(),
                            value: m.value,
                            unit: m.unit.clone(),
                            higher_is_worse: m.higher_is_worse,
                            severity: f.severity,
                        })
                    })
                })
                .collect(),
        }
    }
}

fn stamp(path: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    // Seconds miss an edit that keeps the byte length within the same
    // second. Existing second-based cache entries simply rebuild once.
    let modified = u64::try_from(meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos()).ok()?;
    Some((meta.len(), modified))
}

/// Every saved run with its index entry, reading only the reports that are
/// new or have changed since the index was written.
fn indexed(dir: &Path) -> Vec<(PathBuf, IndexEntry)> {
    let index_path = dir.join(INDEX_FILE);
    let known: Index = std::fs::read_to_string(&index_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let mut current = Index::new();
    let mut out = Vec::new();
    for path in json_files(dir) {
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else { continue };
        let Some((size, modified)) = stamp(&path) else { continue };
        let entry = match known.get(&name) {
            Some(e) if e.size == size && e.modified == modified => e.clone(),
            _ => match load(&path) {
                Ok(report) => IndexEntry::of(&report, size, modified),
                Err(_) => continue, // not a report; leave it alone
            },
        };
        current.insert(name, entry.clone());
        out.push((path, entry));
    }
    if current != known {
        // Written beside, then moved into place, so a reader never sees half
        // of it. Best effort: without it the next call just reads more.
        let tmp = dir.join(format!("{INDEX_FILE}.{}.{}", std::process::id(), INDEX_WRITE.fetch_add(1, Ordering::Relaxed)));
        if serde_json::to_string(&current).ok().and_then(|text| std::fs::write(&tmp, text).ok()).is_some() {
            let _ = std::fs::rename(&tmp, &index_path);
        }
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(dir.join(OLD_INDEX_FILE));
    }
    out
}

/// Saved runs, newest first.
pub fn list() -> Vec<ReportMeta> {
    history_dir().map(|dir| list_in(&dir)).unwrap_or_default()
}

fn list_in(dir: &Path) -> Vec<ReportMeta> {
    let mut metas: Vec<ReportMeta> = indexed(dir)
        .into_iter()
        .map(|(path, e)| ReportMeta {
            path: path.display().to_string(),
            generated: e.generated,
            hostname: e.hostname,
            modules: e.modules,
            worst: e.worst,
            cancelled: e.cancelled,
            ticket: e.ticket,
        })
        .collect();
    metas.sort_by(|a, b| b.generated.cmp(&a.generated));
    metas
}

// ----------------------------------------------------------------- trends

/// One measurement over this computer's saved runs.
#[derive(Debug, Clone, Serialize)]
pub struct TrendSeries {
    pub module_id: String,
    /// The module's title, for the picker.
    pub module: String,
    pub label: String,
    pub unit: String,
    pub higher_is_worse: bool,
    /// Oldest first.
    pub points: Vec<TrendPoint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrendPoint {
    pub generated: String,
    pub value: f64,
    pub severity: Severity,
}

/// How many runs back a trend reaches.
pub const TREND_RUNS: usize = 60;

/// Every measurement taken in at least two of `hostname`'s saved runs, as a
/// series over time. Read from the index, so no report is opened.
pub fn trends(hostname: &str) -> Vec<TrendSeries> {
    history_dir().map(|dir| trends_in(&dir, hostname)).unwrap_or_default()
}

fn trends_in(dir: &Path, hostname: &str) -> Vec<TrendSeries> {
    let mut runs: Vec<IndexEntry> = indexed(dir)
        .into_iter()
        .map(|(_, e)| e)
        .filter(|e| e.hostname.eq_ignore_ascii_case(hostname) && !e.cancelled)
        .collect();
    runs.sort_by(|a, b| a.generated.cmp(&b.generated));
    if runs.len() > TREND_RUNS {
        runs.drain(..runs.len() - TREND_RUNS);
    }
    let modules: Vec<(String, String)> = crate::module::registry().iter().map(|m| m.info()).map(|i| (i.id, i.title)).collect();
    let mut series: Vec<TrendSeries> = Vec::new();
    for run in &runs {
        for m in &run.metrics {
            let point = TrendPoint { generated: run.generated.clone(), value: m.value, severity: m.severity };
            match series.iter_mut().find(|s| s.module_id == m.module_id && s.label == m.label && s.unit == m.unit) {
                Some(s) => s.points.push(point),
                None => series.push(TrendSeries {
                    module: modules.iter().find(|(id, _)| *id == m.module_id).map_or_else(|| m.module_id.clone(), |(_, title)| title.clone()),
                    module_id: m.module_id.clone(),
                    label: m.label.clone(),
                    unit: m.unit.clone(),
                    higher_is_worse: m.higher_is_worse,
                    points: vec![point],
                }),
            }
        }
    }
    series.retain(|s| s.points.len() >= 2);
    // In checklist order, so the picker reads like the report.
    let order = |id: &str| modules.iter().position(|(m, _)| m == id).unwrap_or(usize::MAX);
    series.sort_by(|a, b| order(&a.module_id).cmp(&order(&b.module_id)).then(a.label.cmp(&b.label)));
    series
}

pub fn load(path: &Path) -> Result<Report, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("Can't read {}: {e}", path.display()))?;
    parse(&text)
}

/// Parse report JSON (from history, an export, or a remote run).
pub fn parse(text: &str) -> Result<Report, String> {
    serde_json::from_str(text).map_err(|e| format!("Not an ITriage report: {e}"))
}

/// The most recent saved run of this host from before `generated` that ran
/// at least one of the same checks (`ids`): a tune-up run in between doesn't
/// hide the triage run before it.
pub fn previous(hostname: &str, generated: &str, ids: &[String]) -> Option<Report> {
    previous_in(&history_dir()?, hostname, generated, ids)
}

/// Of this computer's earlier, finished runs, the one that shares the most
/// read-only checks with `ids`, the newest of those on a tie. So a triage is
/// compared with the last triage even if a tune-up or an update run came in
/// between. A run that only changed things has nothing to compare.
fn previous_in(dir: &Path, hostname: &str, generated: &str, ids: &[String]) -> Option<Report> {
    let mutating: Vec<String> = crate::module::registry()
        .iter()
        .map(|m| m.info())
        .filter(|i| i.mutating)
        .map(|i| i.id)
        .collect();
    let wanted: Vec<&String> = ids.iter().filter(|id| !mutating.contains(id)).collect();
    if wanted.is_empty() {
        return None;
    }
    // Chosen from the index; only the winner is read from disk.
    let mut runs = indexed(dir);
    runs.sort_by(|a, b| b.0.cmp(&a.0)); // names start with the run's timestamp: newest first
    let mut best: Option<(usize, PathBuf)> = None;
    for (path, old) in runs {
        if !old.hostname.eq_ignore_ascii_case(hostname) || old.generated.as_str() >= generated || old.cancelled {
            continue;
        }
        let shared = wanted.iter().filter(|id| old.checks.contains(id)).count();
        if shared > best.as_ref().map_or(0, |(n, _)| *n) {
            let complete = shared == wanted.len();
            best = Some((shared, path));
            if complete {
                break; // nothing older can do better
            }
        }
    }
    best.and_then(|(_, path)| load(&path).ok())
}

/// Compare two runs of the same computer, oldest first whichever way
/// they're given.
pub fn compare(a: &Report, b: &Report) -> Result<ReportDiff, String> {
    if !a.host.hostname.eq_ignore_ascii_case(&b.host.hostname) {
        return Err(format!(
            "These runs are from different computers ({} and {}), so they can't be compared.",
            a.host.hostname, b.host.hostname
        ));
    }
    let (old, new) = if a.generated <= b.generated { (a, b) } else { (b, a) };
    Ok(diff(old, new))
}

// ------------------------------------------------------------------ diff

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// A problem that wasn't there before.
    New,
    /// A problem that's gone.
    Resolved,
    /// Still a problem, at a different severity.
    Changed,
    /// Still a problem, at the same severity ("still failing").
    Ongoing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub module_id: String,
    pub module: String,
    pub label: String,
    pub kind: ChangeKind,
    pub before: Option<Severity>,
    pub after: Option<Severity>,
    /// The current value (or the last known one, for resolved items).
    pub value: String,
    /// What it said last time, when that's different.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub was: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trend {
    Better,
    Worse,
    Same,
}

/// A measured number in both runs (latency, loss, free space, signal…).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricChange {
    pub module_id: String,
    pub module: String,
    pub label: String,
    pub unit: String,
    pub before: f64,
    pub after: f64,
    pub delta: f64,
    pub trend: Trend,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportDiff {
    /// When the older report was generated.
    pub against: String,
    /// When the newer one was.
    pub generated: String,
    pub new_issues: usize,
    pub resolved: usize,
    pub changed: usize,
    /// Problems in both runs.
    pub ongoing: usize,
    pub changes: Vec<Change>,
    /// Every measurement taken both times, worst change first.
    pub metrics: Vec<MetricChange>,
    /// Checks that ran only in the newer run, and only in the older one.
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// What makes this comparison incomplete.
    pub gaps: Vec<String>,
}

impl ReportDiff {
    pub fn better(&self) -> usize {
        self.metrics.iter().filter(|m| m.trend == Trend::Better).count()
    }
    pub fn worse(&self) -> usize {
        self.metrics.iter().filter(|m| m.trend == Trend::Worse).count()
    }
}

fn is_problem(s: Severity) -> bool {
    s.rank() >= Severity::Warning.rank()
}

/// How far a measurement has to move to count as a change, not noise.
fn tolerance(unit: &str, before: f64) -> f64 {
    let floor: f64 = match unit {
        "ms" => 2.0,
        "%" | "% free" => 1.0,
        "days" => 0.5,
        _ => 0.0,
    };
    floor.max(before.abs() * 0.1)
}

fn trend(m: &crate::model::Metric, before: f64, after: f64) -> Trend {
    let delta = after - before;
    if delta.abs() <= tolerance(&m.unit, before) {
        Trend::Same
    } else if (delta > 0.0) == m.higher_is_worse {
        Trend::Worse
    } else {
        Trend::Better
    }
}

/// Has a measurement really moved from `before` to `after`, and which way?
/// The same judgement the comparison makes, for a first and last point.
pub fn movement(unit: &str, higher_is_worse: bool, before: f64, after: f64) -> Trend {
    trend(&crate::model::Metric { value: after, unit: unit.to_string(), higher_is_worse }, before, after)
}

/// What changed between two runs. Problems (warning and above) are compared
/// by severity, so values that always move, like uptime, don't create noise;
/// measured numbers are compared separately. Only modules that ran both
/// times are compared; the rest are listed as added or removed.
pub fn diff(old: &Report, new: &Report) -> ReportDiff {
    const ERROR_LABEL: &str = "Module couldn't run";
    let mut changes = Vec::new();
    let mut metrics = Vec::new();
    let mut gaps = Vec::new();
    let old_by_module: HashMap<&str, &ModuleResult> = old.results.iter().map(|r| (r.module_id.as_str(), r)).collect();
    let new_ids: Vec<&str> = new.results.iter().map(|r| r.module_id.as_str()).collect();

    for n in &new.results {
        let Some(o) = old_by_module.get(n.module_id.as_str()) else {
            continue;
        };
        let change = |label: &str, kind, before, after, value: &str, was: Option<&str>| Change {
            module_id: n.module_id.clone(),
            module: n.title.clone(),
            label: label.to_string(),
            kind,
            before,
            after,
            value: value.to_string(),
            was: was.filter(|w| *w != value).map(str::to_string),
        };
        if o.preview != n.preview {
            gaps.push(format!("{}: one run was a preview, so its results describe changes that weren't made", n.title));
            continue;
        }

        // A module that couldn't run has no findings, which says nothing
        // about them: last time's problems aren't resolved, and this time's
        // aren't new. Only the failure itself is compared.
        match (&o.error, &n.error) {
            (None, Some(e)) => {
                changes.push(change(ERROR_LABEL, ChangeKind::New, None, Some(Severity::Critical), e, None));
                gaps.push(format!("{}: couldn't run this time, so what it found last time isn't compared", n.title));
                continue;
            }
            (Some(e), None) => {
                changes.push(change(ERROR_LABEL, ChangeKind::Resolved, Some(Severity::Critical), None, e, None));
                gaps.push(format!("{}: couldn't run last time, so what it found this time has nothing to compare with", n.title));
                continue;
            }
            (Some(was), Some(e)) => {
                changes.push(change(ERROR_LABEL, ChangeKind::Ongoing, Some(Severity::Critical), Some(Severity::Critical), e, Some(was)));
                continue;
            }
            (None, None) => {}
        }

        let before: HashMap<&str, &crate::model::Finding> = o.findings.iter().map(|f| (f.label.as_str(), f)).collect();
        let after: HashMap<&str, &crate::model::Finding> = n.findings.iter().map(|f| (f.label.as_str(), f)).collect();

        for f in &n.findings {
            match before.get(f.label.as_str()) {
                None if is_problem(f.severity) => {
                    changes.push(change(&f.label, ChangeKind::New, None, Some(f.severity), &f.value, None))
                }
                None => {}
                Some(was) => {
                    let (b, a) = (was.severity, f.severity);
                    let kind = match (is_problem(b), is_problem(a)) {
                        (false, true) => Some(ChangeKind::New),
                        (true, false) => Some(ChangeKind::Resolved),
                        (true, true) if b != a => Some(ChangeKind::Changed),
                        (true, true) => Some(ChangeKind::Ongoing),
                        (false, false) => None,
                    };
                    if let Some(kind) = kind {
                        changes.push(change(&f.label, kind, Some(b), Some(a), &f.value, Some(&was.value)));
                    }
                    match (&was.metric, &f.metric) {
                        (Some(mb), Some(ma)) if mb.unit == ma.unit => metrics.push(MetricChange {
                            module_id: n.module_id.clone(),
                            module: n.title.clone(),
                            label: f.label.clone(),
                            unit: ma.unit.clone(),
                            before: mb.value,
                            after: ma.value,
                            delta: ((ma.value - mb.value) * 100.0).round() / 100.0,
                            trend: trend(ma, mb.value, ma.value),
                        }),
                        (Some(_), None) => gaps.push(format!("{}: {} was measured last time but not this time", n.title, f.label)),
                        (None, Some(_)) => gaps.push(format!("{}: {} wasn't measured last time", n.title, f.label)),
                        _ => {}
                    }
                }
            }
        }
        for f in &o.findings {
            if is_problem(f.severity) && !after.contains_key(f.label.as_str()) {
                changes.push(change(&f.label, ChangeKind::Resolved, Some(f.severity), None, &f.value, None));
            }
        }
    }

    let added: Vec<String> = new
        .results
        .iter()
        .filter(|r| !old_by_module.contains_key(r.module_id.as_str()))
        .map(|r| r.title.clone())
        .collect();
    let removed: Vec<String> = old
        .results
        .iter()
        .filter(|r| !new_ids.contains(&r.module_id.as_str()))
        .map(|r| r.title.clone())
        .collect();
    if old.cancelled {
        gaps.push("The earlier run was cancelled, so some of its checks didn't finish.".into());
    }
    if new.cancelled {
        gaps.push("This run was cancelled, so some checks didn't finish.".into());
    }
    if old.profile != new.profile {
        gaps.push(format!(
            "Different site profiles ({} then {}), so thresholds and requirements may differ.",
            old.profile.as_deref().unwrap_or("built-in"),
            new.profile.as_deref().unwrap_or("built-in")
        ));
    }

    // Worse first, then better, then unchanged; each by size of change.
    let rank = |t: Trend| match t {
        Trend::Worse => 0,
        Trend::Better => 1,
        Trend::Same => 2,
    };
    metrics.sort_by(|a, b| rank(a.trend).cmp(&rank(b.trend)).then(b.delta.abs().total_cmp(&a.delta.abs())));

    let count = |k| changes.iter().filter(|c| c.kind == k).count();
    ReportDiff {
        against: old.generated.clone(),
        generated: new.generated.clone(),
        new_issues: count(ChangeKind::New),
        resolved: count(ChangeKind::Resolved),
        changed: count(ChangeKind::Changed),
        ongoing: count(ChangeKind::Ongoing),
        changes,
        metrics,
        added,
        removed,
        gaps,
    }
}

// ------------------------------------------------------------- rendering

fn sev_tag(s: Severity) -> &'static str {
    match s {
        Severity::Ok => "OK",
        Severity::Info => "INFO",
        Severity::Warning => "WARN",
        Severity::Critical => "CRIT",
    }
}

fn utc(rfc3339: &str) -> String {
    // "2026-11-07T14:12:03Z" → "2026-11-07 14:12 UTC"
    match rfc3339.get(..16) {
        Some(d) if rfc3339.len() >= 17 => format!("{} UTC", d.replace('T', " ")),
        _ => rfc3339.to_string(),
    }
}

/// A measurement as people read it: "12 ms", "34%", "4.5 days".
pub fn metric_text(value: f64, unit: &str) -> String {
    let v = if (value - value.round()).abs() < 0.05 { format!("{}", value.round()) } else { format!("{value:.1}") };
    match unit {
        "%" => format!("{v}%"),
        "% free" => format!("{v}% free"),
        "days" if v == "1" => "1 day".to_string(),
        "" => v,
        u => format!("{v} {u}"),
    }
}

/// The ticket text: a header, what needs attention, every module's findings,
/// and (with `logs`) each module's transcript. The CLI prints this and the
/// history folder keeps it beside each run.
pub fn render_text(report: &Report, diff: Option<&ReportDiff>, logs: bool) -> String {
    let h = &report.host;
    let mut out = vec![
        format!("ITriage report — {}", utc(&report.generated)),
        [
            Some(h.hostname.clone()),
            Some(h.os.clone()),
            Some(if h.elevated { "elevated".to_string() } else { "standard user".to_string() }),
            report.profile.as_ref().map(|p| format!("profile: {p}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · "),
    ];
    if let Some(t) = &report.ticket {
        out.push(format!("Ticket: {t}"));
    }
    if let Some(role) = &report.role { out.push(format!("Workstation role: {role}")); }
    if let Some(trace) = &report.runbook {
        out.push(format!("Troubleshooting: {} — {}", trace.id, trace.conclusion));
        for (i,step) in trace.steps.iter().enumerate() { out.push(format!("  Phase {}: {} [{}]",i+1,step.reason,step.modules.join(", "))); }
    }
    if let Some(recording) = &report.recording {
        out.push(format!("Recording: {} sample(s), {} marker(s), started {}",recording.samples.len(),recording.markers.len(),recording.started));
        for marker in &recording.markers { out.push(format!("  {}: {}",epoch_to_rfc3339(marker.at_ms/1000),marker.label)); }
    }
    if let Some(baseline) = &report.baseline { out.push(format!("Working-PC baseline: {} -> {}: {} configuration difference(s)",baseline.baseline_host,baseline.current_host,baseline.differences.len())); }
    if report.cancelled {
        out.push("The run was cancelled before every module finished.".into());
    }
    if report.results.iter().any(|r| r.preview) {
        out.push("PREVIEW: modules that change the machine only said what they would do.".into());
    }
    if report.results.iter().any(|r| r.restart_required) {
        out.push("A restart is needed to finish the changes.".into());
    }
    if let Some(d) = diff {
        out.push(format!("Since {}: {}", utc(&d.against), diff_line(d)));
    }
    out.push("=".repeat(60));

    out.extend(crate::insight::render(&report.likely));

    // Key findings next, the way NetTriage's ServiceNow summary opens.
    let mut key = Vec::new();
    for r in &report.results {
        if let Some(e) = &r.error {
            key.push(format!("- [FAILED] {}: {e}", r.title));
        }
        for f in r.findings.iter().filter(|f| is_problem(f.severity)) {
            key.push(format!("- [{}] {}: {}: {}", sev_tag(f.severity), r.title, f.label, f.value));
        }
    }
    out.push("KEY FINDINGS".into());
    if key.is_empty() {
        out.push("- Nothing needs attention.".into());
    } else {
        out.extend(key);
    }
    out.push(String::new());

    for r in &report.results {
        let status = if r.error.is_some() { "FAILED".to_string() } else { format!("{:?}", r.status()).to_uppercase() };
        let preview = if r.preview { " (preview)" } else { "" };
        out.push(format!(
            "[{status}] {}{preview}: {}",
            r.title,
            if r.error.is_some() { "couldn't run" } else { r.summary.as_str() }
        ));
        if let Some(e) = &r.error {
            out.push(format!("    error: {e}"));
        }
        for f in &r.findings {
            out.push(format!("    {:<5} {}: {}", sev_tag(f.severity), f.label, f.value));
            if let Some(d) = &f.detail {
                out.push(format!("          {d}"));
            }
            if let Some(kb) = &f.kb {
                out.push(format!("          KB: {} <{}>", kb.title, kb.url));
            }
        }
        if logs && !r.log.is_empty() {
            out.push("    log:".into());
            out.extend(r.log.iter().map(|l| format!("      | {l}")));
        }
        out.push(String::new());
    }
    if let Some(d) = diff {
        out.push(render_diff(d, &report.host.hostname));
    }
    out.join("\n")
}

fn diff_line(d: &ReportDiff) -> String {
    let mut bits = Vec::new();
    for (n, what) in [(d.new_issues, "new"), (d.resolved, "resolved"), (d.changed, "changed"), (d.ongoing, "still failing")] {
        if n > 0 {
            bits.push(format!("{n} {what}"));
        }
    }
    let (better, worse) = (d.better(), d.worse());
    if better + worse > 0 {
        bits.push(format!("{better} measurement{} better, {worse} worse", if better == 1 { "" } else { "s" }));
    }
    if bits.is_empty() {
        "no change in problems".into()
    } else {
        bits.join(", ")
    }
}

/// Compare-NetTriage's "BEFORE AND AFTER" text.
pub fn render_diff(d: &ReportDiff, hostname: &str) -> String {
    let mut out = vec![
        "BEFORE AND AFTER".to_string(),
        format!("Computer  {hostname}"),
        format!("Before    {}", utc(&d.against)),
        format!("After     {}", utc(&d.generated)),
        String::new(),
        "CHECK RESULTS".to_string(),
        format!(
            "Resolved {} · New {} · Changed {} · Still failing {} · Added {} · Removed {}",
            d.resolved,
            d.new_issues,
            d.changed,
            d.ongoing,
            d.added.len(),
            d.removed.len()
        ),
    ];
    let word = |k: ChangeKind| match k {
        ChangeKind::New => "New",
        ChangeKind::Resolved => "Resolved",
        ChangeKind::Changed => "Changed",
        ChangeKind::Ongoing => "Still failing",
    };
    for c in &d.changes {
        let sev = |s: Option<Severity>| s.map(sev_tag).unwrap_or("—");
        out.push(format!(
            "- {:<13} {}: {}  ({} → {}) {}",
            word(c.kind),
            c.module,
            c.label,
            sev(c.before),
            sev(c.after),
            c.value
        ));
        if let Some(was) = &c.was {
            out.push(format!("                was: {was}"));
        }
    }
    if !d.added.is_empty() {
        out.push(format!("- Added         {}", d.added.join(", ")));
    }
    if !d.removed.is_empty() {
        out.push(format!("- Removed       {}", d.removed.join(", ")));
    }
    out.push(String::new());
    out.push("LATENCY AND QUALITY".to_string());
    let moved: Vec<&MetricChange> = d.metrics.iter().filter(|m| m.trend != Trend::Same).collect();
    for m in &moved {
        out.push(format!(
            "- {}: {}  {} → {} ({}{}, {})",
            m.module,
            m.label,
            metric_text(m.before, &m.unit),
            metric_text(m.after, &m.unit),
            if m.delta > 0.0 { "+" } else { "" },
            metric_text(m.delta, &m.unit),
            if m.trend == Trend::Better { "better" } else { "worse" }
        ));
    }
    let same = d.metrics.len() - moved.len();
    if d.metrics.is_empty() {
        out.push("- No measurements in common.".into());
    } else if same > 0 {
        out.push(format!("- {same} measurement{} about the same", if same == 1 { "" } else { "s" }));
    }
    if !d.gaps.is_empty() {
        out.push(String::new());
        out.push("GAPS".to_string());
        out.extend(d.gaps.iter().map(|g| format!("- {g}")));
    }
    out.join("\n")
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
            log: Vec::new(),
            restart_required: false,
            preview: false,
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
        let disk = find("C:\\");
        assert_eq!(disk.kind, ChangeKind::Ongoing, "still a problem at the same severity");
        assert_eq!(disk.was.as_deref(), Some("90% used"));
        assert!(d.changes.iter().all(|c| c.module_id != "desk.time"), "module didn't run last time");
        assert_eq!(d.added, vec!["desk.time".to_string()]);
        assert!(d.changes.iter().all(|c| c.label != "Running services"), "OK rows never count");
        assert_eq!((d.new_issues, d.resolved, d.changed, d.ongoing), (1, 1, 1, 1));
    }

    #[test]
    fn measurements_move_better_or_worse() {
        let old = report(vec![result("net.latency", vec![
            Finding::warn("Gateway 10.0.0.1 round trip", "avg 38 ms").with_metric(38.0, "ms", true),
            Finding::crit("Gateway 10.0.0.1 packet loss", "25%").with_metric(25.0, "%", true),
            Finding::ok("DNS server 10.0.0.53 round trip", "avg 12 ms").with_metric(12.0, "ms", true),
        ], None), result("desk.wifi", vec![Finding::warn("Signal", "48%").with_metric(48.0, "%", false)], None),
           result("proc.services", vec![], None)]);
        let new = report(vec![result("net.latency", vec![
            Finding::ok("Gateway 10.0.0.1 round trip", "avg 3 ms").with_metric(3.0, "ms", true),
            Finding::ok("Gateway 10.0.0.1 packet loss", "0%").with_metric(0.0, "%", true),
            Finding::ok("DNS server 10.0.0.53 round trip", "avg 13 ms").with_metric(13.0, "ms", true),
        ], None), result("desk.wifi", vec![Finding::warn("Signal", "41%")], None)]);
        let d = diff(&old, &new);
        let m = |label: &str| d.metrics.iter().find(|x| x.label == label).unwrap();
        assert_eq!(m("Gateway 10.0.0.1 round trip").trend, Trend::Better);
        assert_eq!(m("Gateway 10.0.0.1 round trip").delta, -35.0);
        assert_eq!(m("Gateway 10.0.0.1 packet loss").trend, Trend::Better);
        assert_eq!(m("DNS server 10.0.0.53 round trip").trend, Trend::Same, "1 ms is noise");
        assert_eq!((d.better(), d.worse()), (2, 0));
        assert_eq!(d.metrics.last().unwrap().trend, Trend::Same, "unchanged sort last");
        assert_eq!(d.removed, vec!["proc.services".to_string()]);
        assert!(d.gaps.iter().any(|g| g.contains("Signal") && g.contains("not this time")), "{:?}", d.gaps);
        assert_eq!(d.resolved, 2, "both gateway problems cleared");

        let text = render_diff(&d, "WS-1");
        assert!(text.contains("BEFORE AND AFTER"));
        assert!(text.contains("38 ms → 3 ms (-35 ms, better)"), "{text}");
        assert!(text.contains("1 measurement about the same"), "{text}");
        assert!(text.contains("GAPS"));
    }

    #[test]
    fn compare_checks_the_computer_and_orders_the_runs() {
        let mut a = report(vec![result("m", vec![Finding::warn("x", "bad")], None)]);
        a.generated = "2026-11-05T10:00:00Z".into();
        let mut b = report(vec![result("m", vec![Finding::ok("x", "fine")], None)]);
        b.generated = "2026-11-07T10:00:00Z".into();
        let d = compare(&b, &a).unwrap();
        assert_eq!(d.against, a.generated, "the older run comes first");
        assert_eq!(d.resolved, 1);
        let mut other = b.clone();
        other.host.hostname = "WS-2".into();
        assert!(compare(&a, &other).unwrap_err().contains("different computers"));
    }

    #[test]
    fn ticket_text_leads_with_key_findings() {
        let mut r = report(vec![
            result("system.disk", vec![Finding::crit("C:\\", "98% used"), Finding::ok("D:\\", "40% used")], None),
            result("desk.time", vec![], Some("w32tm missing")),
        ]);
        r.results[0].log = vec!["Measuring disk latency…".into()];
        let text = render_text(&r, None, true);
        let key = text.find("KEY FINDINGS").unwrap();
        assert!(text[key..].starts_with("KEY FINDINGS\n- [CRIT] system.disk: C:\\: 98% used\n- [FAILED] desk.time: w32tm missing")
            || text[key..].contains("- [FAILED] desk.time: w32tm missing"), "{text}");
        assert!(text.contains("      | Measuring disk latency…"), "logs are included");
        assert!(!render_text(&r, None, false).contains("| Measuring"));
        assert_eq!(metric_text(4.0, "ms"), "4 ms");
        assert_eq!(metric_text(48.25, "% free"), "48.2% free");
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
    fn a_module_that_couldnt_run_resolves_and_adds_nothing() {
        let ran = report(vec![result("system.disk", vec![Finding::crit("C:\\", "98% used"), Finding::warn("D:\\", "88% used")], None)]);
        let failed = report(vec![result("system.disk", vec![], Some("performance counters unavailable"))]);

        let d = diff(&ran, &failed);
        assert_eq!((d.new_issues, d.resolved), (1, 0), "the full disk isn't resolved just because nobody looked: {:?}", d.changes);
        assert_eq!(d.changes[0].label, "Module couldn't run");
        assert!(d.gaps.iter().any(|g| g.contains("couldn't run this time")), "{:?}", d.gaps);

        let d = diff(&failed, &ran);
        assert_eq!((d.new_issues, d.resolved), (0, 1), "and it isn't new just because it's visible again: {:?}", d.changes);
        assert!(d.gaps.iter().any(|g| g.contains("couldn't run last time")), "{:?}", d.gaps);
    }

    #[test]
    fn an_opened_report_cant_name_a_path() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-history-names-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let history = dir.join("deep").join("history");
        let mut evil = report(vec![result("system.disk", vec![Finding::ok("C:\\", "50% used")], None)]);
        for (generated, hostname) in [
            ("../../escaped", "WS-1"),
            ("/tmp/absolute", "WS-1"),
            ("\\\\server\\share\\x", "..\\..\\up"),
            ("C:\\Windows\\x", "a/b"),
            ("", ""),
        ] {
            evil.generated = generated.into();
            evil.host.hostname = hostname.into();
            let saved = save_in(&history, &evil, 0).unwrap();
            assert_eq!(saved.parent(), Some(history.as_path()), "{generated:?} / {hostname:?} → {}", saved.display());
            assert!(saved.with_extension("txt").parent() == Some(history.as_path()) && saved.is_file());
        }
        let outside: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(outside, vec![std::ffi::OsString::from("deep")], "nothing was written above the history folder");
        assert_eq!(file_part("20261107T141203Z", "", "run"), "20261107T141203Z");
        assert_eq!(file_part("WS-FLINT-07", "-", "host"), "WS-FLINT-07");
        assert_eq!((file_part("", "", "run"), file_part(&"x".repeat(300), "", "run").len()), ("run".to_string(), 64));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_older_exports_without_schema() {
        let json = r#"{"generated":"2026-11-06T19:22:31Z","host":{"hostname":"WS-1","os":"Windows 11","platform":"windows","elevated":false,"can_relaunch_elevated":true,"elevation_note":""},"results":[]}"#;
        let r = parse(json).unwrap();
        assert_eq!(r.schema, SCHEMA);
        assert_eq!(r.host.hostname, "WS-1");
        assert_eq!((r.tool_version.as_str(), r.exit_code), ("", None), "older reports have neither");
        let fresh = report(vec![result("system.disk", vec![Finding::ok("C:\\", "50% used")], None)]);
        assert_eq!((fresh.tool_version.as_str(), fresh.exit_code), (env!("CARGO_PKG_VERSION"), Some(0)));
        assert!(parse("{}").is_err());
    }

    #[test]
    fn same_second_runs_keep_their_own_files() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-history-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = report(vec![result("system.disk", vec![Finding::ok("C:\\", "50% used")], None)]);
        let mut b = a.clone();
        b.results[0].findings[0] = Finding::warn("C:\\", "91% used");

        let pa = save_in(&dir, &a, 100).unwrap();
        assert_eq!(save_in(&dir, &a, 100).unwrap(), pa, "saving the same report again reuses its file");
        let pb = save_in(&dir, &b, 100).unwrap();
        assert_ne!(pa, pb, "a different run in the same second gets its own file");
        assert!(pb.to_string_lossy().ends_with("~2.json"), "{}", pb.display());
        let mut names = json_files(&dir);
        names.sort();
        assert!(pa.with_extension("txt").exists(), "a transcript is saved beside it");
        assert_eq!(names, vec![pa, pb], "and sorts after the first, oldest first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rechecked_reports_refresh_their_verdict_and_diagnosis() {
        let mut run = report(vec![result("system.disk", vec![Finding::crit("C:\\", "2% free").with_metric(2.0, "% free", false)], None)]);
        assert!(!run.likely.is_empty());
        run.results[0].error = Some("drive unavailable".into());
        run.refresh();
        assert_eq!(run.exit_code, Some(1));
        assert!(run.likely.is_empty(), "a failed re-check can't support the old diagnosis");
        run.results[0].error = None;
        run.results[0].findings = vec![Finding::ok("C:\\", "50% free").with_metric(50.0, "% free", false)];
        run.refresh();
        assert_eq!(run.exit_code, Some(0));
        assert!(run.likely.is_empty());
        run.cancelled = true;
        run.refresh();
        assert_eq!(run.exit_code, Some(2), "re-checking a result doesn't finish a cancelled run");
    }

    #[test]
    fn the_history_list_reads_each_report_once() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-index-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut first = report(vec![result("system.disk", vec![Finding::warn("C:\\", "90% used")], None)]);
        first.generated = "2026-11-01T09:00:00Z".into();
        let mut second = report(vec![result("system.disk", vec![Finding::ok("C:\\", "50% used")], None), result("fix.temp", vec![], None)]);
        second.generated = "2026-11-02T09:00:00Z".into();
        second.results[1].preview = true;
        let p1 = save_in(&dir, &first, 0).unwrap();
        let p2 = save_in(&dir, &second, 0).unwrap();

        let listed = list_in(&dir);
        assert_eq!(listed.iter().map(|m| m.generated.as_str()).collect::<Vec<_>>(), vec![second.generated.as_str(), first.generated.as_str()], "newest first");
        assert_eq!((listed[1].worst, listed[0].modules), (Severity::Warning, 2));
        let index: Index = serde_json::from_str(&std::fs::read_to_string(dir.join(INDEX_FILE)).unwrap()).unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(index[p2.file_name().unwrap().to_str().unwrap()].checks, vec!["system.disk"], "previews aren't checks");

        // From here the reports themselves aren't read: emptying one's file
        // while keeping its size and time would go unnoticed, so prove it
        // the other way round. A report that changes is read again...
        let mut changed = first.clone();
        changed.results[0].findings[0] = Finding::crit("C:\\", "99% used, and counting");
        std::fs::write(&p1, serde_json::to_string_pretty(&changed).unwrap()).unwrap();
        assert_eq!(list_in(&dir)[1].worst, Severity::Critical, "a changed report is re-read");
        // ...one that's deleted drops out, and the index isn't a run itself.
        std::fs::remove_file(&p2).unwrap();
        let listed = list_in(&dir);
        assert_eq!(listed.len(), 1);
        assert!(json_files(&dir).iter().all(|p| p.file_name().unwrap() != INDEX_FILE));
        // A damaged index is just rebuilt.
        std::fs::write(dir.join(INDEX_FILE), "not json").unwrap();
        assert_eq!(list_in(&dir).len(), 1);
        // The lookup for "the last comparable run" goes through it too.
        let found = previous_in(&dir, "WS-1", "2026-11-05T09:00:00Z", &["system.disk".to_string()]).unwrap();
        assert_eq!(found.generated, first.generated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_detects_same_size_edits_within_one_second() {
        use std::fs::FileTimes;
        use std::time::{Duration, UNIX_EPOCH};
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-fast-edit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut run = report(vec![result("system.disk", vec![Finding::ok("Free", "50% free").with_metric(50.0, "% free", false)], None)]);
        let path = save_in(&dir, &run, 0).unwrap();
        let set_time = |nanos| {
            let time = UNIX_EPOCH + Duration::new(1_790_000_000, nanos);
            std::fs::File::options().write(true).open(&path).unwrap().set_times(FileTimes::new().set_modified(time)).unwrap();
        };
        set_time(100_000_000);
        let original = std::fs::metadata(&path).unwrap().len();
        assert_eq!(indexed(&dir)[0].1.metrics[0].value, 50.0);
        run.results[0].findings[0] = Finding::ok("Free", "40% free").with_metric(40.0, "% free", false);
        std::fs::write(&path, serde_json::to_string_pretty(&run).unwrap()).unwrap();
        set_time(200_000_000);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), original);
        assert_eq!(indexed(&dir)[0].1.metrics[0].value, 40.0, "the history and trends must see the edited measurement");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_same_second_runs_never_overwrite_each_other() {
        use std::sync::{Arc, Barrier};
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-concurrent-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let barrier = Arc::new(Barrier::new(16));
        let saved = std::thread::scope(|s| {
            let handles: Vec<_> = (0..16).map(|i| {
                let (dir, barrier) = (&dir, barrier.clone());
                s.spawn(move || {
                    let run = report(vec![result("system.disk", vec![Finding::ok("Run", i.to_string())], None)]);
                    barrier.wait();
                    (save_in(dir, &run, 0).unwrap(), i.to_string())
                })
            }).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect::<Vec<_>>()
        });
        assert_eq!(json_files(&dir).len(), saved.len(), "each simultaneous run needs its own record");
        for (path, expected) in saved {
            assert_eq!(load(&path).unwrap().results[0].findings[0].value, expected);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn measurements_read_naturally() {
        assert_eq!(metric_text(38.0, "ms"), "38 ms");
        assert_eq!(metric_text(4.5, "days"), "4.5 days");
        assert_eq!(metric_text(1.0, "days"), "1 day");
        assert_eq!(metric_text(8.0, "% free"), "8% free");
        assert_eq!(metric_text(2.0, ""), "2");
    }

    #[test]
    fn a_ticket_follows_the_run_everywhere() {
        assert_eq!(clean_ticket("  INC0012345 ").as_deref(), Some("INC0012345"));
        assert_eq!(clean_ticket("REQ/2026/0042 #7").as_deref(), Some("REQ/2026/0042 #7"));
        assert_eq!(clean_ticket("x\n<script>\"y\";").as_deref(), Some("xscripty"), "only what a ticket reference is made of");
        assert_eq!(clean_ticket(&"9".repeat(200)).unwrap().len(), 40);
        assert_eq!(clean_ticket("  \t "), None);

        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-ticket-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut run = report(vec![result("system.disk", vec![Finding::ok("C:\\", "50% used")], None)]).with_ticket(Some(" INC0012345 "));
        run.generated = "2026-11-03T09:00:00Z".into();
        assert_eq!(run.ticket.as_deref(), Some("INC0012345"));
        let path = save_in(&dir, &run, 0).unwrap();
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "20261103T090000Z_WS-1_INC0012345.json");
        assert_eq!(list_in(&dir)[0].ticket.as_deref(), Some("INC0012345"));
        let text = render_text(&run, None, false);
        assert!(text.lines().nth(2) == Some("Ticket: INC0012345"), "{text}");
        assert_eq!(load(&path).unwrap().ticket.as_deref(), Some("INC0012345"));

        // A ticket made of path characters still can't name a folder.
        let mut odd = report(vec![result("system.disk", vec![], None)]).with_ticket(Some("../../x"));
        odd.generated = "2026-11-04T09:00:00Z".into();
        let path = save_in(&dir, &odd, 0).unwrap();
        assert_eq!(path.parent().unwrap(), dir);
        assert!(report(vec![]).with_ticket(None).ticket.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_likely_cause_leads_the_ticket_text() {
        let run = report(vec![result("desk.wifi", vec![Finding::warn("Signal", "42% · weak")], None)]);
        assert_eq!(run.likely.len(), 1);
        let text = render_text(&run, None, false);
        let (likely, key) = (text.find("LIKELY CAUSE").unwrap(), text.find("KEY FINDINGS").unwrap());
        assert!(likely < key, "{text}");
        assert!(text.contains("- Weak Wi-Fi (42%) is the most likely reason"));
        // Reports from before 0.7 have neither field and still open.
        let mut value = serde_json::to_value(&run).unwrap();
        value.as_object_mut().unwrap().remove("likely");
        let old: Report = serde_json::from_value(value).unwrap();
        assert!(old.likely.is_empty() && old.ticket.is_none());
        assert!(!render_text(&old, None, false).contains("LIKELY CAUSE"));
    }

    #[test]
    fn trends_follow_a_measurement_across_runs() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-trend-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let run = |when: &str, host: &str, free: f64, signal: Option<f64>| {
            let mut findings = vec![Finding::ok("C:\\", format!("{free}% free")).with_metric(free, "% free", false)];
            let mut results = Vec::new();
            if let Some(s) = signal {
                results.push(result("desk.wifi", vec![Finding::warn("Signal", format!("{s}%")).with_metric(s, "%", false)], None));
            }
            findings.push(Finding::info("Volumes", "1"));
            results.insert(0, result("system.disk", findings, None));
            let mut r = report(results);
            r.generated = when.into();
            r.host.hostname = host.into();
            save_in(&dir, &r, 0).unwrap();
        };
        run("2026-11-03T09:00:00Z", "WS-1", 22.0, Some(40.0));
        run("2026-11-01T09:00:00Z", "WS-1", 31.0, None);
        run("2026-11-02T09:00:00Z", "ws-1", 27.0, None);
        run("2026-11-02T10:00:00Z", "OTHER", 80.0, Some(90.0));

        let series = trends_in(&dir, "WS-1");
        assert_eq!(series.len(), 1, "the signal was only measured once: {series:?}");
        let disk = &series[0];
        assert_eq!((disk.module_id.as_str(), disk.module.as_str(), disk.label.as_str(), disk.unit.as_str()), ("system.disk", "Disk space & latency", "C:\\", "% free"));
        assert!(!disk.higher_is_worse);
        assert_eq!(disk.points.iter().map(|p| p.value).collect::<Vec<_>>(), vec![31.0, 27.0, 22.0], "oldest first, this computer only");
        assert!(trends_in(&dir, "nobody").is_empty());
        // The index of 0.6 is replaced, not read.
        std::fs::write(dir.join(OLD_INDEX_FILE), "{}").unwrap();
        std::fs::remove_file(dir.join(INDEX_FILE)).unwrap();
        assert_eq!(trends_in(&dir, "WS-1").len(), 1);
        assert!(!dir.join(OLD_INDEX_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compares_with_the_run_sharing_the_most_checks() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-previous-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let at = |when: &str, ids: &[&str]| {
            let mut r = report(ids.iter().map(|id| result(id, vec![Finding::ok("x", "y")], None)).collect());
            r.generated = when.into();
            r
        };
        let triage = at("2026-11-01T09:00:00Z", &["system.info", "system.disk", "net.latency"]);
        let older_triage = at("2026-10-01T09:00:00Z", &["system.info", "system.disk", "net.latency"]);
        let updates = at("2026-11-02T09:00:00Z", &["system.info", "update.scan"]);
        let tuneup = at("2026-11-03T09:00:00Z", &["fix.dns", "fix.temp"]);
        let mut cancelled = at("2026-11-04T09:00:00Z", &["system.info", "system.disk", "net.latency"]);
        cancelled.cancelled = true;
        let mut elsewhere = at("2026-11-04T10:00:00Z", &["system.info", "system.disk", "net.latency"]);
        elsewhere.host.hostname = "WS-2".into();
        for r in [&triage, &older_triage, &updates, &tuneup, &cancelled, &elsewhere] {
            save_in(&dir, r, 0).unwrap();
        }
        let ids = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let now = "2026-11-05T09:00:00Z";

        let pick = previous_in(&dir, "ws-1", now, &ids(&["system.info", "system.disk", "net.latency"])).unwrap();
        assert_eq!(pick.generated, triage.generated, "the last triage, not the newer update run, cancelled run or other PC");
        let pick = previous_in(&dir, "WS-1", now, &ids(&["system.info", "update.scan", "update.firmware"])).unwrap();
        assert_eq!(pick.generated, updates.generated, "update runs compare with update runs");
        let pick = previous_in(&dir, "WS-1", now, &ids(&["system.info"])).unwrap();
        assert_eq!(pick.generated, updates.generated, "on a tie, the newest");
        assert!(previous_in(&dir, "WS-1", now, &ids(&["fix.dns", "fix.temp"])).is_none(), "a tune-up has nothing to compare");
        assert!(previous_in(&dir, "WS-1", "2026-09-01T00:00:00Z", &ids(&["system.info"])).is_none(), "only earlier runs");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
