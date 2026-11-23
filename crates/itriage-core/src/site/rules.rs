//! Custom checks: read-only rules a site writes in its own profile
//! (`[[check]]`), so a desk can check "the badge-tap agent points at the
//! production appliance" or "this PC logged no temporary-profile sign-ins
//! today" without waiting for a new ITriage release.
//!
//! What a rule can look at is fixed, and every kind only reads:
//!
//! | `kind`     | Looks at | Conditions |
//! |---|---|---|
//! | `registry` | a key, or one value in it (Windows) | `exists`, `equals`, `contains`, `matches`, `min`/`max`, `min_version` |
//! | `file`     | a file or folder | `exists`, `contains`, `matches`, `min_version` (Windows), `max_age_days` |
//! | `service`  | a Windows service or systemd unit | `exists`, `state` |
//! | `process`  | a running program, by name | `exists` |
//! | `event`    | event IDs in a Windows event log | `max_count` |
//! | `journal`  | a systemd unit's journal entries (Linux) | `max_count`, `matches` to pick the entries |
//!
//! There is deliberately no kind that runs a command or a script: a profile
//! can make ITriage *look* somewhere, never *do* something. Event queries
//! are built only from values checked here first (names from a small
//! character set, numeric IDs), never pasted in as given.
//!
//! A rule that's written wrong (an unknown key, a condition that doesn't
//! fit its kind, a pattern that doesn't compile) shows as a warning on that
//! rule alone. It doesn't make the whole profile invalid: a managed profile
//! that fails to parse locks ITriage read-only, and a typo in one check
//! shouldn't do that.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Most rules one profile may define; the rest are reported, not run.
pub const MAX_RULES: usize = 100;
/// How much of a file `contains` / `matches` read.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Event IDs one rule may name.
const MAX_IDS: usize = 20;
/// Longest look-back for `event` and `journal` (30 days).
const MAX_HOURS: u32 = 720;
/// The most matching events counted.
const MAX_EVENTS: usize = 1000;

/// One `[[check]]` entry as written. Every field is optional to serde, so a
/// mistake is reported on the rule (see [`plan`]) instead of failing the
/// whole profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    /// What the row is called in the report.
    pub label: String,
    /// registry, file, service, process, event or journal.
    pub kind: String,
    /// Run only on "windows" or "linux". Registry and event rules are
    /// Windows-only and journal rules Linux-only whatever this says.
    pub platform: Option<String>,
    /// How a failure is graded: info, warning (the default) or critical.
    pub severity: Option<String>,
    /// Shown under a failed row: what to do about it.
    pub help: Option<String>,

    // --- what to look at ---
    /// registry: `HKLM\SOFTWARE\…` (also HKCU, HKU and the long forms).
    pub key: Option<String>,
    /// registry: one value under `key`; absent checks the key itself.
    pub value: Option<String>,
    /// file: an absolute path; `%VARIABLES%` (Windows) and `~/` or `$HOME`
    /// (Linux) are expanded.
    pub path: Option<String>,
    /// service: the service or unit name. process: the program's name.
    pub name: Option<String>,
    /// event: the log, e.g. `System` or `Microsoft-Windows-…/Operational`.
    pub log: Option<String>,
    /// event: only this provider's events.
    pub provider: Option<String>,
    /// event: the event IDs to count.
    pub ids: Vec<u32>,
    /// journal: the systemd unit.
    pub unit: Option<String>,
    /// event / journal: how far back to look, in hours (default 24).
    pub within_hours: Option<u32>,

    // --- what it should be ---
    pub exists: Option<bool>,
    pub equals: Option<toml::Value>,
    pub contains: Option<String>,
    pub matches: Option<String>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub min_version: Option<String>,
    /// service: running or stopped.
    pub state: Option<String>,
    /// file: changed within this many days.
    pub max_age_days: Option<f64>,
    /// event / journal: how many matching entries are still fine (default 0).
    pub max_count: Option<u32>,

    /// Keys this version doesn't know, kept so the rule can name them.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Registry,
    File,
    Service,
    Process,
    Event,
    Journal,
}

impl Kind {
    fn parse(text: &str) -> Option<Kind> {
        Some(match text.trim().to_ascii_lowercase().as_str() {
            "registry" => Kind::Registry,
            "file" => Kind::File,
            "service" => Kind::Service,
            "process" => Kind::Process,
            "event" => Kind::Event,
            "journal" => Kind::Journal,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Registry => "registry",
            Kind::File => "file",
            Kind::Service => "service",
            Kind::Process => "process",
            Kind::Event => "event",
            Kind::Journal => "journal",
        }
    }

    /// The platform a kind only exists on.
    fn only_on(self) -> Option<&'static str> {
        match self {
            Kind::Registry | Kind::Event => Some("windows"),
            Kind::Journal => Some("linux"),
            _ => None,
        }
    }

    /// The locator keys this kind takes (required ones first).
    fn locators(self) -> &'static [&'static str] {
        match self {
            Kind::Registry => &["key", "value"],
            Kind::File => &["path"],
            Kind::Service | Kind::Process => &["name"],
            Kind::Event => &["log", "ids", "provider", "within_hours"],
            Kind::Journal => &["unit", "within_hours"],
        }
    }

    /// The condition keys this kind takes.
    fn conditions(self) -> &'static [&'static str] {
        match self {
            Kind::Registry => &["exists", "equals", "contains", "matches", "min", "max", "min_version"],
            Kind::File => &["exists", "contains", "matches", "min_version", "max_age_days"],
            Kind::Service => &["exists", "state"],
            Kind::Process => &["exists"],
            Kind::Event => &["max_count"],
            Kind::Journal => &["max_count", "matches"],
        }
    }
}

/// Where a registry rule looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
    Users,
}

/// A registry value as read, in the few shapes a rule can compare.
#[derive(Debug, Clone, PartialEq)]
pub enum RegData {
    Text(String),
    Number(u64),
    Lines(Vec<String>),
    /// Binary data: only its size is shown.
    Binary(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
}

/// The test a rule applies to what it finds.
#[derive(Debug, Clone)]
pub enum Cond {
    Exists(bool),
    Equals(String),
    Contains(String),
    Matches(Regex),
    Range(Option<f64>, Option<f64>),
    MinVersion(String),
    State(ServiceState),
    MaxAge(f64),
    /// At most this many matching events or journal entries.
    AtMost(u32),
}

/// What to look at, checked and expanded.
#[derive(Debug, Clone)]
pub enum Target {
    Registry { hive: Hive, subkey: String, value: Option<String> },
    File(PathBuf),
    Service(String),
    Process(String),
    Event { log: String, provider: Option<String>, ids: Vec<u32>, hours: u32 },
    Journal { unit: String, hours: u32, filter: Option<Regex> },
}

/// A rule that's ready to run.
#[derive(Debug, Clone)]
pub struct Plan {
    pub label: String,
    pub kind: Kind,
    pub platform: Option<&'static str>,
    pub severity: Severity,
    pub help: Option<String>,
    pub target: Target,
    pub cond: Cond,
}

/// What a rule found: whether it passed, and the row's value text.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub pass: bool,
    pub text: String,
}

impl Verdict {
    fn new(pass: bool, text: impl Into<String>) -> Self {
        Self { pass, text: text.into() }
    }
}

/// Is this a name that can go into an event-log query? Log and provider
/// names are letters, digits, spaces and `-_./`: nothing that could close
/// the quote around it or start an XPath expression.
pub fn valid_event_name(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty() && name.len() <= 256 && name.chars().all(|c| c.is_ascii_alphanumeric() || " -_./".contains(c))
}

/// The registry root and the rest of the path, from `HKLM\SOFTWARE\…`.
pub fn parse_key(key: &str) -> Result<(Hive, String), String> {
    let key = key.trim().trim_end_matches('\\');
    let (root, rest) = key.split_once('\\').unwrap_or((key, ""));
    let hive = match root.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Hive::LocalMachine,
        "HKCU" | "HKEY_CURRENT_USER" => Hive::CurrentUser,
        "HKU" | "HKEY_USERS" => Hive::Users,
        _ => return Err(format!("`{root}` isn't a registry root: start the key with HKLM\\, HKCU\\ or HKU\\")),
    };
    let rest = rest.trim_matches('\\');
    if rest.is_empty() {
        return Err("Name a key under the root, like HKLM\\SOFTWARE\\Vendor\\App.".into());
    }
    if rest.len() > 1024 || rest.contains('\0') || rest.contains("\\\\") {
        return Err("That key path isn't valid.".into());
    }
    Ok((hive, rest.to_string()))
}

/// Expand `%NAME%` (Windows) or a leading `~/` and `$HOME` (Linux) from
/// `lookup`, and insist on an absolute path.
pub fn expand_path(path: &str, windows: bool, lookup: impl Fn(&str) -> Option<String>) -> Result<PathBuf, String> {
    let path = path.trim();
    if path.is_empty() || path.len() > 1024 || path.contains('\0') {
        return Err("Give the file's full path.".into());
    }
    let expanded = if windows {
        let mut out = String::new();
        let mut rest = path;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let end = after.find('%').ok_or("A `%` in the path isn't closed.")?;
            let name = &after[..end];
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || "_()".contains(c)) {
                return Err(format!("`%{name}%` isn't an environment variable name."));
            }
            out.push_str(&lookup(name).ok_or_else(|| format!("%{name}% isn't set on this PC."))?);
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        out
    } else {
        let home = || lookup("HOME").ok_or_else(|| "$HOME isn't set.".to_string());
        if let Some(rest) = path.strip_prefix("~/") {
            format!("{}/{rest}", home()?.trim_end_matches('/'))
        } else if let Some(rest) = path.strip_prefix("$HOME/") {
            format!("{}/{rest}", home()?.trim_end_matches('/'))
        } else {
            path.to_string()
        }
    };
    let absolute = if windows {
        let b = expanded.as_bytes();
        (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) || expanded.starts_with(r"\\")
    } else {
        expanded.starts_with('/')
    };
    if !absolute {
        return Err(format!("`{path}` isn't a full path."));
    }
    Ok(PathBuf::from(expanded))
}

fn pattern(text: &str) -> Result<Regex, String> {
    RegexBuilder::new(text)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|e| format!("`matches` isn't a valid pattern: {}", crate::parse::text::first_line(&e.to_string())))
}

fn scalar(v: &toml::Value) -> Result<String, String> {
    Ok(match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => (if *b { "1" } else { "0" }).to_string(),
        _ => return Err("`equals` takes a string or a number.".into()),
    })
}

/// Turn a rule as written into a plan, or say what's wrong with it.
pub fn plan(rule: &Rule, env: &dyn Fn(&str) -> Option<String>) -> Result<Plan, String> {
    let label = rule.label.trim();
    if label.is_empty() {
        return Err("Give it a `label`.".into());
    }
    if label.chars().count() > 120 {
        return Err("Keep the label under 120 characters.".into());
    }
    if let Some(key) = rule.unknown.keys().next() {
        return Err(format!("`{key}` isn't a setting a check takes."));
    }
    let kind = Kind::parse(&rule.kind).ok_or_else(|| {
        format!(
            "`kind = \"{}\"` isn't one ITriage knows: use registry, file, service, process, event or journal.",
            rule.kind
        )
    })?;

    // Keys that don't belong to this kind are a mistake worth naming: a
    // file rule with `equals` was meant to be something else.
    let given: Vec<&str> = [
        ("key", rule.key.is_some()),
        ("value", rule.value.is_some()),
        ("path", rule.path.is_some()),
        ("name", rule.name.is_some()),
        ("log", rule.log.is_some()),
        ("provider", rule.provider.is_some()),
        ("ids", !rule.ids.is_empty()),
        ("unit", rule.unit.is_some()),
        ("within_hours", rule.within_hours.is_some()),
        ("exists", rule.exists.is_some()),
        ("equals", rule.equals.is_some()),
        ("contains", rule.contains.is_some()),
        ("matches", rule.matches.is_some()),
        ("min", rule.min.is_some()),
        ("max", rule.max.is_some()),
        ("min_version", rule.min_version.is_some()),
        ("state", rule.state.is_some()),
        ("max_age_days", rule.max_age_days.is_some()),
        ("max_count", rule.max_count.is_some()),
    ]
    .into_iter()
    .filter(|(_, set)| *set)
    .map(|(k, _)| k)
    .collect();
    if let Some(stray) = given.iter().find(|k| !kind.locators().contains(k) && !kind.conditions().contains(k)) {
        return Err(format!("`{stray}` doesn't apply to a {} check.", kind.name()));
    }

    let severity = match rule.severity.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
        None => Severity::Warning,
        Some(s) => match s.as_str() {
            "info" => Severity::Info,
            "warning" | "warn" => Severity::Warning,
            "critical" | "crit" => Severity::Critical,
            _ => return Err(format!("`severity = \"{s}\"`: use info, warning or critical.")),
        },
    };
    let platform = match rule.platform.as_deref().map(|p| p.trim().to_ascii_lowercase()) {
        None => kind.only_on(),
        Some(p) if p == "windows" || p == "linux" => {
            let p: &'static str = if p == "windows" { "windows" } else { "linux" };
            if kind.only_on().is_some_and(|only| only != p) {
                return Err(format!("A {} check only works on {}.", kind.name(), kind.only_on().unwrap_or_default()));
            }
            Some(p)
        }
        Some(p) => return Err(format!("`platform = \"{p}\"`: use windows or linux.")),
    };
    let help = rule.help.as_deref().map(str::trim).filter(|h| !h.is_empty());
    if help.is_some_and(|h| h.chars().count() > 500) {
        return Err("Keep `help` under 500 characters.".into());
    }
    let hours = rule.within_hours.unwrap_or(24);
    if !(1..=MAX_HOURS).contains(&hours) {
        return Err(format!("`within_hours` goes from 1 to {MAX_HOURS}."));
    }
    let required = |field: &Option<String>, key: &str| -> Result<String, String> {
        field
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("A {} check needs `{key}`.", kind.name()))
    };

    let target = match kind {
        Kind::Registry => {
            let (hive, subkey) = parse_key(&required(&rule.key, "key")?)?;
            let value = rule.value.as_deref().map(str::to_string);
            if value.as_deref().is_some_and(|v| v.len() > 16_383 || v.contains('\0')) {
                return Err("That value name isn't valid.".into());
            }
            Target::Registry { hive, subkey, value }
        }
        Kind::File => {
            let windows = platform.map_or(cfg!(windows), |p| p == "windows");
            let path = required(&rule.path, "path")?;
            // A rule for the other OS is skipped, so its variables can't be
            // looked up here; its shape is still checked.
            if platform.is_some_and(|p| p != std::env::consts::OS) {
                let stand_in = if windows { r"C:\x" } else { "/x" };
                expand_path(&path, windows, |_| Some(stand_in.to_string()))?;
                Target::File(PathBuf::from(path))
            } else {
                Target::File(expand_path(&path, windows, env)?)
            }
        }
        Kind::Service => {
            let name = required(&rule.name, "name")?;
            if !crate::actions::valid_service_name(&name) {
                return Err(format!("`{name}` isn't a service name."));
            }
            Target::Service(name)
        }
        Kind::Process => {
            let name = required(&rule.name, "name")?;
            if name.len() > 255 || name.contains(['/', '\\', '\0']) {
                return Err("Give the program's name, like `ISXAgent.exe`, not a path.".into());
            }
            Target::Process(name)
        }
        Kind::Event => {
            let log = required(&rule.log, "log")?;
            if !valid_event_name(&log) {
                return Err(format!("`{log}` isn't a log name ITriage will query."));
            }
            let provider = rule.provider.as_deref().map(str::trim).filter(|p| !p.is_empty());
            if let Some(p) = provider.filter(|p| !valid_event_name(p)) {
                return Err(format!("`{p}` isn't a provider name ITriage will query."));
            }
            if rule.ids.is_empty() || rule.ids.len() > MAX_IDS {
                return Err(format!("An event check needs `ids`: 1 to {MAX_IDS} event IDs."));
            }
            if let Some(id) = rule.ids.iter().find(|id| **id > 65_535) {
                return Err(format!("{id} isn't an event ID (they go up to 65535)."));
            }
            Target::Event { log, provider: provider.map(str::to_string), ids: rule.ids.clone(), hours }
        }
        Kind::Journal => {
            let unit = required(&rule.unit, "unit")?;
            if !crate::actions::valid_service_name(&unit) {
                return Err(format!("`{unit}` isn't a unit name."));
            }
            let filter = rule.matches.as_deref().map(pattern).transpose()?;
            Target::Journal { unit, hours, filter }
        }
    };

    // One condition per rule (min and max together count as one range).
    let mut conds: Vec<Cond> = Vec::new();
    if let Some(e) = rule.exists {
        conds.push(Cond::Exists(e));
    }
    if let Some(v) = &rule.equals {
        conds.push(Cond::Equals(scalar(v)?));
    }
    if let Some(c) = &rule.contains {
        if c.is_empty() {
            return Err("`contains` needs some text.".into());
        }
        conds.push(Cond::Contains(c.clone()));
    }
    if let Some(m) = &rule.matches {
        if kind != Kind::Journal {
            conds.push(Cond::Matches(pattern(m)?));
        }
    }
    if rule.min.is_some() || rule.max.is_some() {
        if let (Some(lo), Some(hi)) = (rule.min, rule.max) {
            if lo > hi {
                return Err("`min` is above `max`.".into());
            }
        }
        conds.push(Cond::Range(rule.min, rule.max));
    }
    if let Some(v) = &rule.min_version {
        if v.trim().is_empty() {
            return Err("`min_version` needs a version, like \"7.11\".".into());
        }
        conds.push(Cond::MinVersion(v.trim().to_string()));
    }
    if let Some(s) = &rule.state {
        conds.push(Cond::State(match s.trim().to_ascii_lowercase().as_str() {
            "running" => ServiceState::Running,
            "stopped" => ServiceState::Stopped,
            other => return Err(format!("`state = \"{other}\"`: use running or stopped.")),
        }));
    }
    if let Some(d) = rule.max_age_days {
        if !(d > 0.0 && d.is_finite()) {
            return Err("`max_age_days` must be more than 0.".into());
        }
        conds.push(Cond::MaxAge(d));
    }
    if let Some(n) = rule.max_count {
        if n as usize >= MAX_EVENTS {
            return Err(format!("`max_count` goes up to {}.", MAX_EVENTS - 1));
        }
        conds.push(Cond::AtMost(n));
    }
    if conds.len() > 1 {
        return Err("Give one condition per check (`min` and `max` together count as one); split the rest into another [[check]].".into());
    }
    let cond = match conds.pop() {
        Some(c) => c,
        None => match kind {
            Kind::Service => Cond::State(ServiceState::Running),
            Kind::Event | Kind::Journal => Cond::AtMost(0),
            _ => Cond::Exists(true),
        },
    };
    if kind == Kind::File && matches!(cond, Cond::MinVersion(_)) && platform.unwrap_or(std::env::consts::OS) != "windows" {
        return Err("`min_version` on a file reads its Windows version resource; set `platform = \"windows\"`.".into());
    }
    if kind == Kind::Registry && rule.value.is_none() && !matches!(cond, Cond::Exists(_)) {
        return Err("Name the `value` to compare; a key on its own can only be checked with `exists`.".into());
    }

    Ok(Plan { label: label.to_string(), kind, platform, severity, help: help.map(str::to_string), target, cond })
}

fn quoted(s: &str) -> String {
    format!("\"{}\"", crate::parse::text::truncate_chars(s, 120))
}

fn number(text: &str) -> Option<f64> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok().map(|n| n as f64);
    }
    t.parse::<f64>().ok().filter(|n| n.is_finite())
}

fn in_range(n: f64, lo: Option<f64>, hi: Option<f64>) -> bool {
    lo.is_none_or(|lo| n >= lo) && hi.is_none_or(|hi| n <= hi)
}

fn range_text(lo: Option<f64>, hi: Option<f64>) -> String {
    match (lo, hi) {
        (Some(lo), Some(hi)) => format!("expected {lo}–{hi}"),
        (Some(lo), None) => format!("expected at least {lo}"),
        (None, Some(hi)) => format!("expected at most {hi}"),
        (None, None) => String::new(),
    }
}

/// Judge a registry key (`value` is `None` for a key rule) as read.
pub fn judge_registry(cond: &Cond, key_found: bool, value_name: Option<&str>, data: Option<&RegData>) -> Verdict {
    let what = value_name.map(|v| if v.is_empty() { "(Default)".to_string() } else { v.to_string() });
    let Some(name) = what else {
        return match cond {
            Cond::Exists(want) => Verdict::new(key_found == *want, if key_found { "key present" } else { "key not found" }),
            _ => Verdict::new(false, "key not compared"),
        };
    };
    let Some(data) = data else {
        let found = if key_found { format!("{name} not set") } else { "key not found".to_string() };
        return Verdict::new(matches!(cond, Cond::Exists(false)), found);
    };
    let shown = match data {
        RegData::Text(s) => quoted(s),
        RegData::Number(n) => format!("{n} (0x{n:X})"),
        RegData::Lines(lines) => quoted(&lines.join("; ")),
        RegData::Binary(n) => format!("{n} bytes of binary data"),
    };
    let text_of = |d: &RegData| match d {
        RegData::Text(s) => Some(s.clone()),
        RegData::Number(n) => Some(n.to_string()),
        RegData::Lines(l) => Some(l.join("\n")),
        RegData::Binary(_) => None,
    };
    match cond {
        Cond::Exists(want) => Verdict::new(*want, format!("{name} = {shown}")),
        Cond::Equals(expected) => {
            let pass = match data {
                RegData::Number(n) => number(expected).is_some_and(|e| e == *n as f64),
                RegData::Lines(l) => l.iter().any(|line| line.eq_ignore_ascii_case(expected)),
                _ => text_of(data).is_some_and(|t| t.trim().eq_ignore_ascii_case(expected.trim())),
            };
            let tail = if pass { String::new() } else { format!(" · expected {}", quoted(expected)) };
            Verdict::new(pass, format!("{name} = {shown}{tail}"))
        }
        Cond::Contains(needle) => {
            let pass = text_of(data).is_some_and(|t| t.to_lowercase().contains(&needle.to_lowercase()));
            let tail = if pass { String::new() } else { format!(" · doesn't contain {}", quoted(needle)) };
            Verdict::new(pass, format!("{name} = {shown}{tail}"))
        }
        Cond::Matches(re) => {
            let pass = text_of(data).is_some_and(|t| re.is_match(&t));
            let tail = if pass { String::new() } else { " · doesn't match the expected pattern".into() };
            Verdict::new(pass, format!("{name} = {shown}{tail}"))
        }
        Cond::Range(lo, hi) => {
            let n = match data {
                RegData::Number(n) => Some(*n as f64),
                _ => text_of(data).and_then(|t| number(&t)),
            };
            match n {
                Some(n) if in_range(n, *lo, *hi) => Verdict::new(true, format!("{name} = {shown}")),
                Some(_) => Verdict::new(false, format!("{name} = {shown} · {}", range_text(*lo, *hi))),
                None => Verdict::new(false, format!("{name} = {shown} · not a number")),
            }
        }
        Cond::MinVersion(min) => match text_of(data) {
            Some(v) if crate::parse::version::meets(v.trim(), min) => Verdict::new(true, format!("{name} = {shown}")),
            Some(_) => Verdict::new(false, format!("{name} = {shown} · needs {min} or later")),
            None => Verdict::new(false, format!("{name} = {shown} · not a version")),
        },
        _ => Verdict::new(false, format!("{name} = {shown}")),
    }
}

/// What a file rule found on disk.
#[derive(Debug, Clone, Default)]
pub struct FileSeen {
    pub exists: bool,
    pub is_dir: bool,
    /// Text read for `contains` / `matches` (at most [`MAX_FILE_BYTES`]).
    pub text: Option<String>,
    /// Only part of the file was read.
    pub truncated: bool,
    pub version: Option<String>,
    /// Days since it last changed.
    pub age_days: Option<f64>,
}

pub fn judge_file(cond: &Cond, seen: &FileSeen) -> Verdict {
    let kind = if seen.is_dir { "folder" } else { "file" };
    if !seen.exists {
        return Verdict::new(matches!(cond, Cond::Exists(false)), "not found");
    }
    let part = if seen.truncated { " (first 1 MB)" } else { "" };
    match cond {
        Cond::Exists(want) => Verdict::new(*want, format!("{kind} present")),
        Cond::Contains(needle) => match &seen.text {
            Some(t) if t.to_lowercase().contains(&needle.to_lowercase()) => Verdict::new(true, format!("contains {}", quoted(needle))),
            Some(_) => Verdict::new(false, format!("doesn't contain {}{part}", quoted(needle))),
            None => Verdict::new(false, format!("{kind} couldn't be read as text")),
        },
        Cond::Matches(re) => match &seen.text {
            Some(t) if re.is_match(t) => Verdict::new(true, "matches the expected pattern"),
            Some(_) => Verdict::new(false, format!("doesn't match the expected pattern{part}")),
            None => Verdict::new(false, format!("{kind} couldn't be read as text")),
        },
        Cond::MinVersion(min) => match &seen.version {
            Some(v) if crate::parse::version::meets(v, min) => Verdict::new(true, format!("version {v}")),
            Some(v) => Verdict::new(false, format!("version {v} · needs {min} or later")),
            None => Verdict::new(false, "no version information in the file"),
        },
        Cond::MaxAge(days) => match seen.age_days {
            Some(age) => {
                let ago = crate::util::ago((age * 86_400.0).max(0.0) as u64);
                Verdict::new(age <= *days, format!("changed {ago}{}", if age <= *days { String::new() } else { format!(" · expected within {days} day{}", if *days == 1.0 { "" } else { "s" }) }))
            }
            None => Verdict::new(false, "its last-changed time couldn't be read"),
        },
        _ => Verdict::new(false, format!("{kind} present")),
    }
}

/// A service as found: missing, or running / stopped (with how it starts).
pub fn judge_service(cond: &Cond, state: Option<(bool, &str)>) -> Verdict {
    match (cond, state) {
        (Cond::Exists(want), None) => Verdict::new(!*want, "not installed"),
        (Cond::Exists(want), Some((_, shown))) => Verdict::new(*want, format!("installed · {shown}")),
        (Cond::State(_), None) => Verdict::new(false, "not installed"),
        (Cond::State(ServiceState::Running), Some((running, shown))) => {
            Verdict::new(running, if running { shown.to_string() } else { format!("{shown} · expected running") })
        }
        (Cond::State(ServiceState::Stopped), Some((running, shown))) => {
            Verdict::new(!running, if running { format!("{shown} · expected stopped") } else { shown.to_string() })
        }
        (_, Some((_, shown))) => Verdict::new(false, shown.to_string()),
        (_, None) => Verdict::new(false, "not installed"),
    }
}

/// How many copies of a program are running.
pub fn judge_process(cond: &Cond, running: usize) -> Verdict {
    let want = !matches!(cond, Cond::Exists(false));
    let text = match running {
        0 => "not running".to_string(),
        1 => "running".to_string(),
        n => format!("running ({n} copies)"),
    };
    Verdict::new((running > 0) == want, text)
}

/// Matching events or journal entries, and the newest one's time.
pub fn judge_count(cond: &Cond, count: usize, capped: bool, hours: u32, newest: Option<&str>) -> Verdict {
    let allowed = match cond {
        Cond::AtMost(n) => *n as usize,
        _ => 0,
    };
    let span = match hours {
        24 => "day".to_string(),
        1 => "hour".to_string(),
        h if h.is_multiple_of(24) => format!("{} days", h / 24),
        h => format!("{h} hours"),
    };
    if count == 0 {
        return Verdict::new(true, format!("none in the last {span}"));
    }
    let n = if capped { format!("{count}+") } else { count.to_string() };
    let mut text = format!("{n} in the last {span}");
    if count > allowed {
        text.push_str(&format!(" · {allowed} allowed"));
    }
    if let Some(t) = newest {
        text.push_str(&format!(" · newest {t}"));
    }
    Verdict::new(count <= allowed, text)
}

pub struct SiteRules;

impl TriageModule for SiteRules {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "site.rules",
            "Site custom checks",
            Category::Site,
            "The site profile's own read-only checks ([[check]]): registry values, files, services, programs, and events or journal entries, each with what it should be.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let profile = ctx.profile();
        if profile.checks.is_empty() {
            return Ok(Output::new(
                "No custom checks in the site profile",
                vec![Finding::info(
                    "Site profile",
                    format!(
                        "{} has no [[check]] entries",
                        if profile.name.is_empty() { "The default profile" } else { profile.name.as_str() }
                    ),
                )],
            ));
        }
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let os = std::env::consts::OS;
        let mut findings = Vec::new();
        let (mut passed, mut failed, mut broken, mut elsewhere) = (0usize, 0usize, 0usize, 0usize);
        for rule in profile.checks.iter().take(MAX_RULES) {
            let label = if rule.label.trim().is_empty() { "Unnamed check".to_string() } else { rule.label.trim().to_string() };
            let plan = match plan(rule, &env) {
                Ok(p) => p,
                Err(why) => {
                    broken += 1;
                    findings.push(
                        Finding::warn(label, "set up wrong in the profile")
                            .with_detail(format!("{why} Fix this [[check]] in the site profile; the other checks still ran.")),
                    );
                    continue;
                }
            };
            if plan.platform.is_some_and(|p| p != os) {
                elsewhere += 1;
                continue;
            }
            ctx.log(format!("Checking {}…", plan.label));
            match run(&plan) {
                Ok(v) if v.pass => {
                    passed += 1;
                    findings.push(Finding::ok(plan.label, v.text));
                }
                Ok(v) => {
                    failed += 1;
                    let mut f = Finding::new(plan.label.clone(), v.text, plan.severity);
                    if let Some(h) = &plan.help {
                        f = f.with_detail(h.clone());
                    }
                    if let (Target::Service(name), Cond::State(ServiceState::Running)) = (&plan.target, &plan.cond) {
                        if crate::actions::valid_service_name(name) {
                            f = f.with_action(crate::actions::offer("start-service", Some(name)));
                        }
                    }
                    findings.push(f);
                }
                Err(e) => {
                    failed += 1;
                    findings.push(Finding::warn(plan.label, format!("couldn't check: {e}")));
                }
            }
        }
        if profile.checks.len() > MAX_RULES {
            findings.push(Finding::warn(
                "Too many checks",
                format!("The profile has {} [[check]] entries; the first {MAX_RULES} ran.", profile.checks.len()),
            ));
        }
        let ran = passed + failed;
        let mut summary = if ran == 0 {
            "No custom checks apply here".to_string()
        } else if failed == 0 && ran == 1 {
            "The custom check passed".to_string()
        } else if failed == 0 {
            format!("All {ran} custom checks passed")
        } else {
            format!("{passed} of {ran} custom checks passed")
        };
        if broken > 0 {
            summary.push_str(&format!(" · {broken} set up wrong"));
        }
        if elsewhere > 0 {
            findings.push(Finding::info(
                "Other platforms",
                format!("{elsewhere} check{} for another operating system skipped", crate::util::plural(elsewhere)),
            ));
        }
        Ok(Output::new(summary, findings))
    }
}

/// Look, then judge.
fn run(plan: &Plan) -> Result<Verdict, String> {
    match &plan.target {
        Target::Registry { hive, subkey, value } => {
            let (found, data) = imp::registry(*hive, subkey, value.as_deref())?;
            Ok(judge_registry(&plan.cond, found, value.as_deref(), data.as_ref()))
        }
        Target::File(path) => Ok(judge_file(&plan.cond, &look_at_file(path, &plan.cond))),
        Target::Service(name) => {
            let state = crate::site::checks::service_state(name)?;
            use crate::site::checks::State;
            let seen = match &state {
                State::Missing => None,
                State::Running => Some((true, "running")),
                State::Stopped(shown, _) => Some((false, shown.as_str())),
            };
            Ok(judge_service(&plan.cond, seen))
        }
        Target::Process(name) => Ok(judge_process(&plan.cond, running(name))),
        Target::Event { log, provider, ids, hours } => {
            let (count, newest) = imp::events(log, provider.as_deref(), ids, *hours, MAX_EVENTS)?;
            Ok(judge_count(&plan.cond, count, count >= MAX_EVENTS, *hours, newest.as_deref()))
        }
        Target::Journal { unit, hours, filter } => {
            let (count, newest) = imp::journal(unit, *hours, filter.as_ref(), MAX_EVENTS)?;
            Ok(judge_count(&plan.cond, count, count >= MAX_EVENTS, *hours, newest.as_deref()))
        }
    }
}

/// Read only what the condition needs.
fn look_at_file(path: &std::path::Path, cond: &Cond) -> FileSeen {
    let Ok(meta) = std::fs::metadata(path) else {
        return FileSeen::default();
    };
    let mut seen = FileSeen { exists: true, is_dir: meta.is_dir(), ..FileSeen::default() };
    match cond {
        Cond::Contains(_) | Cond::Matches(_) if meta.is_file() => {
            use std::io::Read;
            if let Ok(file) = std::fs::File::open(path) {
                let mut bytes = Vec::new();
                if file.take(MAX_FILE_BYTES).read_to_end(&mut bytes).is_ok() {
                    seen.truncated = meta.len() > MAX_FILE_BYTES;
                    seen.text = Some(decode(&bytes));
                }
            }
        }
        Cond::MinVersion(_) => seen.version = imp::file_version(path),
        Cond::MaxAge(_) => {
            seen.age_days = meta
                .modified()
                .ok()
                .map(|t| std::time::SystemTime::now().duration_since(t).map(|d| d.as_secs_f64()).unwrap_or(0.0) / 86_400.0);
        }
        _ => {}
    }
    seen
}

/// Text from a config file: UTF-16 (with its byte-order mark, as Windows
/// tools often write), else UTF-8.
pub fn decode(bytes: &[u8]) -> String {
    let utf16 = |rest: &[u8], le: bool| {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| if le { u16::from_le_bytes(c) } else { u16::from_be_bytes(c) })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Running processes with this name (case-insensitive; `.exe` optional).
/// Linux shortens a process's own name to 15 characters, so the program
/// file's name counts too.
fn running(name: &str) -> usize {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};
    let bare = |n: &str| {
        let n = n.trim().to_lowercase();
        n.strip_suffix(".exe").unwrap_or(&n).to_string()
    };
    let want = bare(name);
    let sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet)),
    );
    sys.processes()
        .values()
        .filter(|p| {
            bare(&p.name().to_string_lossy()) == want
                || p.exe().and_then(|e| e.file_name()).is_some_and(|f| bare(&f.to_string_lossy()) == want)
        })
        .count()
}

/// Count `journalctl --output=json --reverse` lines (newest first) that
/// pass `filter`, up to `max`, with the newest one's time.
#[cfg_attr(windows, allow(dead_code))]
fn count_journal(stdout: &str, filter: Option<&Regex>, max: usize) -> (usize, Option<String>) {
    let mut count = 0usize;
    let mut newest = None;
    for entry in stdout.lines().filter_map(crate::parse::journal::parse_line) {
        if filter.is_some_and(|re| !re.is_match(&entry.message)) {
            continue;
        }
        if newest.is_none() {
            newest = entry.epoch.map(crate::parse::time::epoch_to_rfc3339);
        }
        count += 1;
        if count >= max {
            break;
        }
    }
    (count, newest)
}

#[cfg(windows)]
mod imp {
    use super::{Hive, RegData};
    use crate::win::registry::{self as reg, HKCU, HKLM, HKU};

    pub fn registry(hive: Hive, subkey: &str, value: Option<&str>) -> Result<(bool, Option<RegData>), String> {
        let root = match hive {
            Hive::LocalMachine => HKLM,
            Hive::CurrentUser => HKCU,
            Hive::Users => HKU,
        };
        if !reg::key_exists(root, subkey) {
            return Ok((false, None));
        }
        let Some(value) = value else {
            return Ok((true, None));
        };
        Ok((true, reg::read_any(root, subkey, value).map(|v| match v {
            reg::Data::Text(s) => RegData::Text(s),
            reg::Data::Number(n) => RegData::Number(n),
            reg::Data::Lines(l) => RegData::Lines(l),
            reg::Data::Binary(n) => RegData::Binary(n),
        })))
    }

    pub fn events(log: &str, provider: Option<&str>, ids: &[u32], hours: u32, max: usize) -> Result<(usize, Option<String>), String> {
        crate::win::eventlog::count_matching(log, provider, ids, hours, max)
    }

    pub fn journal(_: &str, _: u32, _: Option<&regex::Regex>, _: usize) -> Result<(usize, Option<String>), String> {
        Err("the systemd journal is Linux-only".into())
    }

    pub fn file_version(path: &std::path::Path) -> Option<String> {
        crate::win::apps::file_version(path)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{Hive, RegData};
    use crate::util::{capture_for, cmd, command_exists};

    pub fn registry(_: Hive, _: &str, _: Option<&str>) -> Result<(bool, Option<RegData>), String> {
        Err("the registry is Windows-only".into())
    }

    pub fn events(_: &str, _: Option<&str>, _: &[u32], _: u32, _: usize) -> Result<(usize, Option<String>), String> {
        Err("Windows event logs are Windows-only".into())
    }

    /// Entries from one unit in the last `hours`: errors and worse, or with
    /// a filter, any entry whose message matches it.
    pub fn journal(unit: &str, hours: u32, filter: Option<&regex::Regex>, max: usize) -> Result<(usize, Option<String>), String> {
        if !command_exists("journalctl") {
            return Err("journalctl not found".into());
        }
        let since = format!("--since=-{hours}h");
        let mut c = cmd("journalctl");
        // No --quiet: its stderr says when there's no journal, or only part of it.
        c.args(["--no-pager", since.as_str(), "--reverse", "--lines=5000", "--output=json"])
            .args(["--output-fields=PRIORITY,MESSAGE,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT"]);
        if filter.is_none() {
            c.arg("--priority=3");
        }
        c.arg(format!("--unit={unit}")).env("LC_ALL", "C");
        let out = capture_for(c, std::time::Duration::from_secs(60))?;
        if !out.success() && out.stdout.trim().is_empty() {
            return Err(format!("journalctl failed: {}", crate::parse::text::first_line(&out.combined())));
        }
        let (count, newest) = super::count_journal(&out.stdout, filter, max);
        // "None" from a journal that records nothing, or that this account
        // can only partly see, would be a false all-clear.
        if count == 0 && (out.stderr.contains("No journal files were found") || journal_is_empty()) {
            return Err("the systemd journal is empty, so journald isn't recording here".into());
        }
        if count == 0 && out.stderr.contains("not seeing messages from other users") {
            return Err("only this account's own journal is visible: run as root or add it to the systemd-journal group".into());
        }
        Ok((count, newest))
    }

    /// No entries at all, at any priority, from any unit. (With JSON
    /// output journalctl says nothing about an empty journal.)
    fn journal_is_empty() -> bool {
        let mut c = cmd("journalctl");
        c.args(["--no-pager", "--lines=1", "--output=cat"]).env("LC_ALL", "C");
        crate::util::capture(c).map(|o| o.stdout.trim().is_empty()).unwrap_or(true)
    }

    pub fn file_version(_: &std::path::Path) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(toml_text: &str) -> Rule {
        #[derive(Deserialize)]
        struct One {
            check: Vec<Rule>,
        }
        toml::from_str::<One>(toml_text).expect("test rule parses").check.remove(0)
    }

    fn env(name: &str) -> Option<String> {
        match name {
            "ProgramFiles" => Some(r"C:\Program Files".into()),
            "ProgramFiles(x86)" => Some(r"C:\Program Files (x86)".into()),
            "HOME" => Some("/home/jparker".into()),
            _ => None,
        }
    }

    fn planned(toml_text: &str) -> Result<Plan, String> {
        plan(&rule(toml_text), &env)
    }

    #[test]
    fn a_registry_rule_plans() {
        let p = planned(
            r#"[[check]]
            label = "Badge agent appliance"
            kind = "registry"
            key = 'HKLM\SOFTWARE\SSOProvider\ISXAgent\'
            value = "IPTXPrimServer"
            equals = "imprivata.example.org"
            severity = "critical"
            help = "Re-run the agent installer with the production appliance."
            "#,
        )
        .unwrap();
        assert_eq!(p.kind, Kind::Registry);
        assert_eq!(p.platform, Some("windows"), "registry rules are Windows-only");
        assert_eq!(p.severity, Severity::Critical);
        match &p.target {
            Target::Registry { hive, subkey, value } => {
                assert_eq!(*hive, Hive::LocalMachine);
                assert_eq!(subkey, r"SOFTWARE\SSOProvider\ISXAgent", "trailing backslash dropped");
                assert_eq!(value.as_deref(), Some("IPTXPrimServer"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&p.cond, Cond::Equals(e) if e == "imprivata.example.org"));
    }

    #[test]
    fn mistakes_name_the_problem() {
        let cases = [
            ("kind = \"registry\"\nkey = 'HKLM\\X'", "label"),
            ("label = \"x\"\nkind = \"script\"", "isn't one ITriage knows"),
            ("label = \"x\"\nkind = \"file\"\npath = 'C:\\x'\nequals = \"1\"", "`equals` doesn't apply to a file check"),
            ("label = \"x\"\nkind = \"registry\"\nkey = 'HKCR\\x'", "isn't a registry root"),
            ("label = \"x\"\nkind = \"registry\"\nkey = 'HKLM'", "Name a key"),
            ("label = \"x\"\nkind = \"registry\"\nkey = 'HKLM\\x'\nequals = \"1\"", "Name the `value`"),
            ("label = \"x\"\nkind = \"file\"\npath = 'C:\\x'\ncontians = \"y\"", "`contians` isn't a setting"),
            ("label = \"x\"\nkind = \"file\"\nplatform = \"windows\"\npath = 'C:\\x'\ncontains = \"a\"\nmatches = \"b\"", "one condition per check"),
            ("label = \"x\"\nkind = \"event\"\nlog = \"System\"", "needs `ids`"),
            ("label = \"x\"\nkind = \"event\"\nlog = \"System' or 1=1\"\nids = [1]", "isn't a log name"),
            ("label = \"x\"\nkind = \"event\"\nlog = \"System\"\nprovider = \"a']]\"\nids = [1]", "isn't a provider name"),
            ("label = \"x\"\nkind = \"event\"\nlog = \"System\"\nids = [70000]", "isn't an event ID"),
            ("label = \"x\"\nkind = \"event\"\nlog = \"System\"\nids = [1]\nwithin_hours = 9999", "within_hours"),
            ("label = \"x\"\nkind = \"journal\"\nunit = \"sssd\"\nplatform = \"windows\"", "only works on linux"),
            ("label = \"x\"\nkind = \"service\"\nname = \"Spooler\"\nstate = \"paused\"", "use running or stopped"),
            ("label = \"x\"\nkind = \"service\"\nname = \"a;b\"", "isn't a service name"),
            ("label = \"x\"\nkind = \"process\"\nname = 'C:\\x\\agent.exe'", "not a path"),
            ("label = \"x\"\nkind = \"file\"\nplatform = \"linux\"\npath = \"/etc/x\"\nmatches = \"(\"", "isn't a valid pattern"),
            ("label = \"x\"\nkind = \"file\"\nplatform = \"linux\"\npath = \"relative/x\"", "isn't a full path"),
            ("label = \"x\"\nkind = \"file\"\nplatform = \"linux\"\npath = \"/x\"\nmin_version = \"1\"", "Windows version resource"),
            ("label = \"x\"\nkind = \"registry\"\nkey = 'HKLM\\x'\nvalue = \"v\"\nmin = 5\nmax = 1", "`min` is above `max`"),
            ("label = \"x\"\nkind = \"process\"\nname = \"x\"\nseverity = \"urgent\"", "use info, warning or critical"),
        ];
        for (body, expect) in cases {
            let err = planned(&format!("[[check]]\n{body}")).expect_err(body);
            assert!(err.contains(expect), "{body}\n→ {err}");
        }
    }

    #[test]
    fn defaults_per_kind() {
        let svc = planned("[[check]]\nlabel = \"Spooler\"\nkind = \"service\"\nname = \"Spooler\"").unwrap();
        assert!(matches!(svc.cond, Cond::State(ServiceState::Running)));
        assert_eq!(svc.severity, Severity::Warning);
        assert_eq!(svc.platform, None, "services exist on both");
        let ev = planned("[[check]]\nlabel = \"Temp profiles\"\nkind = \"event\"\nlog = \"Application\"\nprovider = \"Microsoft-Windows-User Profiles Service\"\nids = [1511, 1515]").unwrap();
        assert!(matches!(ev.cond, Cond::AtMost(0)));
        assert!(matches!(&ev.target, Target::Event { hours: 24, ids, .. } if ids == &vec![1511, 1515]));
        let proc_ = planned("[[check]]\nlabel = \"Agent\"\nkind = \"process\"\nname = \"ISXAgent.exe\"").unwrap();
        assert!(matches!(proc_.cond, Cond::Exists(true)));
        let j = planned("[[check]]\nlabel = \"SSSD\"\nkind = \"journal\"\nunit = \"sssd.service\"\nmatches = \"(?i)offline\"\nmax_count = 2").unwrap();
        assert_eq!(j.platform, Some("linux"));
        assert!(matches!(j.cond, Cond::AtMost(2)), "matches picks journal entries; it isn't the condition");
        assert!(matches!(&j.target, Target::Journal { filter: Some(_), .. }));
    }

    #[test]
    fn paths_expand() {
        assert_eq!(
            expand_path(r"%ProgramFiles(x86)%\Imprivata\agent.ini", true, env).unwrap(),
            PathBuf::from(r"C:\Program Files (x86)\Imprivata\agent.ini")
        );
        assert_eq!(expand_path(r"\\fs01\share\x.txt", true, env).unwrap(), PathBuf::from(r"\\fs01\share\x.txt"));
        assert_eq!(expand_path("~/.config/x.conf", false, env).unwrap(), PathBuf::from("/home/jparker/.config/x.conf"));
        assert_eq!(expand_path("$HOME/x", false, env).unwrap(), PathBuf::from("/home/jparker/x"));
        for bad in [r"%ProgramFiles", r"%%\x", r"%a b%\x", r"x\y"] {
            assert!(expand_path(bad, true, env).is_err(), "{bad}");
        }
        // A Windows rule on Linux isn't expanded (or refused) here: it's skipped.
        let p = planned("[[check]]\nlabel = \"x\"\nkind = \"file\"\nplatform = \"windows\"\npath = '%NOPE%\\x'");
        if cfg!(windows) {
            assert!(p.is_err());
        } else {
            assert!(p.is_ok());
        }
    }

    #[test]
    fn registry_values_are_judged() {
        let text = RegData::Text("Imprivata.Example.org".into());
        let eq = |e: &str| Cond::Equals(e.into());
        assert!(judge_registry(&eq("imprivata.example.org"), true, Some("Server"), Some(&text)).pass, "case-insensitive");
        let v = judge_registry(&eq("prod.example.org"), true, Some("Server"), Some(&text));
        assert!(!v.pass && v.text.contains("expected \"prod.example.org\""), "{}", v.text);
        let n = RegData::Number(1);
        assert!(judge_registry(&eq("1"), true, Some("Enabled"), Some(&n)).pass);
        assert!(judge_registry(&eq("0x1"), true, Some("Enabled"), Some(&n)).pass, "hex works");
        assert!(judge_registry(&Cond::Range(Some(1.0), Some(5.0)), true, Some("n"), Some(&RegData::Number(3))).pass);
        assert!(!judge_registry(&Cond::Range(None, Some(2.0)), true, Some("n"), Some(&RegData::Number(3))).pass);
        assert!(judge_registry(&Cond::MinVersion("7.11".into()), true, Some("Version"), Some(&RegData::Text("7.12.0.4".into()))).pass);
        assert!(!judge_registry(&Cond::MinVersion("7.11".into()), true, Some("Version"), Some(&RegData::Text("7.9".into()))).pass);
        let lines = RegData::Lines(vec!["a.example.org".into(), "b.example.org".into()]);
        assert!(judge_registry(&eq("B.example.org"), true, Some("Servers"), Some(&lines)).pass, "one of the lines");
        assert!(judge_registry(&Cond::Contains("b.ex".into()), true, Some("Servers"), Some(&lines)).pass);
        // Missing things.
        assert!(!judge_registry(&eq("1"), true, Some("Enabled"), None).pass);
        assert_eq!(judge_registry(&eq("1"), true, Some("Enabled"), None).text, "Enabled not set");
        assert!(judge_registry(&Cond::Exists(false), true, Some("Enabled"), None).pass);
        assert_eq!(judge_registry(&Cond::Exists(true), false, None, None).text, "key not found");
        assert!(judge_registry(&Cond::Exists(true), true, Some(""), Some(&text)).text.starts_with("(Default) = "));
        let bin = judge_registry(&Cond::Contains("x".into()), true, Some("Blob"), Some(&RegData::Binary(16)));
        assert!(!bin.pass && bin.text.contains("16 bytes"));
    }

    #[test]
    fn files_are_judged_for_real() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-rules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let utf8 = dir.join("agent.conf");
        std::fs::write(&utf8, "[server]\nhost = Imprivata.Example.org\n").unwrap();
        let utf16 = dir.join("agent16.ini");
        let mut bytes = vec![0xFF, 0xFE];
        for u in "Host=prod01".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(&utf16, bytes).unwrap();

        let contains = Cond::Contains("imprivata.example.org".into());
        assert!(judge_file(&contains, &look_at_file(&utf8, &contains)).pass);
        let re = Cond::Matches(pattern(r"(?mi)^host = \S+\.example\.org$").unwrap());
        assert!(judge_file(&re, &look_at_file(&utf8, &re)).pass);
        let c16 = Cond::Contains("host=prod01".into());
        assert!(judge_file(&c16, &look_at_file(&utf16, &c16)).pass, "UTF-16 files are read as text");
        let fresh = Cond::MaxAge(1.0);
        let v = judge_file(&fresh, &look_at_file(&utf8, &fresh));
        assert!(v.pass && v.text.starts_with("changed"), "{}", v.text);
        let missing = dir.join("nope");
        assert!(!judge_file(&Cond::Exists(true), &look_at_file(&missing, &Cond::Exists(true))).pass);
        assert!(judge_file(&Cond::Exists(false), &look_at_file(&missing, &Cond::Exists(false))).pass);
        assert_eq!(judge_file(&Cond::Exists(true), &look_at_file(&dir, &Cond::Exists(true))).text, "folder present");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn services_processes_and_counts() {
        let run = Cond::State(ServiceState::Running);
        assert!(judge_service(&run, Some((true, "running"))).pass);
        let v = judge_service(&run, Some((false, "STOPPED · Automatic")));
        assert!(!v.pass && v.text.ends_with("expected running"));
        assert!(!judge_service(&run, None).pass);
        assert!(judge_service(&Cond::Exists(false), None).pass);
        assert!(judge_service(&Cond::State(ServiceState::Stopped), Some((false, "STOPPED · Disabled"))).pass);

        assert!(judge_process(&Cond::Exists(true), 2).pass);
        assert_eq!(judge_process(&Cond::Exists(true), 2).text, "running (2 copies)");
        assert!(!judge_process(&Cond::Exists(true), 0).pass);
        assert!(judge_process(&Cond::Exists(false), 0).pass);

        assert!(judge_count(&Cond::AtMost(0), 0, false, 24, None).pass);
        let v = judge_count(&Cond::AtMost(0), 3, false, 24, Some("2026-11-20T08:14:03Z"));
        assert!(!v.pass);
        assert_eq!(v.text, "3 in the last day · 0 allowed · newest 2026-11-20T08:14:03Z");
        assert!(judge_count(&Cond::AtMost(5), 3, false, 6, None).pass);
        assert!(judge_count(&Cond::AtMost(5), 1000, true, 6, None).text.starts_with("1000+ in the last 6 hours"));
    }

    #[test]
    fn journal_lines_are_counted() {
        let out = [
            r#"{"__REALTIME_TIMESTAMP":"1795414443000000","PRIORITY":"6","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.9 port 50122 ssh2"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1795414400000000","PRIORITY":"6","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for jparker"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1795414300000000","PRIORITY":"6","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"FAILED PASSWORD for admin"}"#,
            "not json",
        ]
        .join("\n");
        let failed = pattern("(?i)failed password").unwrap();
        let (n, newest) = count_journal(&out, Some(&failed), 100);
        assert_eq!(n, 2);
        assert_eq!(newest.as_deref(), Some("2026-11-23T06:14:03Z"), "the first line is the newest");
        assert_eq!(count_journal(&out, None, 100).0, 3, "no filter counts every entry journalctl gave");
        assert_eq!(count_journal(&out, None, 2).0, 2, "capped");
    }

    #[test]
    fn the_shipped_examples_are_valid() {
        for text in [
            include_str!("../../../../profiles/clinical-workstation.example.toml"),
            include_str!("../../../../profiles/home-lab.toml"),
        ] {
            let profile = crate::profile::Profile::from_toml(text).unwrap();
            assert!(!profile.checks.is_empty());
            for r in &profile.checks {
                // Real variables where they exist, a stand-in elsewhere.
                let env = |n: &str| std::env::var(n).ok().or_else(|| Some(if cfg!(windows) { r"C:\x".into() } else { "/x".into() }));
                assert!(plan(r, &env).is_ok(), "{}: {:?}", r.label, plan(r, &env).err());
            }
        }
    }

    #[test]
    fn this_platforms_own_process_is_found() {
        let me = std::env::current_exe().unwrap();
        let name = me.file_name().unwrap().to_string_lossy().to_string();
        assert!(running(&name) >= 1, "{name}");
        assert!(running(&name.to_uppercase()) >= 1, "case-insensitive");
        assert_eq!(running("itriage-no-such-program-xyz"), 0);
    }

    #[test]
    fn the_module_reports_each_rule() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-rules-mod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let present = dir.join("present.txt");
        std::fs::write(&present, "ok").unwrap();
        let os = std::env::consts::OS;
        let other = if os == "windows" { "linux" } else { "windows" };
        let profile = crate::profile::Profile::from_toml(&format!(
            r#"
            [[check]]
            label = "Marker file"
            kind = "file"
            platform = "{os}"
            path = '{present}'

            [[check]]
            label = "Missing file"
            kind = "file"
            platform = "{os}"
            path = '{missing}'
            severity = "critical"
            help = "Reinstall the agent."

            [[check]]
            label = "Typo"
            kind = "file"
            platform = "{os}"
            path = '{present}'
            contians = "x"

            [[check]]
            label = "Elsewhere"
            kind = "process"
            platform = "{other}"
            name = "x"
            "#,
            present = present.display(),
            missing = dir.join("missing.txt").display(),
        ))
        .unwrap();
        let ctx = RunContext::silent().with_profile(&profile);
        let r = SiteRules.run(&ctx);
        assert!(r.error.is_none(), "{r:?}");
        assert_eq!(r.summary, "1 of 2 custom checks passed · 1 set up wrong");
        let row = |l: &str| r.findings.iter().find(|f| f.label == l).unwrap_or_else(|| panic!("{l}: {:?}", r.findings));
        assert_eq!(row("Marker file").severity, Severity::Ok);
        assert_eq!(row("Missing file").severity, Severity::Critical);
        assert_eq!(row("Missing file").detail.as_deref(), Some("Reinstall the agent."));
        assert_eq!(row("Typo").severity, Severity::Warning);
        assert!(row("Typo").detail.as_deref().unwrap().contains("`contians`"));
        assert!(row("Other platforms").value.contains("1 check for another"));
        let none = SiteRules.run(&RunContext::silent());
        assert_eq!(none.summary, "No custom checks in the site profile");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
