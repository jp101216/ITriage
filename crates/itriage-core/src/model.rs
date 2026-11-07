//! Shared result types. Everything here is `serde`-serializable so the Tauri
//! command layer can hand it straight to the frontend as JSON, and the JSON /
//! ticket-text exports fall out of the same structs.

use serde::{Deserialize, Serialize};

/// How alarming a single finding is. Drives the colour chip in the UI and the
/// worst-of roll-up on a module card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Critical,
}

impl Severity {
    /// Higher = worse. Used to roll a module's findings up to one status.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Ok => 0,
            Severity::Info => 1,
            Severity::Warning => 2,
            Severity::Critical => 3,
        }
    }
}

/// Which bucket a module lives in. The frontend groups the checklist by this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    System,
    Network,
    Processes,
    Eventlog,
    Fixes,
    Updates,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::System => "System",
            Category::Network => "Network",
            Category::Processes => "Processes & services",
            Category::Eventlog => "Event log",
            Category::Fixes => "Fixes",
            Category::Updates => "Updates",
        }
    }
}

/// One line of a report: a labelled value with a severity, plus an optional
/// second line of detail (an event's message, a package's description…).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub label: String,
    pub value: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Finding {
    pub fn new(label: impl Into<String>, value: impl Into<String>, severity: Severity) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            severity,
            detail: None,
        }
    }
    pub fn ok(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(label, value, Severity::Ok)
    }
    pub fn info(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(label, value, Severity::Info)
    }
    pub fn warn(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(label, value, Severity::Warning)
    }
    pub fn crit(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(label, value, Severity::Critical)
    }
    /// Attach a muted second line, shown under the row in the UI and indented
    /// under it in the ticket-text export.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if !detail.trim().is_empty() {
            self.detail = Some(detail);
        }
        self
    }
}

/// What a module produces on a successful run, before timing/error wrapping.
pub struct Output {
    pub findings: Vec<Finding>,
    pub summary: String,
}

impl Output {
    pub fn new(summary: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self {
            findings,
            summary: summary.into(),
        }
    }
}

/// Static description of a module, shown in the checklist before anything runs.
/// Serialize-only: it's sent out to the frontend but never read back into Rust,
/// which lets `platforms` stay `&'static str` without a `Deserialize` lifetime.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: Category,
    /// `true` for anything that changes the box (fixes, installing updates).
    /// The UI asks for confirmation before running any mutating module.
    pub mutating: bool,
    /// Needs administrator/root. On Windows the module fails fast unless the
    /// app is elevated; on Linux it asks for a password through pkexec.
    pub requires_admin: bool,
    /// What to tell the user in the confirmation dialog before it runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// Which OSes this module actually does something useful on.
    pub platforms: Vec<&'static str>,
}

impl ModuleInfo {
    /// A read-only, cross-platform module. Chain `.mutating()`, `.admin()` and
    /// `.warning(..)` for anything stronger.
    pub fn new(id: &str, title: &str, category: Category, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            category,
            mutating: false,
            requires_admin: false,
            warning: None,
            platforms: vec!["windows", "linux"],
        }
    }
    pub fn mutating(mut self) -> Self {
        self.mutating = true;
        self
    }
    pub fn admin(mut self) -> Self {
        self.requires_admin = true;
        self
    }
    pub fn warning(mut self, text: impl Into<String>) -> Self {
        self.warning = Some(text.into());
        self
    }
}

/// The outcome of running one module: findings plus timing and any error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub module_id: String,
    pub title: String,
    pub category: Category,
    pub findings: Vec<Finding>,
    pub summary: String,
    pub error: Option<String>,
    pub duration_ms: u128,
}

impl ModuleResult {
    /// Worst severity across findings, or `Critical` if the module errored.
    /// This is what the frontend turns into the card's status chip.
    pub fn status(&self) -> Severity {
        if self.error.is_some() {
            return Severity::Critical;
        }
        self.findings
            .iter()
            .map(|f| f.severity)
            .max_by_key(|s| s.rank())
            .unwrap_or(Severity::Ok)
    }
}
