//! The `TriageModule` trait, the run context, and the registry that lists
//! every module.
//!
//! A module implements just `info()` (static description) and `execute()` (do
//! the work, return findings or an error string). The provided `run()` times
//! it and wraps the result, so individual modules never deal with timing or
//! the `ModuleResult` shape.

use crate::model::{ModuleInfo, ModuleResult, Output};
use std::time::Instant;

/// Passed to every module run. Long-running modules call [`RunContext::log`] to
/// stream progress lines to whatever shell is driving them: the Tauri app
/// forwards each line to the UI as a `module-log` event, and the CLI example
/// prints them.
pub struct RunContext<'a> {
    sink: &'a (dyn Fn(&str) + Send + Sync),
}

impl<'a> RunContext<'a> {
    pub fn new(sink: &'a (dyn Fn(&str) + Send + Sync)) -> Self {
        Self { sink }
    }

    /// Report one line of progress ("Downloading 2/5: …").
    pub fn log(&self, line: impl AsRef<str>) {
        (self.sink)(line.as_ref())
    }
}

impl RunContext<'static> {
    /// A context that discards progress lines.
    pub fn silent() -> Self {
        fn discard(_: &str) {}
        Self { sink: &discard }
    }
}

pub trait TriageModule: Send + Sync {
    fn info(&self) -> ModuleInfo;

    /// Do the work. Return `Ok(Output)` with findings + a one-line summary, or
    /// `Err(message)` if the module couldn't run (missing tool, denied, etc.).
    fn execute(&self, ctx: &RunContext) -> Result<Output, String>;

    /// Times `execute()` and packages it into a `ModuleResult`. Don't override.
    fn run(&self, ctx: &RunContext) -> ModuleResult {
        let info = self.info();
        let start = Instant::now();
        let outcome = self.execute(ctx);
        let duration_ms = start.elapsed().as_millis();

        match outcome {
            Ok(out) => ModuleResult {
                module_id: info.id,
                title: info.title,
                category: info.category,
                findings: out.findings,
                summary: out.summary,
                error: None,
                duration_ms,
            },
            Err(err) => ModuleResult {
                module_id: info.id,
                title: info.title,
                category: info.category,
                findings: Vec::new(),
                summary: String::new(),
                error: Some(err),
                duration_ms,
            },
        }
    }
}

/// Every module the app knows about, in display order. Add new modules here.
///
/// Every module is cross-platform at the registry level; OS differences live
/// inside each module behind `#[cfg(windows)]` / `#[cfg(not(windows))]`.
pub fn registry() -> Vec<Box<dyn TriageModule>> {
    vec![
        // --- System ---
        Box::new(crate::triage::system::SystemInfo),
        Box::new(crate::triage::disk::DiskUsage),
        Box::new(crate::triage::memory::MemoryUsage),
        // --- Processes & services ---
        Box::new(crate::triage::processes::TopProcesses),
        Box::new(crate::triage::services::ServiceHealth),
        // --- Network ---
        Box::new(crate::triage::network::Connectivity),
        // --- Event log ---
        Box::new(crate::triage::eventlog::RecentErrors),
        // --- Fixes (mutating) ---
        Box::new(crate::fixes::temp::ClearTemp),
        Box::new(crate::fixes::dns::FlushDns),
        // --- Updates: one read-only scan, two installers split by risk ---
        Box::new(crate::update::scan::AvailableUpdates),
        Box::new(crate::update::apply::InstallUpdates),
        Box::new(crate::update::firmware::InstallFirmware),
    ]
}

/// Run a named subset of the registry, in registry order. Unknown ids are
/// ignored. Used by the CLI example and anything else that wants a blocking
/// run without the event streaming the Tauri layer does.
pub fn run_selected(ids: &[String], ctx: &RunContext) -> Vec<ModuleResult> {
    registry()
        .iter()
        .filter(|m| ids.iter().any(|id| *id == m.info().id))
        .map(|m| m.run(ctx))
        .collect()
}
