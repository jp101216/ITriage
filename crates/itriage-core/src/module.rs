//! The `TriageModule` trait, the run context, and the registry that lists
//! every module.
//!
//! A module implements just `info()` (static description) and `execute()` (do
//! the work, return findings or an error string). The provided `run()` times
//! it and wraps the result, so individual modules never deal with timing or
//! the `ModuleResult` shape.

use crate::model::{ModuleInfo, ModuleResult, Output};
use crate::profile::Profile;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Passed to every module run. It carries:
/// * a progress sink: long-running modules call [`RunContext::log`], and the
///   Tauri app forwards each line to the UI as a `module-log` event;
/// * an optional cancel flag, which modules check at *safe* points (between
///   downloads, between steps), never mid-install;
/// * the active site profile (requirements, policy, KB links).
pub struct RunContext<'a> {
    sink: &'a (dyn Fn(&str) + Send + Sync),
    cancel: Option<&'a AtomicBool>,
    profile: Option<&'a Profile>,
}

impl<'a> RunContext<'a> {
    pub fn new(sink: &'a (dyn Fn(&str) + Send + Sync)) -> Self {
        Self {
            sink,
            cancel: None,
            profile: None,
        }
    }

    pub fn with_cancel(mut self, flag: &'a AtomicBool) -> Self {
        self.cancel = Some(flag);
        self
    }

    pub fn with_profile(mut self, profile: &'a Profile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Report one line of progress ("Downloading 2/5: …").
    pub fn log(&self, line: impl AsRef<str>) {
        (self.sink)(line.as_ref())
    }

    /// Has the user asked to stop? Check only where stopping is safe.
    pub fn cancelled(&self) -> bool {
        self.cancel.is_some_and(|c| c.load(Ordering::Relaxed))
    }

    pub fn profile(&self) -> &Profile {
        self.profile.unwrap_or_else(|| Profile::builtin())
    }
}

impl RunContext<'static> {
    /// A context that discards progress lines.
    pub fn silent() -> Self {
        fn discard(_: &str) {}
        Self {
            sink: &discard,
            cancel: None,
            profile: None,
        }
    }
}

pub trait TriageModule: Send + Sync {
    fn info(&self) -> ModuleInfo;

    /// Do the work. Return `Ok(Output)` with findings + a one-line summary, or
    /// `Err(message)` if the module couldn't run (missing tool, denied, etc.).
    fn execute(&self, ctx: &RunContext) -> Result<Output, String>;

    /// Checks the site policy, times `execute()`, applies the profile (drops
    /// fixes it doesn't allow, links KB articles) and audits modules that
    /// change the machine. Don't override.
    fn run(&self, ctx: &RunContext) -> ModuleResult {
        let info = self.info();
        let mutating = info.mutating;
        if let Some(reason) = ctx.profile().block_reason(&info) {
            return ModuleResult {
                module_id: info.id,
                title: info.title,
                category: info.category,
                findings: Vec::new(),
                summary: String::new(),
                error: Some(reason),
                duration_ms: 0,
            };
        }

        let start = Instant::now();
        let outcome = self.execute(ctx);
        let duration_ms = start.elapsed().as_millis();

        let mut result = match outcome {
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
        };
        ctx.profile().annotate(&mut result);
        if mutating {
            crate::audit::module_ran(&result);
        }
        result
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
        // --- Workstation (service desk) ---
        Box::new(crate::desk::time::ClockSync),
        Box::new(crate::desk::domain::DomainPolicy),
        Box::new(crate::desk::printers::Printers),
        Box::new(crate::desk::devices::Devices),
        Box::new(crate::desk::wifi::WifiVpn),
        Box::new(crate::desk::certs::MachineCerts),
        Box::new(crate::desk::battery::BatteryHealth),
        // --- Site & clinical (driven by the site profile) ---
        Box::new(crate::site::apps::SiteApps),
        Box::new(crate::site::checks::SiteChecks),
        // --- Fixes (mutating) ---
        Box::new(crate::fixes::temp::ClearTemp),
        Box::new(crate::fixes::dns::FlushDns),
        // --- Updates: one read-only scan, two installers split by risk ---
        Box::new(crate::update::scan::AvailableUpdates),
        Box::new(crate::update::apply::InstallUpdates),
        Box::new(crate::update::firmware::InstallFirmware),
    ]
}

/// The checklist for this machine: modules for the current OS, each marked
/// `locked` when the site policy blocks it.
pub fn catalogue(profile: &Profile) -> Vec<ModuleInfo> {
    registry()
        .iter()
        .map(|m| {
            let mut info = m.info();
            info.locked = profile.block_reason(&info);
            info
        })
        .filter(|i| i.platforms.contains(&std::env::consts::OS))
        .collect()
}

/// Run a named subset of the registry, in registry order, stopping early if
/// the context is cancelled. Unknown ids are ignored. Used by the CLI example
/// and anything else that wants a blocking run without event streaming.
pub fn run_selected(ids: &[String], ctx: &RunContext) -> Vec<ModuleResult> {
    let mut results = Vec::new();
    for m in registry().iter().filter(|m| ids.iter().any(|id| *id == m.info().id)) {
        if ctx.cancelled() {
            break;
        }
        results.push(m.run(ctx));
    }
    results
}
