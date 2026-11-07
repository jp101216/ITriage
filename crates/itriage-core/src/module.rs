//! The `TriageModule` trait, the run context, and the registry that lists
//! every module.
//!
//! A module implements just `info()` (static description) and `execute()` (do
//! the work, return findings or an error string); modules that change the
//! machine also implement `preview()`. The provided `run()` checks the policy,
//! times the module, keeps its log, and wraps the result, so individual modules
//! never deal with timing or the `ModuleResult` shape.

use crate::model::{Finding, ModuleInfo, ModuleResult, Output, Severity, Target};
use crate::profile::Profile;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Most log lines kept with a result (the live view sees them all).
const MAX_LOG_LINES: usize = 600;

/// Passed to every module run. It carries:
/// * a progress sink: long-running modules call [`RunContext::log`], and the
///   Tauri app forwards each line to the UI as a `module-log` event;
/// * an optional cancel flag, which modules check at *safe* points (between
///   downloads, between steps), never mid-install;
/// * the active site profile (requirements, policy, thresholds, KB links);
/// * preview (what-if) and remote-safe switches, and a typed destination.
#[derive(Clone, Copy)]
pub struct RunContext<'a> {
    sink: &'a (dyn Fn(&str) + Send + Sync),
    cancel: Option<&'a AtomicBool>,
    profile: Option<&'a Profile>,
    preview: bool,
    remote_safe: bool,
    target: Option<&'a Target>,
}

impl<'a> RunContext<'a> {
    pub fn new(sink: &'a (dyn Fn(&str) + Send + Sync)) -> Self {
        Self {
            sink,
            cancel: None,
            profile: None,
            preview: false,
            remote_safe: false,
            target: None,
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

    /// Preview (what-if): modules that change the machine say what they would
    /// do and change nothing.
    pub fn preview(mut self, on: bool) -> Self {
        self.preview = on;
        self
    }

    /// Remote-safe: modules that could drop a remote session or restart the
    /// PC refuse to run.
    pub fn remote_safe(mut self, on: bool) -> Self {
        self.remote_safe = on;
        self
    }

    /// The destination for `net.target`.
    pub fn with_target(mut self, target: &'a Target) -> Self {
        self.target = Some(target);
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

    pub fn is_preview(&self) -> bool {
        self.preview
    }

    pub fn is_remote_safe(&self) -> bool {
        self.remote_safe
    }

    pub fn target(&self) -> Option<&Target> {
        self.target
    }

    /// The same context with a different progress sink.
    pub(crate) fn with_sink<'b>(&self, sink: &'b (dyn Fn(&str) + Send + Sync)) -> RunContext<'b>
    where
        'a: 'b,
    {
        RunContext { sink, ..*self }
    }
}

impl RunContext<'static> {
    /// A context that discards progress lines.
    pub fn silent() -> Self {
        fn discard(_: &str) {}
        RunContext::new(&discard)
    }
}

/// Why remote-safe mode refuses a module.
pub const REMOTE_SAFE_REASON: &str =
    "Remote-safe mode is on: this could drop the remote session or restart the PC. Switch remote-safe off to run it.";

pub trait TriageModule: Send + Sync {
    fn info(&self) -> ModuleInfo;

    /// Do the work. Return `Ok(Output)` with findings + a one-line summary, or
    /// `Err(message)` if the module couldn't run (missing tool, denied, etc.).
    fn execute(&self, ctx: &RunContext) -> Result<Output, String>;

    /// What a module that changes the machine would do, for a preview
    /// (what-if) run. Must not change anything. The default lists its
    /// description; modules override it with their actual steps.
    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        let info = self.info();
        Ok(Output::new(
            format!("Preview: {} would run. Nothing was changed.", info.title),
            vec![Finding::info("Would", info.description)],
        ))
    }

    /// Checks the site policy and remote-safe mode, times `execute()` (or
    /// `preview()`), keeps the log, applies the profile (drops fixes it doesn't
    /// allow, links KB articles) and audits modules that change the machine.
    /// Don't override.
    fn run(&self, ctx: &RunContext) -> ModuleResult {
        let info = self.info();
        let mutating = info.mutating;
        if let Some(reason) = ctx.profile().block_reason(&info) {
            return ModuleResult::failed(&info, reason);
        }
        let preview = ctx.is_preview() && mutating;
        if ctx.is_remote_safe() && info.disruptive && !preview {
            return ModuleResult::failed(&info, REMOTE_SAFE_REASON);
        }

        let lines = Mutex::new(Vec::<String>::new());
        let tee = |line: &str| {
            if let Ok(mut kept) = lines.lock() {
                if kept.len() < MAX_LOG_LINES {
                    kept.push(line.to_string());
                } else if kept.len() == MAX_LOG_LINES {
                    kept.push("… (log truncated)".to_string());
                }
            }
            ctx.log(line);
        };
        let inner = ctx.with_sink(&tee);

        let start = Instant::now();
        let outcome = if preview { self.preview(&inner) } else { self.execute(&inner) };
        let duration_ms = start.elapsed().as_millis();
        let log = lines.into_inner().unwrap_or_default();

        let mut result = match outcome {
            Ok(out) => ModuleResult {
                module_id: info.id.clone(),
                title: info.title.clone(),
                category: info.category,
                findings: out.findings,
                summary: out.summary,
                error: None,
                duration_ms,
                log,
                restart_required: out.restart_required && !preview,
                preview,
            },
            Err(err) => ModuleResult {
                duration_ms,
                log,
                preview,
                ..ModuleResult::failed(&info, err)
            },
        };
        ctx.profile().annotate(&mut result);
        if mutating && !preview {
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
        Box::new(crate::net::latency::Latency),
        Box::new(crate::net::proxy::ProxySettings),
        Box::new(crate::net::target::DestinationTest),
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
        // --- Network repair (mutating; the Tune-Up network phase) ---
        Box::new(crate::fixes::dns::FlushDns),
        Box::new(crate::fixes::netrepair::PurgeCaches),
        Box::new(crate::fixes::netrepair::NetworkTuning),
        Box::new(crate::fixes::netrepair::ResetStack),
        Box::new(crate::fixes::netrepair::RestartAdapters),
        // --- Cleanup & maintenance (mutating) ---
        Box::new(crate::fixes::temp::ClearTemp),
        Box::new(crate::fixes::maintenance::EmptyRecycleBin),
        Box::new(crate::fixes::maintenance::RepairImage),
        Box::new(crate::fixes::maintenance::OptimizeDrives),
        Box::new(crate::fixes::maintenance::RefreshPolicy),
        Box::new(crate::fixes::maintenance::ConfigMgrCycles),
        // --- Updates: one read-only scan, two installers split by risk ---
        Box::new(crate::update::scan::AvailableUpdates),
        Box::new(crate::update::apply::InstallUpdates),
        Box::new(crate::update::firmware::InstallFirmware),
        // --- Last, so it runs after everything else in a sequence ---
        Box::new(crate::fixes::maintenance::RestartComputer),
    ]
}

/// The checklist for this machine: modules for the current OS, each marked
/// `locked` when the site policy or remote-safe mode blocks it.
pub fn catalogue(profile: &Profile, remote_safe: bool) -> Vec<ModuleInfo> {
    registry()
        .iter()
        .map(|m| {
            let mut info = m.info();
            info.locked = profile
                .block_reason(&info)
                .or_else(|| (remote_safe && info.disruptive).then(|| REMOTE_SAFE_REASON.to_string()));
            info
        })
        .filter(|i| i.platforms.contains(&std::env::consts::OS))
        .collect()
}

/// A ready-made selection, one per PowerShell toolkit script.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub title: &'static str,
    /// The script it stands in for.
    pub script: &'static str,
    pub description: &'static str,
    pub modules: &'static [&'static str],
}

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "triage",
        title: "Slowness triage",
        script: "Invoke-NetTriage",
        description: "System baseline, performance, network, latency, proxy, Wi-Fi and VPN, the site's servers, and a destination if you give one. Changes nothing.",
        modules: &[
            "system.info", "system.disk", "system.memory", "proc.top", "net.connectivity", "net.latency",
            "net.proxy", "net.target", "desk.wifi", "site.checks",
        ],
    },
    Preset {
        id: "tuneup",
        title: "Tune-up",
        script: "Invoke-EndpointTuneUp",
        description: "DNS, address caches, TCP and adapter power, network stack and adapters, temp files, drive optimisation, Group Policy and Configuration Manager. Recycle Bin, system file repair and restart stay opt-in.",
        modules: &[
            "fix.dns", "fix.netcache", "fix.tcp", "fix.netstack", "fix.adapters", "fix.temp", "fix.optimize",
            "fix.gpupdate", "fix.sccm",
        ],
    },
    Preset {
        id: "updates",
        title: "Drivers & firmware",
        script: "Invoke-UpdateSystem",
        description: "Identity and BIOS, what's pending, then drivers, BIOS and firmware through the manufacturer's tool and Windows Update.",
        modules: &["system.info", "update.scan", "update.firmware"],
    },
];

pub fn preset(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id.eq_ignore_ascii_case(id))
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

/// "Changes finished; restart to complete them": Windows' 3010
/// (ERROR_SUCCESS_REBOOT_REQUIRED). Unix exit codes stop at 255, so it's 3
/// there.
pub const EXIT_RESTART: i32 = if cfg!(windows) { 3010 } else { 3 };

/// The exit code for scripts and RMM tools, matching the PowerShell toolkit:
/// * `0`: finished, including diagnostics that found problems;
/// * `1`: nothing could run;
/// * `2`: incomplete: a module couldn't run, a change partly failed, or the
///   run was cancelled;
/// * [`EXIT_RESTART`] (3010 on Windows): changes finished and need a restart.
pub fn exit_code(results: &[ModuleResult], cancelled: bool) -> i32 {
    if results.is_empty() || results.iter().all(|r| r.error.is_some()) {
        return 1;
    }
    let mutating: Vec<String> = registry()
        .iter()
        .map(|m| m.info())
        .filter(|i| i.mutating)
        .map(|i| i.id)
        .collect();
    let partial = results.iter().any(|r| {
        r.error.is_some() || (mutating.contains(&r.module_id) && !r.preview && r.status() == Severity::Critical)
    });
    if partial || cancelled {
        2
    } else if results.iter().any(|r| r.restart_required) {
        EXIT_RESTART
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Category;

    struct Fake {
        mutating: bool,
        disruptive: bool,
    }

    impl TriageModule for Fake {
        fn info(&self) -> ModuleInfo {
            let mut i = ModuleInfo::new("fix.fake", "Fake fix", Category::Repair, "Does a thing");
            if self.mutating {
                i = i.mutating();
            }
            if self.disruptive {
                i = i.disruptive();
            }
            i
        }
        fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
            ctx.log("step one");
            ctx.log("step two");
            Ok(Output::new("done", vec![Finding::ok("Thing", "done")]).restart_required(true))
        }
    }

    #[test]
    fn keeps_the_log_and_restart_flag() {
        let ctx = RunContext::silent();
        let r = Fake { mutating: false, disruptive: false }.run(&ctx);
        assert_eq!(r.log, vec!["step one", "step two"]);
        assert!(r.restart_required);
        assert!(!r.preview);
    }

    #[test]
    fn previews_change_nothing() {
        let ctx = RunContext::silent().preview(true);
        let r = Fake { mutating: true, disruptive: true }.run(&ctx);
        assert!(r.preview && r.error.is_none(), "remote-safe doesn't block a preview: {r:?}");
        assert!(r.log.is_empty(), "execute() never ran");
        assert!(!r.restart_required);
        assert!(r.summary.starts_with("Preview"));
    }

    #[test]
    fn remote_safe_blocks_disruptive_modules() {
        let ctx = RunContext::silent().remote_safe(true);
        let r = Fake { mutating: true, disruptive: true }.run(&ctx);
        assert_eq!(r.error.as_deref(), Some(REMOTE_SAFE_REASON));
        let r = Fake { mutating: true, disruptive: false }.run(&ctx);
        assert!(r.error.is_none());
    }

    #[test]
    fn exit_codes_match_the_powershell_toolkit() {
        let ok = |id: &str| ModuleResult {
            findings: vec![Finding::crit("Disk", "98% used")],
            summary: "x".into(),
            error: None,
            ..ModuleResult::failed(&ModuleInfo::new(id, "t", Category::System, "d"), "")
        };
        let failed = |id: &str| ModuleResult::failed(&ModuleInfo::new(id, "t", Category::System, "d"), "nope");
        assert_eq!(exit_code(&[], false), 1);
        assert_eq!(exit_code(&[failed("system.disk")], false), 1);
        assert_eq!(exit_code(&[ok("system.disk")], false), 0, "a critical diagnosis still finished");
        assert_eq!(exit_code(&[ok("system.disk"), failed("system.memory")], false), 2);
        assert_eq!(exit_code(&[ok("system.disk")], true), 2);
        assert_eq!(exit_code(&[ok("fix.temp")], false), 2, "a critical result from a change is a partial failure");
        let restart = ModuleResult { restart_required: true, findings: vec![Finding::ok("x", "y")], ..ok("fix.netstack") };
        assert_eq!(exit_code(&[restart], false), EXIT_RESTART);
    }

    #[test]
    fn presets_name_real_modules() {
        let ids: Vec<String> = registry().iter().map(|m| m.info().id).collect();
        for p in PRESETS {
            for m in p.modules {
                assert!(ids.iter().any(|i| i == m), "{} lists unknown module {m}", p.id);
            }
        }
        assert!(preset("TuneUp").is_some());
        let tuneup = preset("tuneup").unwrap();
        assert!(!tuneup.modules.contains(&"fix.restart") && !tuneup.modules.contains(&"fix.recycle"), "opt-in, as in the script");
    }
}
