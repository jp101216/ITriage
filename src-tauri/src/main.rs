// Hide the console window on Windows release builds (keep it in debug).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri desktop shell for ITriage. Deliberately thin: all the real work
//! lives in `itriage-core`.
//!
//! Commands:
//! * `list_modules`, `list_presets`, `get_profile`, `list_fixes`,
//!   `get_host_context`, `check_target`: what the UI renders before anything
//!   runs (the checklist, with modules the site policy or remote-safe mode
//!   blocks marked locked).
//! * `run_modules` / `cancel_run`: run the selected modules on a background
//!   thread (optionally as a preview, in remote-safe mode, against a typed
//!   destination), streaming progress as events; cancelling stops at the next
//!   safe point. A finished run is audited, saved to the history folder with
//!   its transcript, and compared with the last comparable run of this machine.
//! * `run_fix`: one policy-checked, audited one-click fix.
//! * `list_history`, `load_report`, `import_report`, `compare_with_previous`,
//!   `compare_reports`, `report_text`: the report viewer and comparisons.
//! * `open_link` (https only), `open_history_folder`, `relaunch_elevated`.
//! * `get_telemetry`: one live sample for the HUD charts, polled about once a second.
//!
//! A run and a fix never overlap: both claim the same busy flag.
//!
//! Given any command-line arguments, the binary runs the command line
//! (`itriage --help`) instead of opening a window.

use itriage_core::{
    actions, audit, catalogue, host, host_context, profile, registry, report, HostContext, ModuleInfo, Preset,
    ProfileStatus, Report, ReportDiff, ReportMeta, RunContext, Sampler, Target, Telemetry, PRESETS,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State, Window};

struct App {
    profile: Arc<itriage_core::Profile>,
    status: ProfileStatus,
    /// Set by `cancel_run`; modules check it at safe points.
    cancel: Arc<AtomicBool>,
    /// A run or a fix is in progress.
    busy: Arc<AtomicBool>,
}

/// Releases the busy flag when dropped, so a panic can't wedge the app.
struct Busy(Arc<AtomicBool>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn claim(flag: &Arc<AtomicBool>) -> Result<Busy, String> {
    flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map(|_| Busy(flag.clone()))
        .map_err(|_| "Something is already running. Wait for it to finish, or cancel it, first.".to_string())
}

#[tauri::command]
fn list_modules(app: State<'_, App>, remote_safe: Option<bool>) -> Vec<ModuleInfo> {
    catalogue(&app.profile, remote_safe.unwrap_or(app.profile.policy.remote_safe))
}

#[tauri::command]
fn list_presets() -> Vec<Preset> {
    PRESETS.to_vec()
}

/// Validate a typed destination ("fileserver01:445,3389").
#[tauri::command]
fn check_target(app: State<'_, App>, text: String) -> Result<Target, String> {
    Target::parse(&text, &app.profile.network.target_ports)
}

#[tauri::command]
fn get_profile(app: State<'_, App>) -> ProfileStatus {
    app.status.clone()
}

#[derive(Serialize)]
struct FixInfo {
    id: &'static str,
    label: &'static str,
    description: &'static str,
    requires_admin: bool,
    disruptive: bool,
}

#[tauri::command]
fn list_fixes() -> Vec<FixInfo> {
    actions::FIXES
        .iter()
        .map(|f| FixInfo {
            id: f.id,
            label: f.label,
            description: f.description,
            requires_admin: actions::requires_admin(f.id),
            disruptive: f.disruptive,
        })
        .collect()
}

#[tauri::command]
fn get_host_context() -> HostContext {
    host_context()
}

/// Async so it runs on the runtime's thread pool, not the UI thread. The
/// sampler lives in managed state because CPU% and throughput are deltas
/// between consecutive samples.
#[tauri::command]
async fn get_telemetry(sampler: State<'_, Mutex<Sampler>>) -> Result<Telemetry, String> {
    let mut sampler = sampler.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    Ok(sampler.sample())
}

/// Start an elevated copy through the UAC prompt and close this one. If the
/// user declines the prompt, this one keeps running and the UI shows why.
#[tauri::command]
fn relaunch_elevated(app: AppHandle) -> Result<(), String> {
    itriage_core::relaunch_elevated()?;
    app.exit(0);
    Ok(())
}

#[derive(Serialize)]
struct RunOutcome {
    report: Report,
    /// Where the run was saved in the history folder.
    saved: Option<String>,
    save_error: Option<String>,
    /// What changed since this machine's previous saved run.
    diff: Option<ReportDiff>,
}

/// Run the selected modules in registry order. Emits:
///   `module-start`  { id, title, index, total }  before each module
///   `module-log`    { id, line }                 progress lines while it runs
///   `module-done`   ModuleResult                 after each module
///   `run-complete`  { count, cancelled }         at the end
///
/// `record` (default true) saves the run to history and diffs it against
/// the last comparable one; re-checking one module after a fix passes false.
/// `preview` makes modules that change the machine say what they'd do
/// instead; `remote_safe` refuses the ones that could drop the session;
/// `target` is the destination for the Destination test.
///
/// A re-check is never confirmed by anyone, so it never changes the machine:
/// with `record` false, modules that would are previewed whatever `preview`
/// says.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn run_modules(
    window: Window,
    app: State<'_, App>,
    selected: Vec<String>,
    record: Option<bool>,
    preview: Option<bool>,
    remote_safe: Option<bool>,
    target: Option<String>,
) -> Result<RunOutcome, String> {
    let target = match target.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => Some(Target::parse(t, &app.profile.network.target_ports)?),
        None => None,
    };
    let busy = claim(&app.busy)?;
    app.cancel.store(false, Ordering::SeqCst);
    let profile = app.profile.clone();
    let cancel = app.cancel.clone();
    let profile_name = (app.status.source != "built-in").then(|| app.status.name.clone());
    let record = record.unwrap_or(true);
    let preview = preview.unwrap_or(false) || !record;
    let remote_safe = remote_safe.unwrap_or(profile.policy.remote_safe);

    // Modules do blocking I/O (COM calls, subprocesses, sockets) and some run
    // for many minutes, so keep them off the async runtime's worker threads.
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = busy;
        let os = std::env::consts::OS;
        let chosen: Vec<_> = registry()
            .into_iter()
            .filter(|m| {
                let i = m.info();
                selected.contains(&i.id) && i.platforms.contains(&os)
            })
            .collect();
        let total = chosen.len();
        let mut results = Vec::with_capacity(total);

        for (index, module) in chosen.iter().enumerate() {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            let info = module.info();
            let _ = window.emit(
                "module-start",
                serde_json::json!({ "id": info.id, "title": info.title, "index": index, "total": total }),
            );
            let id = info.id.clone();
            let win = &window;
            let forward = move |line: &str| {
                let _ = win.emit("module-log", serde_json::json!({ "id": id, "line": line }));
            };
            let mut ctx = RunContext::new(&forward)
                .with_cancel(&cancel)
                .with_profile(&profile)
                .preview(preview)
                .remote_safe(remote_safe);
            if let Some(t) = &target {
                ctx = ctx.with_target(t);
            }
            let result = module.run(&ctx);
            let _ = window.emit("module-done", &result);
            results.push(result);
        }

        let cancelled = cancel.load(Ordering::SeqCst);
        audit::run_finished(&results, cancelled);
        let report = Report::new(host_context(), profile_name, results, cancelled);
        let (mut saved, mut save_error, mut diff) = (None, None, None);
        if record && !report.results.is_empty() {
            if !cancelled {
                diff = previous_diff(&report);
            }
            match report::save(&report, profile.history.keep) {
                Ok(p) => saved = Some(p.display().to_string()),
                Err(e) => save_error = Some(e),
            }
        }
        let _ = window.emit(
            "run-complete",
            serde_json::json!({ "count": report.results.len(), "cancelled": cancelled }),
        );
        RunOutcome { report, saved, save_error, diff }
    })
    .await
    .map_err(|e| format!("The run stopped unexpectedly: {e}"))
}

/// The diff against this machine's last comparable saved run.
fn previous_diff(report: &Report) -> Option<ReportDiff> {
    let ids: Vec<String> = report.results.iter().map(|r| r.module_id.clone()).collect();
    report::previous(&report.host.hostname, &report.generated, &ids).map(|old| report::diff(&old, report))
}

/// Ask the current run to stop. The module that's running finishes its
/// current step (an install batch, a download) and the rest are skipped.
#[tauri::command]
fn cancel_run(app: State<'_, App>) -> bool {
    let running = app.busy.load(Ordering::SeqCst);
    if running {
        app.cancel.store(true, Ordering::SeqCst);
    }
    running
}

/// Run one one-click fix. The policy is checked again in the core, whatever
/// the UI showed, and the attempt is audited either way.
#[tauri::command]
async fn run_fix(
    app: State<'_, App>,
    id: String,
    target: Option<String>,
    remote_safe: Option<bool>,
) -> Result<String, String> {
    let busy = claim(&app.busy)?;
    let profile = app.profile.clone();
    let remote_safe = remote_safe.unwrap_or(profile.policy.remote_safe);
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = busy;
        actions::run(&id, target.as_deref(), &profile, remote_safe)
    })
    .await
    .map_err(|e| format!("The fix stopped unexpectedly: {e}"))?
}

#[tauri::command]
async fn list_history() -> Vec<ReportMeta> {
    tauri::async_runtime::spawn_blocking(report::list).await.unwrap_or_default()
}

/// Load a saved run. Only files inside the history folder can be read this
/// way; anything else goes through `import_report` with its contents.
#[tauri::command]
async fn load_report(path: String) -> Result<Report, String> {
    let dir = report::history_dir().ok_or("No history folder on this system.")?;
    let wanted = inside(&dir, Path::new(&path)).ok_or("That file isn't in the run history.")?;
    report::load(&wanted)
}

fn inside(dir: &Path, path: &Path) -> Option<PathBuf> {
    let dir = dir.canonicalize().ok()?;
    let path = path.canonicalize().ok()?;
    (path.starts_with(&dir) && path.extension().is_some_and(|e| e == "json")).then_some(path)
}

#[derive(Serialize)]
struct Imported {
    report: Report,
    diff: Option<ReportDiff>,
    saved: Option<String>,
}

/// Open a report exported elsewhere (another machine's run, a CLI `--json`
/// run). It's added to the history so the next one from that machine can be
/// compared against it.
#[tauri::command]
async fn import_report(app: State<'_, App>, text: String) -> Result<Imported, String> {
    let report = report::parse(&text)?;
    let diff = previous_diff(&report);
    let saved = report::save(&report, app.profile.history.keep).ok().map(|p| p.display().to_string());
    Ok(Imported { report, diff, saved })
}

/// Compare a saved run with the last comparable run before it from the
/// same machine.
#[tauri::command]
async fn compare_with_previous(report: Report) -> Option<ReportDiff> {
    previous_diff(&report)
}

/// Compare any two runs of the same machine (oldest first, whichever order
/// they're picked in).
#[tauri::command]
async fn compare_reports(a: Report, b: Report) -> Result<ReportDiff, String> {
    report::compare(&a, &b)
}

/// The plain-text rendering: the ticket summary, or (`logs`) the full
/// transcript with every module's log.
#[tauri::command]
async fn report_text(report: Report, diff: Option<ReportDiff>, logs: Option<bool>) -> String {
    report::render_text(&report, diff.as_ref(), logs.unwrap_or(false))
}

#[tauri::command]
fn open_link(url: String) -> Result<(), String> {
    host::open_url(&url)
}

#[tauri::command]
async fn open_history_folder() -> Result<(), String> {
    let dir = report::history_dir().ok_or("No history folder on this system.")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("Can't create {}: {e}", dir.display()))?;
    host::open_folder(&dir)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        itriage_core::cli::attach_console();
        std::process::exit(itriage_core::cli::main(args));
    }

    let loaded = profile::load();
    let app = App {
        profile: Arc::new(loaded.profile),
        status: loaded.status,
        cancel: Arc::new(AtomicBool::new(false)),
        busy: Arc::new(AtomicBool::new(false)),
    };

    tauri::Builder::default()
        .manage(Mutex::new(Sampler::new()))
        .manage(app)
        .invoke_handler(tauri::generate_handler![
            list_modules,
            list_presets,
            check_target,
            get_profile,
            list_fixes,
            get_host_context,
            get_telemetry,
            relaunch_elevated,
            run_modules,
            cancel_run,
            run_fix,
            list_history,
            load_report,
            import_report,
            compare_with_previous,
            compare_reports,
            report_text,
            open_link,
            open_history_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running ITriage");
}
