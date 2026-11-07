// Hide the console window on Windows release builds (keep it in debug).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri desktop shell for itriage. Deliberately thin: all the real work
//! lives in `itriage-core`.
//!
//! Commands:
//! * `list_modules`, `get_profile`, `list_fixes`, `get_host_context`: what the
//!   UI renders before anything runs (the checklist, with modules the site
//!   policy blocks marked locked).
//! * `run_modules` / `cancel_run`: run the selected modules on a background
//!   thread, streaming progress as events; cancelling stops at the next safe
//!   point. A finished run is audited, saved to the history folder and
//!   compared with the previous run of this machine.
//! * `run_fix`: one policy-checked, audited one-click fix.
//! * `list_history`, `load_report`, `import_report`, `compare_with_previous`:
//!   the report viewer.
//! * `open_link` (https only), `open_history_folder`, `relaunch_elevated`.
//! * `get_telemetry`: one live sample for the HUD charts, polled about once a second.
//!
//! A run and a fix never overlap: both claim the same busy flag.

use itriage_core::{
    actions, audit, catalogue, host, host_context, profile, registry, report, HostContext, ModuleInfo,
    ProfileStatus, Report, ReportDiff, ReportMeta, RunContext, Sampler, Telemetry,
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
fn list_modules(app: State<'_, App>) -> Vec<ModuleInfo> {
    catalogue(&app.profile)
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
/// the previous one; re-checking one module after a fix passes false.
#[tauri::command]
async fn run_modules(
    window: Window,
    app: State<'_, App>,
    selected: Vec<String>,
    record: Option<bool>,
) -> Result<RunOutcome, String> {
    let busy = claim(&app.busy)?;
    app.cancel.store(false, Ordering::SeqCst);
    let profile = app.profile.clone();
    let cancel = app.cancel.clone();
    let profile_name = (app.status.source != "built-in").then(|| app.status.name.clone());
    let record = record.unwrap_or(true);

    // Modules do blocking I/O (COM calls, subprocesses, sockets) and some run
    // for many minutes, so keep them off the async runtime's worker threads.
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = busy;
        let chosen: Vec<_> = registry()
            .into_iter()
            .filter(|m| selected.iter().any(|id| *id == m.info().id))
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
            let ctx = RunContext::new(&forward).with_cancel(&cancel).with_profile(&profile);
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
                diff = report::previous(&report.host.hostname, &report.generated).map(|old| report::diff(&old, &report));
            }
            match report::save(&report) {
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
async fn run_fix(app: State<'_, App>, id: String, target: Option<String>) -> Result<String, String> {
    let busy = claim(&app.busy)?;
    let profile = app.profile.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = busy;
        actions::run(&id, target.as_deref(), &profile)
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
async fn import_report(text: String) -> Result<Imported, String> {
    let report = report::parse(&text)?;
    let diff = report::previous(&report.host.hostname, &report.generated).map(|old| report::diff(&old, &report));
    let saved = report::save(&report).ok().map(|p| p.display().to_string());
    Ok(Imported { report, diff, saved })
}

/// Compare a saved run with the run before it from the same machine.
#[tauri::command]
async fn compare_with_previous(report: Report) -> Option<ReportDiff> {
    report::previous(&report.host.hostname, &report.generated).map(|old| report::diff(&old, &report))
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
            open_link,
            open_history_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running itriage");
}
