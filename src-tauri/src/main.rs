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
//! * `run_fix`: one policy-checked, audited one-click fix; `preview_fix`:
//!   what it would do, changing nothing.
//! * `list_history`, `load_report`, `import_report`, `compare_with_previous`,
//!   `compare_reports`, `report_text`: the report viewer and comparisons.
//! * `trends`: every measurement over this computer's saved runs.
//! * `likely_causes`: the "likely cause" lines for a set of results (after a
//!   re-check changes them).
//! * `check_update`: whether a newer release exists. It only tells.
//! * `open_link` (https only), `open_history_folder`, `relaunch_elevated`.
//! * `get_telemetry`: one live sample for the HUD charts, polled about once a second.
//! * `close_when_done` / `keep_running`: the answer to "something is still
//!   running; close anyway?".
//!
//! A run and a fix never overlap: both claim the same busy flag.
//!
//! Closing the window while that flag is held would kill a repair or an
//! install part-way through. So the close is held back and the UI asks; the
//! choices are to keep running, or to stop at the next safe point and then
//! close. Relaunching as administrator is refused outright while busy.
//!
//! Given any command-line arguments, the binary runs the command line
//! (`itriage --help`) instead of opening a window.

use itriage_core::report::TrendSeries;
use itriage_core::investigate::{baseline, bundle, guided, recording, timeline};
use itriage_core::update::notice::{self, Notice};
use itriage_core::{
    actions, audit, catalogue, host, host_context, insight, profile, registry, report, HostContext, Insight, ModuleInfo,
    ModuleResult, Preset, ProfileStatus, Report, ReportDiff, ReportMeta, RunContext, Sampler, Target, Telemetry, PRESETS,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State, Window, WindowEvent};

struct App {
    profile: Arc<itriage_core::Profile>,
    status: ProfileStatus,
    /// Set by `cancel_run`; modules check it at safe points.
    cancel: Arc<AtomicBool>,
    /// A run or a fix is in progress.
    busy: Arc<AtomicBool>,
    /// The window was asked to close while busy, and nobody has answered yet.
    close_asked: Arc<AtomicBool>,
    /// Close the window as soon as what's running has stopped.
    close_when_done: Arc<AtomicBool>,
    recording: Arc<AtomicBool>,
    markers: Arc<Mutex<Vec<recording::Marker>>>,
}

/// Releases the busy flag when dropped, so a panic can't wedge the app, and
/// closes the window then if that's what was asked for meanwhile.
struct Busy {
    flag: Arc<AtomicBool>,
    close_asked: Arc<AtomicBool>,
    close_when_done: Arc<AtomicBool>,
    window: Option<Window>,
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
        self.close_asked.store(false, Ordering::SeqCst);
        if self.close_when_done.load(Ordering::SeqCst) {
            if let Some(window) = &self.window {
                let _ = window.destroy();
            }
        }
    }
}

fn claim(app: &App, window: Option<Window>) -> Result<Busy, String> {
    app.busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map(|_| Busy {
            flag: app.busy.clone(),
            close_asked: app.close_asked.clone(),
            close_when_done: app.close_when_done.clone(),
            window,
        })
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
    technician_only: bool,
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
            technician_only: f.technician_only,
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
fn relaunch_elevated(app: AppHandle, state: State<'_, App>) -> Result<(), String> {
    // Relaunching closes this copy, and with it whatever it's in the middle of.
    if state.busy.load(Ordering::SeqCst) {
        return Err("Something is still running. Wait for it to finish, or cancel it, before relaunching as administrator.".into());
    }
    itriage_core::relaunch_elevated()?;
    app.exit(0);
    Ok(())
}

/// "Stop and close": ask the run to stop at its next safe point, and close
/// the window when it has (or at once, if it finished in the meantime).
#[tauri::command]
fn close_when_done(window: Window, app: State<'_, App>) {
    app.close_when_done.store(true, Ordering::SeqCst);
    app.cancel.store(true, Ordering::SeqCst);
    if !app.busy.load(Ordering::SeqCst) {
        let _ = window.destroy();
    }
}

/// "Keep running": forget the close request.
#[tauri::command]
fn keep_running(app: State<'_, App>) {
    app.close_asked.store(false, Ordering::SeqCst);
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
/// `target` is the destination for the Destination test; `ticket` is the
/// ticket reference the run is for (report, file name, audit trail).
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
    ticket: Option<String>,
    runbook: Option<String>,
    base_report: Option<Report>,
) -> Result<RunOutcome, String> {
    if let Some(base) = &base_report {
        if !base.host.hostname.eq_ignore_ascii_case(&host_context().hostname) || base.host.platform != std::env::consts::OS {
            return Err("Local timeline evidence can only be appended to this PC's report.".into());
        }
        if runbook.is_some() || record == Some(false) || selected.is_empty() || selected.iter().any(|id|!matches!(id.as_str(),"system.changes"|"net.wifi-auth")) {
            return Err("Case refreshes collect only read-only change and network-authentication history.".into());
        }
    }
    if let Some(id) = &runbook { guided::next(id, &[])?; }
    let target = match target.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => Some(Target::parse(t, &app.profile.network.target_ports)?),
        None => None,
    };
    let busy = claim(&app, Some(window.clone()))?;
    app.cancel.store(false, Ordering::SeqCst);
    let profile = app.profile.clone();
    let cancel = app.cancel.clone();
    let profile_name = (app.status.source != "built-in").then(|| app.status.name.clone());
    let profile_source = app.status.source;
    let record = record.unwrap_or(true);
    let preview = preview.unwrap_or(false) || !record;
    let remote_safe = remote_safe.unwrap_or(profile.policy.remote_safe);
    let ticket = ticket.as_deref().and_then(report::clean_ticket);

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
        let mut execute = |module: &dyn itriage_core::TriageModule, index: usize, total: usize, reason: &str| {
            if cancel.load(Ordering::SeqCst) {
                return None;
            }
            let info = module.info();
            let _ = window.emit(
                "module-start",
                serde_json::json!({ "id": info.id, "title": info.title, "index": index, "total": total, "reason": reason }),
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
                .remote_safe(remote_safe)
                .with_ticket(ticket.as_deref());
            if let Some(t) = &target {
                ctx = ctx.with_target(t);
            }
            let result = module.run(&ctx);
            let _ = window.emit("module-done", &result);
            Some(result)
        };
        let (results, trace) = if let Some(id) = &runbook {
            let (results,trace) = guided::run_for(id, target.is_some(), &mut execute)?;
            (results,Some(trace))
        } else {
            (chosen.iter().enumerate().filter_map(|(index,m)|execute(m.as_ref(),index,total,"")).collect(),None)
        };

        let cancelled = cancel.load(Ordering::SeqCst);
        audit::run_finished(&results, cancelled, ticket.as_deref());
        let mut report = if let Some(mut base) = base_report {
            base.append_evidence(results,cancelled); base
        } else { Report::new(host_context(), profile_name, results, cancelled).with_ticket(ticket.as_deref()).with_role(&profile.role) };
        if let Some(trace) = trace { report.runbook = Some(trace); }
        if !cancelled { report.check_incidents(&profile, profile_source); }
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
        Ok(RunOutcome { report, saved, save_error, diff })
    })
    .await
    .map_err(|e| format!("The run stopped unexpectedly: {e}"))?
}

struct RecordingFlag(Arc<AtomicBool>);
impl Drop for RecordingFlag {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[tauri::command]
async fn record_problem(
    window: Window,
    app: State<'_, App>,
    config: recording::Config,
    target: Option<String>,
    ticket: Option<String>,
    base_report: Option<Report>,
) -> Result<RunOutcome, String> {
    if base_report
        .as_ref()
        .is_some_and(|r| !r.host.hostname.eq_ignore_ascii_case(&host_context().hostname) || r.host.platform != std::env::consts::OS)
    {
        return Err("Return to this PC's live report before attaching a recording. An opened report from another PC cannot contain local measurements.".into());
    }
    let target = target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Target::parse(s, &app.profile.network.target_ports))
        .transpose()?;
    let busy = claim(&app, Some(window.clone()))?;
    app.cancel.store(false, Ordering::SeqCst);
    app.markers.lock().map_err(|_| "Marker list unavailable")?.clear();
    app.recording.store(true, Ordering::SeqCst);
    let flag = RecordingFlag(app.recording.clone());
    let (markers, cancel, profile) = (app.markers.clone(), app.cancel.clone(), app.profile.clone());
    let profile_name = (app.status.source != "built-in").then(|| app.status.name.clone());
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = busy;
        let _flag = flag;
        let sink = |_: &str| {};
        let ctx = RunContext::new(&sink).with_profile(&profile).with_cancel(&cancel);
        let mut capture = recording::record(config, target.as_ref(), &ctx, &markers, |sample| {
            let _ = window.emit("recording-sample", sample);
        })?;
        {
            let rows = markers.lock().map_err(|_| "Marker list unavailable")?;
            _flag.0.store(false, Ordering::SeqCst);
            capture.markers = rows.clone();
        }
        let result = recording::result(&capture);
        audit::run_finished(std::slice::from_ref(&result), false, ticket.as_deref());
        let mut report = base_report.unwrap_or_else(|| {
            Report::new(host_context(), profile_name, Vec::new(), false)
                .with_ticket(ticket.as_deref())
                .with_role(&profile.role)
        });
        report.recording = Some(capture);
        report.append_evidence(vec![result],false);
        let (saved, save_error) = match report::save(&report, profile.history.keep) {
            Ok(p) => (Some(p.display().to_string()), None),
            Err(e) => (None, Some(e)),
        };
        Ok(RunOutcome {
            report,
            saved,
            save_error,
            diff: None,
        })
    })
    .await
    .map_err(|e| format!("Recording stopped unexpectedly: {e}"))?
}

#[tauri::command]
fn mark_recording(app: State<'_, App>, label: String) -> Result<recording::Marker, String> {
    let mut markers = app.markers.lock().map_err(|_| "Marker list unavailable")?;
    if !app.recording.load(Ordering::SeqCst) {
        return Err("No recording is running.".into());
    }
    recording::append_marker(&mut markers, &label)
}
#[tauri::command]
fn list_runbooks() -> Vec<guided::Runbook> {
    guided::RUNBOOKS.to_vec()
}
#[tauri::command]
fn runbook_plan(id: String) -> Result<guided::Decision, String> {
    guided::next(&id, &[])
}
#[tauri::command]
fn compare_baseline(baseline: Report, current: Report) -> Result<baseline::Comparison, String> {
    baseline::compare(&baseline, &current)
}
#[tauri::command]
fn timeline_near(report: Report, problem_at: String, window_seconds: u64) -> Result<Vec<timeline::ChangeEvent>, String> {
    let at = timeline::problem_time(&problem_at)?;
    Ok(timeline::near(&report, at, window_seconds))
}
/// Every change and network-authentication event in a report, oldest first.
#[tauri::command]
fn timeline_rows(report: Report) -> Vec<timeline::ChangeEvent> {
    timeline::rows(&report)
}
#[tauri::command]
async fn preview_case_bundle(report: Report, options: bundle::Options) -> Result<bundle::Preview, String> {
    tauri::async_runtime::spawn_blocking(move || bundle::prepare(&report, &options).map(|p| p.preview))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn export_case_bundle(report: Report, options: bundle::Options) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || bundle::prepare(&report, &options)?.save().map(|p| p.display().to_string()))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
fn open_cases_folder() -> Result<(), String> {
    let dir = itriage_core::paths::data_dir().ok_or("No local data folder")?.join("cases");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    host::open_folder(&dir)
}

/// The diff against this machine's last comparable saved run.
fn previous_diff(report: &Report) -> Option<ReportDiff> {
    if report.evidence_updated.is_some() { return None; }
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
    window: Window,
    app: State<'_, App>,
    id: String,
    target: Option<String>,
    remote_safe: Option<bool>,
    ticket: Option<String>,
) -> Result<String, String> {
    let busy = claim(&app, Some(window))?;
    let profile = app.profile.clone();
    let remote_safe = remote_safe.unwrap_or(profile.policy.remote_safe);
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = busy;
        actions::run_for(&id, target.as_deref(), &profile, remote_safe, ticket.as_deref())
    })
    .await
    .map_err(|e| format!("The fix stopped unexpectedly: {e}"))?
}

/// What a fix would do here, changing nothing (its preview).
#[tauri::command]
async fn preview_fix(app: State<'_, App>, id: String, target: Option<String>, remote_safe: Option<bool>) -> Result<String, String> {
    let profile = app.profile.clone();
    let remote_safe = remote_safe.unwrap_or(profile.policy.remote_safe);
    tauri::async_runtime::spawn_blocking(move || actions::preview(&id, target.as_deref(), &profile, remote_safe))
        .await
        .map_err(|e| format!("The preview stopped unexpectedly: {e}"))?
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

/// Refresh the live report after a one-click fix's re-check, without changing
/// the saved original run. Verdict, diagnosis and comparison must agree.
#[tauri::command]
async fn refresh_report(mut report: Report) -> Result<RunOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        report.refresh();
        let diff = if report.cancelled { None } else { previous_diff(&report) };
        RunOutcome { report, diff, saved: None, save_error: None }
    })
    .await
    .map_err(|e| format!("Couldn't refresh the report: {e}"))
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

/// Every measurement taken in at least two saved runs of a computer (this
/// one unless another is named), oldest first.
#[tauri::command]
async fn trends(hostname: Option<String>) -> Vec<TrendSeries> {
    tauri::async_runtime::spawn_blocking(move || report::trends(&hostname.unwrap_or_else(|| host_context().hostname)))
        .await
        .unwrap_or_default()
}

/// The "likely cause" lines for a set of results: the report's own, worked
/// out again after a re-check has replaced one of them.
#[tauri::command]
fn likely_causes(results: Vec<ModuleResult>) -> Vec<Insight> {
    insight::likely_causes(&results)
}

/// Is a newer ITriage out? At most one request a day, and none when the
/// site profile turns the notice (or public probes) off.
#[tauri::command]
async fn check_update(app: State<'_, App>) -> Result<Option<Notice>, String> {
    let profile = app.profile.clone();
    Ok(tauri::async_runtime::spawn_blocking(move || notice::check(&profile)).await.unwrap_or(None))
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
    audit::set_system_log(audit::system_log_wanted(&loaded.profile, loaded.status.source));
    let app = App {
        profile: Arc::new(loaded.profile),
        status: loaded.status,
        cancel: Arc::new(AtomicBool::new(false)),
        busy: Arc::new(AtomicBool::new(false)),
        close_asked: Arc::new(AtomicBool::new(false)),
        close_when_done: Arc::new(AtomicBool::new(false)),
        recording: Arc::new(AtomicBool::new(false)),
        markers: Arc::new(Mutex::new(Vec::new())),
    };

    tauri::Builder::default()
        .manage(Mutex::new(Sampler::new()))
        .manage(app)
        .on_window_event(|window, event| {
            let WindowEvent::CloseRequested { api, .. } = event else { return };
            let app = window.state::<App>();
            if !app.busy.load(Ordering::SeqCst) {
                return; // nothing running: close as usual
            }
            api.prevent_close();
            if app.close_asked.swap(true, Ordering::SeqCst) {
                // Asked twice without an answer (the dialog may not be
                // showing): take that as "stop and close".
                app.close_when_done.store(true, Ordering::SeqCst);
                app.cancel.store(true, Ordering::SeqCst);
            } else {
                let _ = window.emit("close-requested", ());
            }
        })
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
            list_runbooks,
            runbook_plan,
            record_problem,
            mark_recording,
            compare_baseline,
            timeline_near,
            timeline_rows,
            preview_case_bundle,
            export_case_bundle,
            open_cases_folder,
            cancel_run,
            close_when_done,
            keep_running,
            run_fix,
            preview_fix,
            list_history,
            load_report,
            import_report,
            compare_with_previous,
            refresh_report,
            compare_reports,
            report_text,
            trends,
            likely_causes,
            check_update,
            open_link,
            open_history_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running ITriage");
}
