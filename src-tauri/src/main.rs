// Hide the console window on Windows release builds (keep it in debug).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri desktop shell for itriage. Deliberately thin: all the real work
//! lives in `itriage-core`.
//!
//! Commands:
//! * `list_modules`: the checklist the UI renders.
//! * `get_host_context`: hostname, OS, and whether we're elevated.
//! * `relaunch_elevated`: restart through UAC (Windows), then exit.
//! * `run_modules`: run the selected modules on a background thread,
//!   streaming progress to the UI as events.
//! * `get_telemetry`: one live sample (CPU, cores, memory, network, disk)
//!   for the HUD charts; the UI polls it about once a second.

use itriage_core::{host_context, registry, HostContext, ModuleInfo, ModuleResult, RunContext, Sampler, Telemetry};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State, Window};

#[tauri::command]
fn list_modules() -> Vec<ModuleInfo> {
    registry().iter().map(|m| m.info()).collect()
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

/// Run the selected modules in registry order. Emits:
///   `module-start`  { id, title, index, total }  before each module
///   `module-log`    { id, line }                 progress lines while it runs
///   `module-done`   ModuleResult                 after each module
///   `run-complete`  { count }                    at the end
/// and also returns the full result set to the caller.
#[tauri::command]
async fn run_modules(window: Window, selected: Vec<String>) -> Vec<ModuleResult> {
    // Modules do blocking I/O (COM calls, subprocesses, sockets) and some run
    // for many minutes, so keep them off the async runtime's worker threads.
    tauri::async_runtime::spawn_blocking(move || {
        let chosen: Vec<_> = registry()
            .into_iter()
            .filter(|m| selected.iter().any(|id| *id == m.info().id))
            .collect();
        let total = chosen.len();
        let mut results = Vec::with_capacity(total);

        for (index, module) in chosen.iter().enumerate() {
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
            let result = module.run(&RunContext::new(&forward));

            let _ = window.emit("module-done", &result);
            results.push(result);
        }

        let _ = window.emit("run-complete", serde_json::json!({ "count": total }));
        results
    })
    .await
    .unwrap_or_default()
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(Sampler::new()))
        .invoke_handler(tauri::generate_handler![
            list_modules,
            get_host_context,
            get_telemetry,
            relaunch_elevated,
            run_modules
        ])
        .run(tauri::generate_context!())
        .expect("error while running itriage");
}
