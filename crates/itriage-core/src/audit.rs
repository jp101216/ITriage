//! Audit trail: every run, every module that changes the machine, and every
//! one-click fix, recorded as one JSON line in a local file *and* mirrored to
//! the system log so a SIEM sees what a technician did and when:
//!
//! * Windows: the Application event log, source `itriage`. When itriage runs
//!   elevated it registers that source (using .NET's EventLogMessages.dll, as
//!   PowerShell's `New-EventLog` does), so Event Viewer shows clean messages.
//! * Linux: syslog/journald via `logger -t itriage`.
//!
//! Auditing is best effort: a full disk or a missing logger never blocks the
//! work being audited.

use crate::model::{ModuleResult, Severity};
use crate::parse::time::epoch_to_rfc3339;
use crate::util::now_epoch;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;

/// Event IDs used in the Windows event log.
pub mod event_id {
    pub const RUN: u32 = 1000;
    pub const MODULE: u32 = 1001;
    pub const FIX_OK: u32 = 1100;
    pub const FIX_FAILED: u32 = 1101;
}

/// The local audit file: `%LOCALAPPDATA%\itriage\audit.jsonl` or
/// `~/.local/state/itriage/audit.jsonl`.
pub fn log_path() -> Option<PathBuf> {
    crate::paths::state_dir().map(|d| d.join("audit.jsonl"))
}

/// Record one event.
pub fn record(kind: &str, id: u32, ok: bool, message: &str, data: Value) {
    if cfg!(test) {
        return; // unit tests exercise audited paths; keep them out of the real log
    }
    let line = json!({
        "ts": epoch_to_rfc3339(now_epoch()),
        "kind": kind,
        "ok": ok,
        "message": message,
        "host": sysinfo::System::host_name().unwrap_or_default(),
        "user": std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default(),
        "elevated": crate::host::is_elevated(),
        "data": data,
    });
    append(&line);
    system_log(id, ok, message);
}

/// A finished run: which modules ran and the worst result.
pub fn run_finished(results: &[ModuleResult], cancelled: bool) {
    let worst = results
        .iter()
        .map(|r| r.status())
        .max_by_key(|s| s.rank())
        .unwrap_or(Severity::Ok);
    let ids: Vec<&str> = results.iter().map(|r| r.module_id.as_str()).collect();
    let message = format!(
        "itriage run {}: {} module(s), worst result {:?}{}",
        if cancelled { "cancelled" } else { "finished" },
        results.len(),
        worst,
        if ids.is_empty() { String::new() } else { format!(" ({})", ids.join(", ")) }
    );
    record("run", event_id::RUN, true, &message, json!({ "modules": ids, "cancelled": cancelled }));
}

/// A module that changes the machine has finished.
pub fn module_ran(result: &ModuleResult) {
    let ok = result.error.is_none();
    let message = match &result.error {
        None => format!("itriage module {} ran: {}", result.module_id, result.summary),
        Some(e) => format!("itriage module {} failed: {e}", result.module_id),
    };
    record("module", event_id::MODULE, ok, &message, json!({ "module": result.module_id }));
}

/// A one-click fix has run.
pub fn fix_ran(id: &str, target: Option<&str>, outcome: &Result<String, String>) {
    let what = match target {
        Some(t) => format!("{id} ({t})"),
        None => id.to_string(),
    };
    let (ok, message) = match outcome {
        Ok(m) => (true, format!("itriage fix {what} succeeded: {m}")),
        Err(e) => (false, format!("itriage fix {what} failed: {e}")),
    };
    let event = if ok { event_id::FIX_OK } else { event_id::FIX_FAILED };
    record("fix", event, ok, &message, json!({ "fix": id, "target": target }));
}

/// Append a JSON line, rotating the file at about 5 MB.
fn append(line: &Value) {
    let Some(path) = log_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 5 * 1024 * 1024) {
        let _ = std::fs::rename(&path, path.with_extension("jsonl.1"));
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{line}");
    }
}

#[cfg(windows)]
fn system_log(id: u32, ok: bool, message: &str) {
    crate::win::eventlog::report("itriage", id, ok, message);
}

#[cfg(not(windows))]
fn system_log(_id: u32, ok: bool, message: &str) {
    if crate::util::command_exists("logger") {
        let mut c = crate::util::cmd("logger");
        c.args(["-t", "itriage", "-p", if ok { "user.notice" } else { "user.warning" }, "--", message]);
        let _ = crate::util::capture(c);
    }
}
