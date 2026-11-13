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
//!
//! Each line of the local file carries `prev`, the SHA-256 of the line
//! before it (across the rotation to `audit.jsonl.1` too), so a line that was
//! edited, removed or slipped in breaks the chain: `itriage --verify-audit`
//! says where. Lines written before 0.10 have no `prev` and aren't checked.
//! The chain can't show that the newest lines were cut off the end; the
//! copy in the system log can. Lines are written one at a time, across
//! threads and across processes (`audit.jsonl.lock` beside the log), so
//! the desktop app and a command-line run sharing the log keep one chain.
//!
//! The system-log copy is on unless a *managed* profile turns it off
//! (`[audit] event_log = false`): a user's own profile can't hide what a
//! technician did from the organisation's SIEM.

use crate::model::{ModuleResult, Severity};
use crate::parse::time::epoch_to_rfc3339;
use crate::util::now_epoch;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Event IDs used in the Windows event log. Unchanged since 0.5, so SIEM
/// rules written for them keep working; 1102 is new in 0.10.
pub mod event_id {
    pub const RUN: u32 = 1000;
    pub const MODULE: u32 = 1001;
    pub const FIX_OK: u32 = 1100;
    pub const FIX_FAILED: u32 = 1101;
    /// Refused before it ran: site policy, remote-safe mode or an install ban.
    pub const FIX_REFUSED: u32 = 1102;
}

/// The `prev` of the first line ever written.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

static SYSTEM_LOG: AtomicBool = AtomicBool::new(true);

/// Mirror to the Windows event log / syslog? The shells call this once with
/// the profile's answer; see the module docs for who may turn it off.
pub fn set_system_log(on: bool) {
    SYSTEM_LOG.store(on, Ordering::Relaxed);
}

/// Whether a profile turns the system-log copy off: only a managed one may.
pub fn system_log_wanted(profile: &crate::profile::Profile, source: &str) -> bool {
    profile.audit.event_log || source != "managed"
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
    if SYSTEM_LOG.load(Ordering::Relaxed) {
        system_log(id, ok, &with_fields(message, &line));
    }
}

/// The message with the fields a SIEM filters on, on a line of their own:
/// "Ticket: INC1 · Account: CORP\\jparker · Elevated: yes".
fn with_fields(message: &str, line: &Value) -> String {
    let mut fields = Vec::new();
    if let Some(t) = line["data"]["ticket"].as_str() {
        fields.push(format!("Ticket: {t}"));
    }
    if let Some(u) = line["user"].as_str().filter(|u| !u.is_empty()) {
        fields.push(format!("Account: {u}"));
    }
    fields.push(format!("Elevated: {}", if line["elevated"].as_bool() == Some(true) { "yes" } else { "no" }));
    format!("{message}\n{}", fields.join(" · "))
}

/// " for ticket INC0012345", or nothing.
fn for_ticket(ticket: Option<&str>) -> String {
    ticket.map(|t| format!(" for ticket {t}")).unwrap_or_default()
}

/// A finished run: which modules ran and the worst result.
pub fn run_finished(results: &[ModuleResult], cancelled: bool, ticket: Option<&str>) {
    let worst = results
        .iter()
        .map(|r| r.status())
        .max_by_key(|s| s.rank())
        .unwrap_or(Severity::Ok);
    let ids: Vec<&str> = results.iter().map(|r| r.module_id.as_str()).collect();
    let message = format!(
        "ITriage run {}{}: {} module(s), worst result {:?}{}",
        if cancelled { "cancelled" } else { "finished" },
        for_ticket(ticket),
        results.len(),
        worst,
        if ids.is_empty() { String::new() } else { format!(" ({})", ids.join(", ")) }
    );
    record("run", event_id::RUN, true, &message, json!({ "modules": ids, "cancelled": cancelled, "ticket": ticket }));
}

/// A module that changes the machine has finished.
pub fn module_ran(result: &ModuleResult, ticket: Option<&str>) {
    let ok = result.error.is_none();
    let message = match &result.error {
        None => format!("ITriage module {} ran{}: {}", result.module_id, for_ticket(ticket), result.summary),
        Some(e) => format!("ITriage module {} failed{}: {e}", result.module_id, for_ticket(ticket)),
    };
    record("module", event_id::MODULE, ok, &message, json!({ "module": result.module_id, "ticket": ticket }));
}

/// A one-click fix was refused before it ran (policy, remote-safe mode).
pub fn fix_refused(id: &str, target: Option<&str>, why: &str, ticket: Option<&str>) {
    let what = match target {
        Some(t) => format!("{id} ({t})"),
        None => id.to_string(),
    };
    let message = format!("ITriage fix {what} refused{}: {why}", for_ticket(ticket));
    record("fix", event_id::FIX_REFUSED, false, &message, json!({ "fix": id, "target": target, "ticket": ticket, "refused": true }));
}

/// A one-click fix has run.
pub fn fix_ran(id: &str, target: Option<&str>, outcome: &Result<String, String>, ticket: Option<&str>) {
    let what = match target {
        Some(t) => format!("{id} ({t})"),
        None => id.to_string(),
    };
    let (ok, message) = match outcome {
        Ok(m) => (true, format!("ITriage fix {what} succeeded{}: {m}", for_ticket(ticket))),
        Err(e) => (false, format!("ITriage fix {what} failed{}: {e}", for_ticket(ticket))),
    };
    let event = if ok { event_id::FIX_OK } else { event_id::FIX_FAILED };
    record("fix", event, ok, &message, json!({ "fix": id, "target": target, "ticket": ticket }));
}

/// Append a JSON line chained to the one before it, rotating the file at
/// about 5 MB.
fn append(line: &Value) {
    let Some(path) = log_path() else { return };
    append_to(&path, line);
}

/// One writer at a time in this process. Reading the last line and writing
/// the next has to be one step: two writers that both read the same last
/// line would both link to it, and `--verify-audit` would call that a
/// changed log.
static APPENDING: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn append_to(path: &Path, line: &Value) {
    let _one = APPENDING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // And one process at a time: the desktop app and a command-line run can
    // share this account's log. The lock is a file beside it, held until
    // this function returns. Best effort, like the rest: without it the
    // line is still written.
    let lock = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(path.with_extension("jsonl.lock")).ok();
    let _held = lock.as_ref().map(|file| file.lock());
    let rotated = path.with_extension("jsonl.1");
    if std::fs::metadata(path).is_ok_and(|m| m.len() > 5 * 1024 * 1024) {
        let _ = std::fs::rename(path, &rotated);
    }
    let prev = last_line(path).or_else(|| last_line(&rotated)).map(|l| hash(&l)).unwrap_or_else(|| GENESIS.to_string());
    let mut line = line.clone();
    line["prev"] = Value::String(prev);
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

pub fn hash(line: &str) -> String {
    Sha256::digest(line.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// The last non-empty line of a file, read from its end.
fn last_line(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(1024 * 1024);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).ok()?;
    let text = String::from_utf8_lossy(&tail);
    text.lines().rev().find(|l| !l.trim().is_empty()).map(str::to_string)
}

/// What `--verify-audit` found.
#[derive(Debug, Clone, PartialEq)]
pub struct Verification {
    /// Lines whose `prev` matched the line before.
    pub chained: usize,
    /// Lines from before 0.10, without a `prev`.
    pub unchained: usize,
    /// The first chained line's predecessor isn't here (rotated away).
    pub starts_mid_chain: bool,
    /// Where the chain breaks: the file, the line number (from 1) and why.
    pub broken: Option<(PathBuf, usize, String)>,
}

/// Check the chain in `path` (and `path.1` before it, when it's there).
pub fn verify(path: &Path) -> Result<Verification, String> {
    let rotated = path.with_extension("jsonl.1");
    let mut files = Vec::new();
    if rotated.is_file() {
        files.push(rotated);
    }
    if path.is_file() {
        files.push(path.to_path_buf());
    }
    if files.is_empty() {
        return Err(format!("There's no audit log at {}.", path.display()));
    }
    let mut v = Verification { chained: 0, unchained: 0, starts_mid_chain: false, broken: None };
    let mut previous: Option<String> = None;
    let mut seen_chain = false;
    for file in files {
        let text = std::fs::read_to_string(&file).map_err(|e| format!("Can't read {}: {e}", file.display()))?;
        for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
            let at = |why: String| Some((file.clone(), n + 1, why));
            let value: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => {
                    v.broken = at("this line isn't a JSON record".into());
                    return Ok(v);
                }
            };
            match value.get("prev").and_then(Value::as_str) {
                None if seen_chain => {
                    v.broken = at("this line has no link to the one before; it was added by something else".into());
                    return Ok(v);
                }
                None => v.unchained += 1,
                Some(prev) => {
                    match &previous {
                        None if prev != GENESIS => v.starts_mid_chain = true,
                        None => {}
                        Some(before) if hash(before) != prev => {
                            v.broken = at(if n == 0 { "the line before it (the end of the older file) was changed or removed".into() } else { format!("line {n} was changed or removed") });
                            return Ok(v);
                        }
                        Some(_) => {}
                    }
                    seen_chain = true;
                    v.chained += 1;
                }
            }
            previous = Some(line.to_string());
        }
    }
    Ok(v)
}

#[cfg(windows)]
fn system_log(id: u32, ok: bool, message: &str) {
    crate::win::eventlog::report("itriage", id, ok, message);
}

/// syslog(3) under the ident `itriage`; journald picks it up.
#[cfg(not(windows))]
fn system_log(_id: u32, ok: bool, message: &str) {
    static OPEN: std::sync::Once = std::sync::Once::new();
    // SAFETY: the ident is a 'static C string, as openlog requires.
    OPEN.call_once(|| unsafe { libc::openlog(c"itriage".as_ptr(), libc::LOG_PID, libc::LOG_USER) });
    let Ok(text) = std::ffi::CString::new(message.replace('\0', "")) else { return };
    let priority = libc::LOG_USER | if ok { libc::LOG_NOTICE } else { libc::LOG_WARNING };
    // SAFETY: a fixed "%s" format with one NUL-terminated argument.
    unsafe { libc::syslog(priority, c"%s".as_ptr(), text.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::current_dir().unwrap().join("target").join(format!("itriage-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn each_line_is_chained_to_the_one_before() {
        let d = dir("chain");
        let path = d.join("audit.jsonl");
        // A 0.9 line first: kept, not checked.
        std::fs::write(&path, "{\"kind\":\"run\",\"message\":\"old\"}\n").unwrap();
        for i in 0..3 {
            append_to(&path, &json!({ "kind": "fix", "message": format!("fix {i}") }));
        }
        let v = verify(&path).unwrap();
        assert_eq!((v.chained, v.unchained, v.broken.is_none(), v.starts_mid_chain), (3, 1, true, false));
        let lines: Vec<String> = std::fs::read_to_string(&path).unwrap().lines().map(str::to_string).collect();
        let second: Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(second["prev"].as_str().unwrap(), hash(&lines[0]), "the first chained line links to the old one");

        // Change one word in the middle: the next line no longer matches.
        let edited = std::fs::read_to_string(&path).unwrap().replace("fix 1", "fix 9");
        std::fs::write(&path, edited).unwrap();
        let v = verify(&path).unwrap();
        let (_, line, why) = v.broken.unwrap();
        assert_eq!((line, why.as_str()), (4, "line 3 was changed or removed"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_chain_carries_across_rotation_and_catches_an_inserted_line() {
        let d = dir("rotate");
        let path = d.join("audit.jsonl");
        append_to(&path, &json!({ "kind": "run", "message": "a" }));
        std::fs::rename(&path, path.with_extension("jsonl.1")).unwrap();
        append_to(&path, &json!({ "kind": "run", "message": "b" }));
        let v = verify(&path).unwrap();
        assert_eq!((v.chained, v.broken.is_none()), (2, true), "{v:?}");
        // A line without a link, after the chain started, is an insertion.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"kind\":\"fix\",\"message\":\"planted\"}\n");
        std::fs::write(&path, text).unwrap();
        let (_, line, why) = verify(&path).unwrap().broken.unwrap();
        assert!(line == 2 && why.contains("no link"), "{line} {why}");
        // A log whose older half rotated away starts mid-chain, and that's said.
        std::fs::remove_file(path.with_extension("jsonl.1")).unwrap();
        let mut lines: Vec<String> = std::fs::read_to_string(&path).unwrap().lines().map(str::to_string).collect();
        lines.pop();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let v = verify(&path).unwrap();
        assert!(v.starts_mid_chain && v.broken.is_none(), "{v:?}");
        assert!(verify(&d.join("missing.jsonl")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn writers_at_the_same_time_keep_one_chain() {
        let d = dir("together");
        let path = d.join("audit.jsonl");
        std::thread::scope(|scope| {
            for writer in 0..8 {
                let path = &path;
                scope.spawn(move || {
                    for i in 0..25 {
                        append_to(path, &json!({ "kind": "fix", "message": format!("writer {writer} line {i}") }));
                    }
                });
            }
        });
        let v = verify(&path).unwrap();
        assert_eq!((v.chained, v.broken), (200, None), "every line links to the one before it");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_a_managed_profile_can_turn_the_system_log_off() {
        let mut p = crate::profile::Profile::default();
        assert!(system_log_wanted(&p, "managed") && system_log_wanted(&p, "user"));
        p.audit.event_log = false;
        assert!(!system_log_wanted(&p, "managed"));
        assert!(system_log_wanted(&p, "user") && system_log_wanted(&p, "env"), "a user's own profile can't hide what was done");
        let line = json!({ "user": "CORP\\jparker", "elevated": true, "data": { "ticket": "INC1" } });
        assert_eq!(with_fields("ITriage fix flush-dns succeeded", &line), "ITriage fix flush-dns succeeded\nTicket: INC1 · Account: CORP\\jparker · Elevated: yes");
    }
}
