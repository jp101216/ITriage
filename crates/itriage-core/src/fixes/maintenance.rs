//! The Endpoint Tune-Up's cleanup and optimize phases, after temp files
//! (`fix.temp`), plus the restart that finishes a tune-up. All MUTATING.
//!
//! * `fix.recycle`: empty the Recycle Bin (opt-in, as `-ClearRecycleBin` is).
//! * `fix.repair`: DISM component-store cleanup, then `sfc /scannow`
//!   (`-DeepClean`; 15–45 minutes).
//! * `fix.optimize`: optimise the system drive (TRIM on an SSD, defragment
//!   on a hard disk); `fstrim` on Linux.
//! * `fix.gpupdate`: `gpupdate /force`.
//! * `fix.sccm`: Configuration Manager client policy, deployment and
//!   inventory cycles, when the client is installed and running.
//! * `fix.restart`: restart in 60 seconds with a warning to the signed-in
//!   user (`-Reboot`), cancellable with the Cancel restart fix.
//!
//! Policy refresh, client cycles and the restart briefly drop or end remote
//! sessions, so remote-safe mode locks them, as `-RemoteSafe` skips them.
//! Never included (as in the Tune-Up): clearing event logs, Prefetch, the
//! Windows Update download cache, the Delivery Optimization cache or Windows
//! Error Reporting queues.

use super::netrepair::would;
use super::{step, tally, OnError};
use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
use crate::util::human_bytes;
use std::time::Duration;

/// What the signed-in user sees before a restart.
pub const RESTART_MESSAGE: &str =
    "IT maintenance is complete. This PC will restart in 1 minute - please save your work.";

// -------------------------------------------------------------- fix.recycle

pub struct EmptyRecycleBin;

impl TriageModule for EmptyRecycleBin {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.recycle",
            "Empty Recycle Bin",
            Category::Fixes,
            "Permanently deletes what's in the Recycle Bin (the Trash on Linux) for the account itriage runs as.",
        )
        .mutating()
        .warning("Permanently deletes files the user may still expect to recover. Ask them first.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        let (items, bytes) = imp::recycle_size()?;
        Ok(Output::new(
            "Preview: nothing was deleted.",
            vec![Finding::info("Would delete", format!("{items} item{} ({})", crate::util::plural(items as usize), human_bytes(bytes)))],
        ))
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let (items, bytes) = imp::recycle_size()?;
        if items == 0 {
            return Ok(Output::new("The Recycle Bin was already empty", vec![Finding::ok("Recycle Bin", "already empty")]));
        }
        ctx.log(format!("Emptying {items} item(s), {}…", human_bytes(bytes)));
        imp::empty_recycle()?;
        Ok(Output::new(
            format!("Freed {} from the Recycle Bin", human_bytes(bytes)),
            vec![Finding::ok("Recycle Bin", format!("emptied: {items} item{} ({})", crate::util::plural(items as usize), human_bytes(bytes)))],
        ))
    }
}

// --------------------------------------------------------------- fix.repair

pub struct RepairImage;

impl TriageModule for RepairImage {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.repair",
            "Clean up & check system files",
            Category::Fixes,
            "DISM component-store cleanup, then System File Checker (sfc /scannow). Takes 15–45 minutes; use when corruption is suspected or space is critical.",
        )
        .only("windows")
        .mutating()
        .admin()
        .warning("Runs DISM and SFC, which take 15–45 minutes and keep the disk busy. Don't restart until they finish.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        Ok(would(
            "would clean the component store and check system files (15–45 minutes)",
            &["dism /Online /Cleanup-Image /StartComponentCleanup /NoRestart", "sfc /scannow"],
        ))
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        crate::util::require_admin_here()?;
        ctx.log("DISM component-store cleanup (10–30 minutes)…");
        let dism = step(
            ctx,
            "DISM component-store cleanup",
            "dism",
            &["/Online", "/Cleanup-Image", "/StartComponentCleanup", "/NoRestart"],
            &[0, 3010],
            OnError::Fail,
            Duration::from_secs(90 * 60),
        );
        let restart = dism.code == Some(3010);
        if ctx.cancelled() {
            return Ok(Output::new("Stopped after DISM (run cancelled)", vec![dism.finding]).restart_required(restart));
        }
        ctx.log("System File Checker (10–20 minutes)…");
        let mut sfc = step(ctx, "System File Checker", "sfc", &["/scannow"], &[0], OnError::Fail, Duration::from_secs(90 * 60));
        if !sfc.ok {
            sfc.finding = sfc.finding.with_detail(r"Details are in C:\Windows\Logs\CBS\CBS.log.");
        }
        let findings = vec![dism.finding, sfc.finding];
        let (_, failed) = tally(&findings);
        let summary = if failed == 0 { "Component store cleaned; system files checked" } else { "System file repair reported problems" };
        Ok(Output::new(summary, findings).restart_required(restart))
    }
}

// ------------------------------------------------------------- fix.optimize

pub struct OptimizeDrives;

impl TriageModule for OptimizeDrives {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Optimises the system drive: TRIM on an SSD, defragmentation on a hard disk (defrag /O)."
        } else {
            "Trims every mounted filesystem that supports it (fstrim -av)."
        };
        ModuleInfo::new("fix.optimize", "Optimize system drive", Category::Fixes, description)
            .mutating()
            .admin()
            .warning("Keeps the disk busy for a few minutes (longer on a hard disk).")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        let command = if cfg!(windows) { format!("defrag {} /O /U", system_drive()) } else { "fstrim -av".into() };
        Ok(would("would optimise the system drive", &[command.as_str()]))
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        crate::util::require_admin_here()?;
        imp::optimize(ctx)
    }
}

pub(crate) fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

// ------------------------------------------------------------ fix.gpupdate

pub struct RefreshPolicy;

impl TriageModule for RefreshPolicy {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.gpupdate",
            "Refresh Group Policy",
            Category::Fixes,
            "Reapplies computer and user Group Policy (gpupdate /force).",
        )
        .only("windows")
        .mutating()
        .disruptive()
        .warning("Reapplies every policy. Network and proxy policies can blip connections while they apply.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        Ok(would("would reapply Group Policy", &["gpupdate /force"]))
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let s = step(ctx, "gpupdate /force", "gpupdate", &["/force", "/wait:120"], &[0], OnError::Fail, Duration::from_secs(300));
        let summary = if s.ok { "Group Policy refreshed" } else { "Group Policy refresh reported a problem" };
        Ok(Output::new(summary, vec![s.finding]))
    }
}

// ---------------------------------------------------------------- fix.sccm

pub struct ConfigMgrCycles;

/// The Tune-Up's three client actions. A missing or non-zero ReturnValue
/// fails the row; a method that returns nothing counts as triggered.
#[cfg_attr(not(windows), allow(dead_code))]
const SCCM_TRIGGERS: &str = r#"
$ErrorActionPreference = 'Stop'
$schedules = [ordered]@{
  'Machine policy retrieval & evaluation' = '{00000000-0000-0000-0000-000000000021}'
  'Application deployment evaluation'     = '{00000000-0000-0000-0000-000000000121}'
  'Hardware inventory'                    = '{00000000-0000-0000-0000-000000000001}'
}
$rows = @()
foreach ($name in $schedules.Keys) {
  try {
    $r = Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID = $schedules[$name] }
    if ($null -eq $r -or $null -eq $r.ReturnValue -or $r.ReturnValue -eq 0) { $rows += [pscustomobject]@{ Item = $name; Status = 'Changed'; Detail = 'triggered' } }
    else { $rows += [pscustomobject]@{ Item = $name; Status = 'Failed'; Detail = "the client returned $($r.ReturnValue)" } }
  } catch { $rows += [pscustomobject]@{ Item = $name; Status = 'Failed'; Detail = $_.Exception.Message } }
}
'ITRIAGE-ROWS ' + (ConvertTo-Json -InputObject @($rows) -Compress)
"#;

impl TriageModule for ConfigMgrCycles {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.sccm",
            "Run Configuration Manager actions",
            Category::Fixes,
            "Triggers the SCCM/MECM client's machine policy, application deployment and hardware inventory cycles, if the client is installed.",
        )
        .only("windows")
        .mutating()
        .admin()
        .disruptive()
        .warning("Asks the Configuration Manager client to fetch policy and evaluate deployments now; software it's told to install may start installing.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        let (state, running) = imp::ccm_state();
        if !running {
            let summary = format!("Preview: a real run would skip this ({} {}). Nothing was changed.", state.label, state.value);
            return Ok(Output::new(summary, vec![state]));
        }
        let mut findings = vec![state];
        findings.extend(
            ["Machine policy retrieval & evaluation", "Application deployment evaluation", "Hardware inventory"]
                .map(|cycle| Finding::info("Would run", cycle)),
        );
        Ok(Output::new(
            "Preview: would trigger the client's policy, deployment and inventory cycles. Nothing was changed.",
            findings,
        ))
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        crate::util::require_admin_here()?;
        let (state, running) = imp::ccm_state();
        if !running {
            let summary = format!("Skipped: {} {}", state.label, state.value);
            return Ok(Output::new(summary, vec![state]));
        }
        let findings = imp::ccm_trigger(ctx);
        let (ok, failed) = tally(&findings);
        let summary = if failed == 0 {
            format!("Triggered {ok} Configuration Manager action{}", crate::util::plural(ok))
        } else {
            format!("{failed} of {} Configuration Manager actions failed", findings.len())
        };
        Ok(Output::new(summary, findings))
    }
}

// ------------------------------------------------------------- fix.restart

pub struct RestartComputer;

impl TriageModule for RestartComputer {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.restart",
            "Restart the PC",
            Category::Fixes,
            "Restarts in 60 seconds, warning the signed-in user to save their work. Runs last in a sequence; Cancel restart stops it.",
        )
        .mutating()
        .admin()
        .disruptive()
        .warning("The PC restarts one minute after this runs. Unsaved work is lost if the user doesn't save it.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        Ok(Output::new(
            "Preview: would restart in 60 seconds. Nothing was changed.",
            vec![Finding::info("Would tell the user", RESTART_MESSAGE)],
        ))
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let said = schedule_restart()?;
        Ok(Output::new(
            "Restarting in 60 seconds",
            vec![Finding::warn("Restart", said).with_action(crate::actions::offer("cancel-restart", None))],
        ))
    }
}

/// Schedule the restart (shared with the restart-computer fix).
#[cfg(windows)]
pub fn schedule_restart() -> Result<String, String> {
    crate::util::run_command("shutdown", &["/r", "/t", "60", "/c", RESTART_MESSAGE])?;
    Ok("scheduled in 60 seconds; the signed-in user was warned".into())
}

#[cfg(not(windows))]
pub fn schedule_restart() -> Result<String, String> {
    root("shutdown", &["-r", "+1", RESTART_MESSAGE])?;
    Ok("scheduled in 1 minute; signed-in users were warned".into())
}

/// Cancel a scheduled restart (the Cancel restart fix).
#[cfg(windows)]
pub fn cancel_restart() -> Result<String, String> {
    let mut c = crate::util::cmd("shutdown");
    c.arg("/a");
    let out = crate::util::capture(c)?;
    match out.code {
        Some(0) => Ok("Restart cancelled.".into()),
        // ERROR_NO_SHUTDOWN_IN_PROGRESS
        Some(1116) => Ok("No restart was scheduled.".into()),
        other => Err(format!("shutdown /a failed ({}): {}", crate::util::exit_label(other), out.combined())),
    }
}

#[cfg(not(windows))]
pub fn cancel_restart() -> Result<String, String> {
    root("shutdown", &["-c"]).map(|_| "Restart cancelled.".into())
}

#[cfg(not(windows))]
fn root(program: &str, args: &[&str]) -> Result<String, String> {
    use crate::util::{capture, pkexec_error, privileged};
    let (c, via_pkexec) = privileged(program, args)?;
    let out = capture(c)?;
    if via_pkexec {
        if let Some(why) = pkexec_error(out.code) {
            return Err(why.to_string());
        }
    }
    if out.success() {
        Ok(out.combined())
    } else {
        Err(format!("{program} failed: {}", crate::parse::text::first_line(&out.combined())))
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::win::scm;
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::{
        SHEmptyRecycleBinW, SHQueryRecycleBinW, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHQUERYRBINFO,
    };

    pub fn recycle_size() -> Result<(u64, u64), String> {
        let mut info = SHQUERYRBINFO {
            cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
            ..Default::default()
        };
        // SAFETY: plain out-parameter; a null root means every drive.
        unsafe { SHQueryRecycleBinW(PCWSTR::null(), &mut info) }
            .map_err(|e| crate::win::err("reading the Recycle Bin", &e))?;
        Ok((info.i64NumItems.max(0) as u64, info.i64Size.max(0) as u64))
    }

    pub fn empty_recycle() -> Result<(), String> {
        // SAFETY: no window, every drive, no prompts.
        unsafe {
            SHEmptyRecycleBinW(None, PCWSTR::null(), SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)
        }
        .map_err(|e| crate::win::err("emptying the Recycle Bin", &e))
    }

    pub fn optimize(ctx: &RunContext) -> Result<Output, String> {
        let drive = system_drive();
        let s = step(ctx, &format!("Optimize {drive}"), "defrag", &[&drive, "/O", "/U"], &[0], OnError::Fail, Duration::from_secs(3 * 3600));
        let summary = if s.ok { format!("{drive} optimised") } else { format!("Optimising {drive} failed") };
        Ok(Output::new(summary, vec![s.finding]))
    }

    /// Whether the Configuration Manager client is there and running.
    pub fn ccm_state() -> (Finding, bool) {
        match scm::query("CcmExec") {
            Ok(Some(s)) if s.running => (Finding::ok("Configuration Manager client", "running"), true),
            Ok(Some(s)) => (Finding::warn("Configuration Manager client", format!("not running ({})", s.state)), false),
            Ok(None) => (Finding::info("Configuration Manager client", "not installed"), false),
            Err(e) => (Finding::warn("Configuration Manager client", e), false),
        }
    }

    pub fn ccm_trigger(ctx: &RunContext) -> Vec<Finding> {
        match crate::win::ps::run(SCCM_TRIGGERS, ctx, Duration::from_secs(180)) {
            Ok(out) => match crate::fixes::rows(&out.stdout) {
                Some(rows) => rows.iter().map(|r| r.finding()).collect(),
                None => vec![Finding::crit("Client actions", format!("PowerShell gave no result ({})", crate::util::exit_label(out.code)))],
            },
            Err(e) => vec![Finding::crit("Client actions", e)],
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::path::PathBuf;

    fn trash() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
        Some(base.join("Trash"))
    }

    fn walk(dir: &std::path::Path) -> (u64, u64) {
        let mut out = (0, 0);
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                match e.metadata() {
                    Ok(m) if m.is_dir() => {
                        let (n, b) = walk(&e.path());
                        out.0 += n;
                        out.1 += b;
                    }
                    Ok(m) => {
                        out.0 += 1;
                        out.1 += m.len();
                    }
                    Err(_) => {}
                }
            }
        }
        out
    }

    pub fn recycle_size() -> Result<(u64, u64), String> {
        let Some(t) = trash() else { return Ok((0, 0)) };
        let items = std::fs::read_dir(t.join("files")).map(|r| r.count() as u64).unwrap_or(0);
        Ok((items, walk(&t.join("files")).1))
    }

    pub fn empty_recycle() -> Result<(), String> {
        let t = trash().ok_or("no home folder")?;
        for sub in ["files", "info", "expunged"] {
            let dir = t.join(sub);
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let p = e.path();
                    let r = if p.is_dir() && !p.is_symlink() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
                    r.map_err(|err| format!("couldn't delete {}: {err}", p.display()))?;
                }
            }
        }
        Ok(())
    }

    pub fn optimize(ctx: &RunContext) -> Result<Output, String> {
        use crate::util::{pkexec_error, privileged, stream};
        let (c, via_pkexec) = privileged("fstrim", &["-av"])?;
        if via_pkexec {
            ctx.log("Asking for your password (pkexec)…");
        }
        let out = stream(c, ctx, Duration::from_secs(3600))?;
        if via_pkexec {
            if let Some(why) = pkexec_error(out.code) {
                return Err(why.to_string());
            }
        }
        let trimmed: Vec<&str> = out.stdout.lines().filter(|l| l.contains("trimmed")).collect();
        let f = match out.code {
            Some(0) if trimmed.is_empty() => Finding::info("fstrim", "no filesystem supports TRIM"),
            Some(0) => Finding::ok("fstrim", trimmed.join(" · ")),
            other => Finding::crit("fstrim", format!("failed ({})", crate::util::exit_label(other))),
        };
        let summary = if f.severity == crate::model::Severity::Critical { "Trimming failed" } else { "Filesystems trimmed" };
        Ok(Output::new(summary, vec![f]))
    }

    pub fn ccm_state() -> (Finding, bool) {
        (Finding::info("Configuration Manager client", "Windows only"), false)
    }

    #[allow(dead_code)]
    pub fn ccm_trigger(_ctx: &RunContext) -> Vec<Finding> {
        Vec::new()
    }
}
