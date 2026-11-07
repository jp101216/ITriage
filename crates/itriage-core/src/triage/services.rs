//! Service health. Read-only.
//!
//! Windows: Automatic-start services that aren't running, judged the way a
//! Tier 2 tech would. Trigger-start services, per-user templates and a short
//! list of self-stopping updaters are excluded, since they're stopped by
//! design. That removes most of the false positives that a plain "StartMode =
//! Auto and State != Running" query reports.
//!
//! Linux: failed systemd units and the overall `is-system-running` state.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};

pub struct ServiceHealth;

impl TriageModule for ServiceHealth {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Automatic services that aren't running, with exit codes. Skips trigger-start services that stop by design."
        } else {
            "Failed systemd units and the overall system state."
        };
        ModuleInfo::new("proc.services", "Services", Category::Processes, description)
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        imp::check()
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::util::plural;
    use crate::win::scm::{services, StartMode};

    /// Automatic services that routinely stop themselves once their work is
    /// done (updaters, licensing). Case-insensitive name prefixes.
    const SELF_STOPPING: &[&str] = &[
        "sppsvc",
        "gupdate",
        "edgeupdate",
        "googleupdater",
        "brave",
        "mapsbroker",
        "clr_optimization_",
    ];

    /// ERROR_SERVICE_NEVER_STARTED: hasn't been started since boot.
    const NEVER_STARTED: u32 = 1077;

    pub fn check() -> Result<Output, String> {
        let all = services()?;
        let running = all.iter().filter(|s| s.running).count();

        let mut problems = Vec::new();
        let (mut by_design, mut updaters) = (0usize, 0usize);
        for s in &all {
            if s.running || !matches!(s.start, StartMode::Auto | StartMode::AutoDelayed) {
                continue;
            }
            if s.trigger_start || s.is_user_template() {
                by_design += 1;
                continue;
            }
            let lower = s.name.to_ascii_lowercase();
            if SELF_STOPPING.iter().any(|p| lower.starts_with(p)) {
                updaters += 1;
                continue;
            }

            let crashed = s.exit_code != 0 && s.exit_code != NEVER_STARTED;
            let delayed = s.start == StartMode::AutoDelayed;
            let severity = match (crashed, delayed) {
                (true, false) => Severity::Critical,
                (true, true) | (false, false) => Severity::Warning,
                (false, true) => Severity::Info,
            };
            let state = if crashed {
                format!("stopped · exit {}", s.exit_code)
            } else if s.exit_code == NEVER_STARTED {
                "never started".to_string()
            } else {
                "stopped".to_string()
            };
            let mode = if delayed { "Automatic (delayed)" } else { "Automatic" };
            let mut finding = Finding::new(
                format!("{} ({})", s.display_name, s.name),
                format!("{state} · {mode}"),
                severity,
            );
            if crashed {
                // e.g. "The process terminated unexpectedly. (os error 1067)"
                finding = finding.with_detail(std::io::Error::from_raw_os_error(s.exit_code as i32).to_string());
            }
            problems.push(finding);
        }

        problems.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
        let flagged = problems
            .iter()
            .filter(|f| f.severity.rank() >= Severity::Warning.rank())
            .count();

        let mut findings = vec![Finding::ok("Running services", running.to_string())];
        findings.extend(problems);
        if by_design + updaters > 0 {
            findings.push(Finding::info(
                "Stopped by design (skipped)",
                format!("{by_design} trigger-start/per-user, {updaters} self-stopping updater{}", plural(updaters)),
            ));
        }

        let summary = if flagged == 0 {
            format!("{running} running · automatic services healthy")
        } else {
            format!("{running} running · {flagged} automatic service{} not running", plural(flagged))
        };
        Ok(Output::new(summary, findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::systemd::{unit_rows, UnitRow};
    use crate::parse::text::first_line;
    use crate::util::{capture, cmd, command_exists, plural};

    pub fn check() -> Result<Output, String> {
        if !command_exists("systemctl") {
            return Err("systemd not detected (no systemctl). This check reads systemd units.".into());
        }

        let mut c = cmd("systemctl");
        c.arg("is-system-running").env("LC_ALL", "C");
        let state_out = capture(c)?;
        let state = state_out.stdout.trim().to_string();
        let combined = state_out.combined();
        if state.is_empty()
            || state == "offline"
            || combined.contains("not been booted with systemd")
            || combined.contains("Failed to connect to bus")
        {
            return Err(format!(
                "systemd isn't running as init here ({}). That's normal in containers and WSL without systemd.",
                first_line(&combined)
            ));
        }

        let running = units(&["--type=service", "--state=running"])?.len();
        let failed = units(&["--state=failed"])?;

        let state_severity = match state.as_str() {
            "running" => Severity::Ok,
            "starting" | "initializing" => Severity::Info,
            _ => Severity::Warning, // degraded, maintenance, stopping
        };
        let mut findings = vec![
            Finding::new("System state", state.clone(), state_severity),
            Finding::ok("Running services", running.to_string()),
        ];
        for u in &failed {
            findings.push(
                Finding::warn(u.unit.clone(), format!("{} ({})", u.active, u.sub))
                    .with_detail(u.description.clone()),
            );
        }

        let summary = if failed.is_empty() {
            format!("{running} services running · no failed units")
        } else {
            format!("{running} running · {} failed unit{}", failed.len(), plural(failed.len()))
        };
        Ok(Output::new(summary, findings))
    }

    fn units(filter: &[&str]) -> Result<Vec<UnitRow>, String> {
        let mut c = cmd("systemctl");
        c.args(["list-units", "--no-legend", "--plain", "--no-pager"])
            .args(filter)
            .env("LC_ALL", "C");
        let out = capture(c)?;
        if !out.success() {
            return Err(format!("systemctl list-units failed: {}", first_line(&out.combined())));
        }
        Ok(unit_rows(&out.stdout))
    }
}
