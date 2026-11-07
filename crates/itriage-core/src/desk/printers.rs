//! Printers & print queue. Read-only.
//!
//! The print service first (nothing prints without it), then every real
//! printer with its state, the default printer, label printers called out,
//! and jobs stuck behind a printer that's in an error state.

use crate::actions::offer;
use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::plural;

pub struct Printers;

impl TriageModule for Printers {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Print Spooler state, every printer's status, stuck jobs, the default printer, and label printers."
        } else {
            "CUPS scheduler state, every queue's status, stuck jobs and the default printer."
        };
        ModuleInfo::new("desk.printers", "Printers & print queue", Category::Workstation, description)
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        imp::check()
    }
}

/// One printer's row: state text, severity, and the queue fix when jobs are
/// stuck behind a problem.
fn printer_row(label: String, problems: &[String], notes: &[String], jobs: usize, detail: String) -> Finding {
    let mut parts: Vec<String> = if problems.is_empty() { vec!["ready".into()] } else { problems.to_vec() };
    parts.extend(notes.iter().cloned());
    let stuck = jobs > 0 && !problems.is_empty();
    if jobs > 0 {
        parts.push(format!("{jobs} job{} {}", plural(jobs), if stuck { "stuck" } else { "queued" }));
    }
    let severity = if !problems.is_empty() {
        Severity::Warning
    } else if !notes.is_empty() {
        Severity::Info
    } else {
        Severity::Ok
    };
    let mut f = Finding::new(label, parts.join(" · "), severity).with_detail(detail);
    if stuck {
        f = f.with_action(offer("clear-print-queue", None));
    }
    f
}

fn summarise(physical: usize, attention: usize) -> String {
    match (physical, attention) {
        (0, _) => "Print service running · no printers installed".into(),
        (n, 0) => format!("{n} printer{} ready", plural(n)),
        (n, a) => format!("{n} printer{} · {a} need{} attention", plural(n), if a == 1 { "s" } else { "" }),
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::printer::{is_label_printer, is_virtual, windows_status};
    use crate::win::{printing, scm};

    pub fn check() -> Result<Output, String> {
        match scm::query("Spooler")? {
            None => {
                return Ok(Output::new(
                    "Printing isn't installed on this machine",
                    vec![Finding::info("Print Spooler", "not installed")],
                ))
            }
            // Servers often disable the spooler on purpose (PrintNightmare hardening).
            Some(s) if !s.running && s.start == scm::StartMode::Disabled => {
                return Ok(Output::new(
                    "Printing is turned off on this machine",
                    vec![Finding::info("Print Spooler", "disabled · printing is turned off here")],
                ))
            }
            Some(s) if !s.running => {
                return Ok(Output::new(
                    "The Print Spooler isn't running, so nothing can print",
                    vec![Finding::crit("Print Spooler", format!("{} · nothing can print", s.state))
                        .with_action(offer("restart-spooler", None))],
                ))
            }
            Some(_) => {}
        }
        let mut findings = vec![Finding::ok("Print Spooler", "running")];
        let printers = printing::printers().map_err(|e| crate::win::err("can't list printers", &e))?;
        let default = printing::default_printer();

        let (mut virtuals, mut physical, mut attention) = (0usize, 0usize, 0usize);
        for p in &printers {
            if is_virtual(&p.name, &p.port) {
                virtuals += 1;
                continue;
            }
            physical += 1;
            let (problems, notes) = windows_status(p.status, p.attributes);
            let mut tags = Vec::new();
            if default.as_deref() == Some(p.name.as_str()) {
                tags.push("default");
            }
            if is_label_printer(&p.name, &p.driver) {
                tags.push("label printer");
            }
            let label = if tags.is_empty() { p.name.clone() } else { format!("{} ({})", p.name, tags.join(", ")) };
            let problems: Vec<String> = problems.iter().map(|s| s.to_string()).collect();
            let notes: Vec<String> = notes.iter().map(|s| s.to_string()).collect();
            if !problems.is_empty() {
                attention += 1;
            }
            findings.push(printer_row(
                label,
                &problems,
                &notes,
                p.jobs as usize,
                format!("{} · port {}", p.driver, p.port),
            ));
        }
        findings.push(match &default {
            Some(d) => Finding::info("Default printer", d.clone()),
            None => Finding::info("Default printer", "none set"),
        });
        if virtuals > 0 {
            findings.push(Finding::info("Software printers (PDF, XPS, OneNote, fax)", virtuals.to_string()));
        }
        Ok(Output::new(summarise(physical, attention), findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::printer::{cups_default, cups_job_counts, cups_printers};
    use crate::util::{capture, cmd, command_exists};

    fn lpstat(args: &[&str]) -> String {
        let mut c = cmd("lpstat");
        c.args(args).env("LC_ALL", "C");
        capture(c).map(|o| o.stdout).unwrap_or_default()
    }

    pub fn check() -> Result<Output, String> {
        if !command_exists("lpstat") {
            return Ok(Output::new(
                "No print system installed",
                vec![Finding::info("CUPS", "not installed (no lpstat)")],
            ));
        }
        if !lpstat(&["-r"]).contains("scheduler is running") {
            return Ok(Output::new(
                "The CUPS scheduler isn't running, so nothing can print",
                vec![Finding::crit("CUPS scheduler", "not running").with_action(offer("restart-spooler", None))],
            ));
        }
        let mut findings = vec![Finding::ok("CUPS scheduler", "running")];
        let queues = cups_printers(&lpstat(&["-p"]));
        let default = cups_default(&lpstat(&["-d"]));
        let jobs = cups_job_counts(&lpstat(&["-o"]));

        let mut attention = 0;
        for q in &queues {
            let mut problems = Vec::new();
            if !q.enabled {
                problems.push(match &q.reason {
                    Some(r) => format!("stopped ({r})"),
                    None => "stopped".to_string(),
                });
                attention += 1;
            }
            let notes: Vec<String> = if q.printing { vec!["printing".into()] } else { Vec::new() };
            let label = if default.as_deref() == Some(q.name.as_str()) {
                format!("{} (default)", q.name)
            } else {
                q.name.clone()
            };
            let detail = if q.enabled { q.reason.clone().unwrap_or_default() } else { String::new() };
            let row = printer_row(label, &problems, &notes, jobs.get(&q.name).copied().unwrap_or(0), detail);
            // "printing" is good news, not a note worth an info dot.
            findings.push(if q.printing && problems.is_empty() { Finding { severity: Severity::Ok, ..row } } else { row });
        }
        findings.push(Finding::info("Default printer", default.unwrap_or_else(|| "none set".into())));
        Ok(Output::new(summarise(queues.len(), attention), findings))
    }
}
