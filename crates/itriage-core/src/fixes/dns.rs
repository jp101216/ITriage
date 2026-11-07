//! Flush the DNS resolver cache and re-register this PC's DNS records.
//! MUTATING. The first two Tune-Up network steps, and the only ones that
//! stay available in remote-safe mode: neither drops a connection.
//!
//! Windows: `ipconfig /flushdns`, then `ipconfig /registerdns` (which needs
//! administrator rights; without them it's skipped and said so). Linux:
//! `resolvectl flush-caches`. Also offered as the `flush-dns` one-click fix.

use super::{step, OnError};
use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
use std::time::Duration;

pub struct FlushDns;

const WAIT: Duration = Duration::from_secs(120);

impl TriageModule for FlushDns {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Flushes the DNS resolver cache (ipconfig /flushdns) and re-registers this PC's DNS records (ipconfig /registerdns)."
        } else {
            "Flushes the DNS resolver cache (resolvectl flush-caches)."
        };
        ModuleInfo::new("fix.dns", "Flush & re-register DNS", Category::Repair, description)
            .mutating()
            .warning("Clears cached DNS lookups, so the next few page loads may be a little slower.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        let command = flush_command();
        let summary = if command.is_ok() {
            "Preview: would flush the DNS cache. Nothing was changed."
        } else {
            "Preview: a real run couldn't flush the DNS cache here. Nothing was changed."
        };
        let mut findings = vec![match command {
            Ok((program, args)) => Finding::info("Would run", format!("{program} {}", args.join(" "))),
            Err(why) => Finding::warn("Would skip", why),
        }];
        if cfg!(windows) {
            findings.push(if crate::host::is_elevated() {
                Finding::info("Would run", "ipconfig /registerdns")
            } else {
                Finding::info("Would skip", "ipconfig /registerdns (needs administrator rights)")
            });
        }
        Ok(Output::new(summary, findings))
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let mut findings = Vec::new();
        let (command, said) = flush()?;
        findings.push(Finding::ok(command, said));
        if cfg!(windows) {
            if crate::host::is_elevated() {
                let s = step(ctx, "ipconfig /registerdns", "ipconfig", &["/registerdns"], &[0], OnError::Fail, WAIT);
                findings.push(s.finding);
            } else {
                findings.push(Finding::info("ipconfig /registerdns", "skipped: needs administrator rights"));
            }
        }
        let failed = findings.iter().any(|f| f.severity == crate::model::Severity::Critical);
        let summary = match (cfg!(windows), failed) {
            (_, true) => "DNS cache flushed; re-registering failed",
            (true, false) => "DNS cache flushed and records re-registered",
            (false, false) => "systemd-resolved cache flushed",
        };
        Ok(Output::new(summary, findings))
    }
}

/// The command a real run flushes with, or why there isn't one here.
#[cfg(windows)]
fn flush_command() -> Result<(&'static str, &'static [&'static str]), &'static str> {
    Ok(("ipconfig", &["/flushdns"]))
}

#[cfg(not(windows))]
fn flush_command() -> Result<(&'static str, &'static [&'static str]), &'static str> {
    use crate::util::command_exists;
    if command_exists("resolvectl") {
        Ok(("resolvectl", &["flush-caches"]))
    } else if command_exists("systemd-resolve") {
        Ok(("systemd-resolve", &["--flush-caches"]))
    } else {
        Err("No supported DNS cache found (resolvectl / systemd-resolve). \
             A box running nscd or dnsmasq needs that service restarted instead.")
    }
}

/// Flush the cache. Returns the command that ran and what it said.
#[cfg(windows)]
pub fn flush() -> Result<(String, String), String> {
    let (program, args) = flush_command()?;
    let out = crate::util::run_command(program, args)?;
    Ok((format!("{program} {}", args.join(" ")), crate::parse::text::first_line(&out).to_string()))
}

#[cfg(not(windows))]
pub fn flush() -> Result<(String, String), String> {
    let (program, args) = flush_command()?;
    let out = crate::util::run_command(program, args)?;
    Ok((
        format!("{program} {}", args.join(" ")),
        if out.is_empty() { "done".to_string() } else { out },
    ))
}
