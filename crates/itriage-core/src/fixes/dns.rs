//! Flush the DNS resolver cache. MUTATING. Routes to the native mechanism:
//! `ipconfig /flushdns` on Windows, `resolvectl` / `systemd-resolve` on Linux.
//! Also offered as the `flush-dns` one-click fix (see `crate::actions`).

use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};

pub struct FlushDns;

impl TriageModule for FlushDns {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.dns",
            "Flush DNS cache",
            Category::Fixes,
            "Clears the OS DNS resolver cache (ipconfig / resolvectl).",
        )
        .mutating()
        .warning("Clears cached DNS lookups. The next few page loads may be a little slower.")
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let (command, said) = flush()?;
        Ok(Output::new(
            if cfg!(windows) { "DNS resolver cache flushed." } else { "systemd-resolved cache flushed." },
            vec![Finding::ok(command, said)],
        ))
    }
}

/// Flush the cache. Returns the command that ran and what it said.
#[cfg(windows)]
pub fn flush() -> Result<(String, String), String> {
    let out = crate::util::run_command("ipconfig", &["/flushdns"])?;
    Ok(("ipconfig /flushdns".into(), crate::parse::text::first_line(&out).to_string()))
}

#[cfg(not(windows))]
pub fn flush() -> Result<(String, String), String> {
    use crate::util::{command_exists, run_command};

    let (program, args): (&str, &[&str]) = if command_exists("resolvectl") {
        ("resolvectl", &["flush-caches"])
    } else if command_exists("systemd-resolve") {
        ("systemd-resolve", &["--flush-caches"])
    } else {
        return Err("No supported DNS cache found (resolvectl / systemd-resolve). \
                    A box running nscd or dnsmasq needs that service restarted instead."
            .into());
    };
    let out = run_command(program, args)?;
    Ok((
        format!("{program} {}", args.join(" ")),
        if out.is_empty() { "done".to_string() } else { out },
    ))
}
