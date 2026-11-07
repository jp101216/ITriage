//! Flush the DNS resolver cache. MUTATING. Routes to the native mechanism:
//! `ipconfig /flushdns` on Windows, `resolvectl` / `systemd-resolve` on Linux.

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

    #[cfg(windows)]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let out = crate::util::run_command("ipconfig", &["/flushdns"])?;
        Ok(Output::new(
            "DNS resolver cache flushed.",
            vec![Finding::ok("ipconfig /flushdns", crate::parse::text::first_line(&out))],
        ))
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
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
        Ok(Output::new(
            "systemd-resolved cache flushed.",
            vec![Finding::ok(
                format!("{program} {}", args.join(" ")),
                if out.is_empty() { "done".to_string() } else { out },
            )],
        ))
    }
}
