//! Running a fixed PowerShell script, for the few steps that only have a
//! PowerShell interface (NetAdapter power management and restarts, the
//! Configuration Manager client's WMI methods).
//!
//! Scripts are compile-time constants: nothing from the user, the network or
//! a profile is ever spliced into them. They go in as `-EncodedCommand`
//! (base64 UTF-16LE), so quoting can't change their meaning.

use crate::fixes::ROWS_MARKER;
use crate::module::RunContext;
use crate::parse::text::{clixml_errors, utf16le_base64};
use crate::util::{cmd, stream, CmdOutput};
use std::time::Duration;

/// Run `script` with Windows PowerShell, streaming its output to the log.
///
/// Progress records are switched off (a redirected PowerShell otherwise
/// writes "Preparing modules for first use." as CLIXML). The log gets the
/// script's own lines and the text of any errors, not the rows line (data
/// for the module) or raw CLIXML.
pub fn run(script: &'static str, ctx: &RunContext, timeout: Duration) -> Result<CmdOutput, String> {
    let script = format!("$ProgressPreference = 'SilentlyContinue'\n{script}");
    let mut c = cmd("powershell.exe");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
        .arg(utf16le_base64(&script));
    let readable = |line: &str| {
        let t = line.trim_start();
        if t.starts_with(ROWS_MARKER.trim_end()) || t.starts_with("#< CLIXML") {
            return;
        }
        if t.starts_with("<Objs ") {
            for e in clixml_errors(t).into_iter().take(4) {
                ctx.log(format!("PowerShell: {e}"));
            }
            return;
        }
        ctx.log(line);
    };
    stream(c, &ctx.with_sink(&readable), timeout)
}
