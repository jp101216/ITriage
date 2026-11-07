//! Running a fixed PowerShell script, for the few steps that only have a
//! PowerShell interface (NetAdapter power management and restarts, the
//! Configuration Manager client's WMI methods).
//!
//! Scripts are compile-time constants: nothing from the user, the network or
//! a profile is ever spliced into them. They go in as `-EncodedCommand`
//! (base64 UTF-16LE), so quoting can't change their meaning.

use crate::module::RunContext;
use crate::parse::text::utf16le_base64;
use crate::util::{cmd, stream, CmdOutput};
use std::time::Duration;

/// Run `script` with Windows PowerShell, streaming its output to the log.
pub fn run(script: &'static str, ctx: &RunContext, timeout: Duration) -> Result<CmdOutput, String> {
    let mut c = cmd("powershell.exe");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
        .arg(utf16le_base64(script));
    stream(c, ctx, timeout)
}
