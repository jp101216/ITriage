//! Running a fixed PowerShell script, for the few steps that only have a
//! PowerShell interface (NetAdapter power management and restarts, the
//! Configuration Manager client's WMI methods).
//!
//! Scripts are compile-time constants: nothing from the user, the network or
//! a profile is ever spliced into them. They go in as `-EncodedCommand`
//! (base64 UTF-16LE), so quoting can't change their meaning.

use crate::fixes::{JSON_MARKER, ROWS_MARKER};
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
    run_with(script, &[], ctx, timeout)
}

/// What every script starts with. `Send-ITriage` prints a result as one line
/// of JSON after a marker, with everything outside printable ASCII escaped,
/// so a name with an accent survives whatever code page the pipe is in. It
/// sticks to operators and string methods, which still work where
/// PowerShell is held to Constrained Language mode.
pub(crate) const PRELUDE: &str = r#"$ProgressPreference = 'SilentlyContinue'
function Send-ITriage($Value) {
  $json = ConvertTo-Json -InputObject $Value -Depth 6 -Compress
  if ($json -cmatch '[^\x20-\x7E]') {
    $json = -join $(foreach ($c in $json.ToCharArray()) { $n = [int]$c; if ($n -lt 32 -or $n -gt 126) { '\u{0:x4}' -f $n } else { $c } })
  }
  'ITRIAGE-JSON ' + $json
}
"#;

/// [`run`], handing the script values through environment variables. That's
/// the only way data reaches a script: it reads `$env:NAME` as text, so a
/// value can never become part of the script, whatever it contains.
pub fn run_with(
    script: &'static str,
    values: &[(&str, &str)],
    ctx: &RunContext,
    timeout: Duration,
) -> Result<CmdOutput, String> {
    let script = format!("{PRELUDE}{script}");
    let mut c = cmd("powershell.exe");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
        .arg(utf16le_base64(&script));
    for (name, value) in values {
        c.env(name, value);
    }
    let readable = |line: &str| {
        let t = line.trim_start();
        if t.starts_with(ROWS_MARKER.trim_end()) || t.starts_with(JSON_MARKER.trim_end()) || t.starts_with("#< CLIXML") {
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

/// Every script ITriage can run, by name. A script is only ever one of these
/// constants; listing them here lets a test check that each one parses.
#[cfg(test)]
pub(crate) fn all_scripts() -> Vec<(&'static str, &'static str)> {
    use crate::fixes::{maintenance, netrepair};
    vec![
        ("NIC_POWER_READ", netrepair::NIC_POWER_READ),
        ("NIC_POWER_OFF", netrepair::NIC_POWER_OFF),
        ("RESTART_ADAPTERS", netrepair::RESTART_ADAPTERS),
        ("PHYSICAL_UP", netrepair::PHYSICAL_UP),
        ("SCCM_TRIGGERS", maintenance::SCCM_TRIGGERS),
        ("BITLOCKER_STATUS", crate::bitlocker::STATUS),
        ("BITLOCKER_SUSPEND", crate::bitlocker::SUSPEND),
        ("POSTURE", crate::security::posture::POSTURE),
        ("RELIABILITY", crate::triage::reliability::RELIABILITY),
        ("STORED_PASSWORD_TASKS", crate::desk::account::STORED_PASSWORD_TASKS),
        ("TUNING_READ", crate::fixes::undo::TUNING_READ),
        ("ADAPTERS_RESTORE", crate::fixes::undo::ADAPTERS_RESTORE),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accents, another script, an emoji (two UTF-16 units) and a control
    /// character, built from code points so this file stays ASCII.
    const NON_ASCII: &str = r#"
$name = 'caf' + [char]233 + ' ' + [char]0x4E2D + ' ' + [char]0xD83D + [char]0xDE00 + [char]9 + 'end'
Send-ITriage ([ordered]@{ Name = $name; Plain = 'ascii only'; List = @('a', ('b' + [char]252)) })
"#;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Sent {
        name: String,
        plain: String,
        list: Vec<String>,
    }

    #[test]
    fn results_survive_the_pipe_whatever_they_contain() {
        let out = run(NON_ASCII, &RunContext::silent(), Duration::from_secs(60)).unwrap();
        let line = out.stdout.lines().find(|l| l.starts_with(JSON_MARKER.trim_end())).expect("a result line");
        assert!(line.is_ascii(), "everything else is escaped: {line}");
        let sent: Sent = crate::fixes::json(&out.stdout).unwrap();
        assert_eq!(sent.name, "caf\u{e9} \u{4e2d} \u{1f600}\tend");
        assert_eq!(sent.plain, "ascii only");
        assert_eq!(sent.list, ["a", "b\u{fc}"]);
    }

    /// Most of these scripts only run on a domain PC, a laptop or with a
    /// vendor tool installed, none of which CI has. Parsing them here still
    /// catches a typo before a technician does. Nothing is executed.
    #[test]
    fn every_script_parses() {
        let dir = std::env::temp_dir().join(format!("itriage-ps-parse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, script) in all_scripts() {
            let file = dir.join(format!("{name}.ps1"));
            std::fs::write(&file, format!("{PRELUDE}{script}")).unwrap();
            let check = format!(
                "$errors = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$errors); \
                 if ($errors -and $errors.Count -gt 0) {{ $errors | ForEach-Object {{ $_.ToString() }}; exit 1 }}",
                file.display()
            );
            let mut c = cmd("powershell.exe");
            c.args(["-NoProfile", "-NonInteractive", "-Command", &check]);
            let out = crate::util::capture(c).unwrap();
            assert!(out.success(), "{name} doesn't parse: {}", out.combined());
            assert!(script.contains("ITRIAGE-") || script.contains("Send-ITriage"), "{name} reports through a marker line");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
