//! Modules that change the machine: the Endpoint Tune-Up's network repair
//! steps (`dns`, `netrepair`) and its cleanup and maintenance steps (`temp`,
//! `maintenance`).
//!
//! Every built-in tool's exit code is checked, the way the Tune-Up checks
//! `$LASTEXITCODE` instead of assuming "done": a failing `netsh` is a failed
//! step, not a success. Two tools only warn on a non-zero exit, as in the
//! Tune-Up: `nbtstat` (NetBIOS is off on many machines) and DHCP
//! release/renew (static adapters report errors while the rest renew).

pub mod dns;
pub mod maintenance;
pub mod netrepair;
pub mod temp;
pub mod undo;
pub mod usbpower;

use crate::model::{Finding, Severity};
use crate::module::RunContext;
use crate::parse::text::{collapse_whitespace, truncate_chars};
use crate::util::{cmd, exit_label, stream};
use serde::Deserialize;
use std::time::Duration;

/// How a step treats a non-zero exit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    Fail,
    Warn,
}

/// One step's outcome.
pub struct Step {
    pub finding: Finding,
    pub ok: bool,
    pub code: Option<i32>,
}

/// Run a built-in tool as one step: stream its output to the log, then
/// grade its exit code. `ok_codes` are the exits that mean success (DISM's
/// 3010 is "done, restart needed").
pub fn step(
    ctx: &RunContext,
    label: &str,
    program: &str,
    args: &[&str],
    ok_codes: &[i32],
    on_error: OnError,
    timeout: Duration,
) -> Step {
    ctx.log(format!("› {program} {}", args.join(" ")));
    let mut c = cmd(program);
    c.args(args);
    match stream(c, ctx, timeout) {
        Ok(out) if out.code.is_some_and(|c| ok_codes.contains(&c)) => Step {
            finding: Finding::ok(label, last_line(&out.stdout).unwrap_or_else(|| "done".into())),
            ok: true,
            code: out.code,
        },
        Ok(out) => {
            let said = last_line(&out.stdout).map(|l| format!(": {l}")).unwrap_or_default();
            let severity = if on_error == OnError::Warn { Severity::Warning } else { Severity::Critical };
            Step {
                finding: Finding::new(label, format!("{}{said}", exit_label(out.code)), severity),
                ok: on_error == OnError::Warn,
                code: out.code,
            }
        }
        Err(e) => Step {
            finding: Finding::new(
                label,
                e,
                if on_error == OnError::Warn { Severity::Warning } else { Severity::Critical },
            ),
            ok: false,
            code: None,
        },
    }
}

/// The last meaningful line a tool printed, shortened.
fn last_line(out: &str) -> Option<String> {
    out.lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty() && l.chars().any(char::is_alphanumeric))
        .map(|l| truncate_chars(&collapse_whitespace(l), 160))
}

/// One row the fixed PowerShell scripts report: an adapter, a schedule…
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Row {
    #[serde(rename = "Item")]
    pub item: String,
    /// Changed, Already, Skipped or Failed.
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Detail", default)]
    pub detail: String,
}

/// The marker the scripts print their JSON after.
pub const ROWS_MARKER: &str = "ITRIAGE-ROWS ";

/// Pull the rows out of a script's output.
pub fn rows(out: &str) -> Option<Vec<Row>> {
    let json = out.lines().rev().find_map(|l| l.trim().strip_prefix(ROWS_MARKER))?;
    serde_json::from_str(json).ok()
}

/// The marker the scripts print a richer JSON result after (see
/// `Send-ITriage` in [`crate::win::ps`]).
pub const JSON_MARKER: &str = "ITRIAGE-JSON ";

/// Pull a script's JSON result out of its output. The error says whether
/// the script printed nothing or printed something unexpected.
pub fn json<T: serde::de::DeserializeOwned>(out: &str) -> Result<T, String> {
    let text = out
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix(JSON_MARKER))
        .ok_or("PowerShell gave no result")?;
    serde_json::from_str(text).map_err(|e| format!("PowerShell's result wasn't in the expected form ({e})"))
}

impl Row {
    pub fn finding(&self) -> Finding {
        let severity = match self.status.as_str() {
            "Changed" | "Already" => Severity::Ok,
            "Skipped" => Severity::Info,
            _ => Severity::Critical,
        };
        Finding::new(self.item.clone(), self.detail.clone(), severity)
    }
}

/// Findings plus a one-line tally for a list of steps.
pub fn tally(findings: &[Finding]) -> (usize, usize) {
    let failed = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    (findings.len() - failed, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_script_rows() {
        let out = "WARNING: something chatty\nITRIAGE-ROWS [{\"Item\":\"Ethernet\",\"Status\":\"Changed\",\"Detail\":\"turned off\"},{\"Item\":\"Wi-Fi\",\"Status\":\"Failed\",\"Detail\":\"Access denied\"}]\n";
        let rows = rows(out).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].finding().severity, Severity::Ok);
        assert_eq!(rows[1].finding().severity, Severity::Critical);
        assert_eq!(super::rows("ITRIAGE-ROWS []").unwrap(), vec![]);
        assert!(super::rows("no marker here").is_none());
    }

    #[test]
    fn reads_a_scripts_json_result() {
        #[derive(Deserialize, Debug, PartialEq)]
        struct Answer {
            #[serde(rename = "Name")]
            name: String,
        }
        let out = "chatter\nITRIAGE-JSON {\"Name\":\"caf\\u00e9\"}\n";
        assert_eq!(json::<Answer>(out).unwrap(), Answer { name: "café".into() });
        assert!(json::<Answer>("nothing").unwrap_err().contains("no result"));
        assert!(json::<Answer>("ITRIAGE-JSON [1,2]").unwrap_err().contains("expected form"));
    }

    #[cfg(unix)]
    #[test]
    fn steps_grade_exit_codes() {
        let ctx = RunContext::silent();
        let ok = step(&ctx, "True", "sh", &["-c", "echo first; echo all good"], &[0], OnError::Fail, Duration::from_secs(10));
        assert!(ok.ok);
        assert_eq!(ok.finding.value, "all good");
        // DISM's 3010 ("done, restart needed") stands in as 3 here: Unix
        // exit codes stop at 255.
        let restart = step(&ctx, "DISM", "sh", &["-c", "exit 3"], &[0, 3], OnError::Fail, Duration::from_secs(10));
        assert!(restart.ok && restart.code == Some(3));
        let fail = step(&ctx, "netsh", "sh", &["-c", "echo The requested operation requires elevation.; exit 1"], &[0], OnError::Fail, Duration::from_secs(10));
        assert_eq!(fail.finding.severity, Severity::Critical);
        assert_eq!(fail.finding.value, "exit 1: The requested operation requires elevation.");
        let warn = step(&ctx, "nbtstat", "sh", &["-c", "exit 1"], &[0], OnError::Warn, Duration::from_secs(10));
        assert!(warn.ok && warn.finding.severity == Severity::Warning);
        let missing = step(&ctx, "x", "definitely-not-a-tool", &[], &[0], OnError::Fail, Duration::from_secs(10));
        assert!(!missing.ok);
    }
}
