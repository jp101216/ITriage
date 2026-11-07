//! winget (Windows Package Manager) helpers.

use crate::module::RunContext;
use crate::parse::winget::{parse_upgrade_table, tally_upgrade, UpgradeTally, WingetRow};
use crate::util::{capture, cmd, command_exists, stream};
use std::time::Duration;

pub fn available() -> bool {
    command_exists("winget")
}

/// Apps with an upgrade available. Read-only.
///
/// `--accept-source-agreements` matters even for listing: on a fresh machine
/// winget otherwise stops to ask about the msstore source terms, and with no
/// stdin it just fails.
pub fn pending() -> Result<Vec<WingetRow>, String> {
    let mut c = cmd("winget");
    c.args(["upgrade", "--accept-source-agreements", "--disable-interactivity"]);
    let out = capture(c)?;
    // winget exits non-zero when nothing needs upgrading; the table is the signal.
    Ok(parse_upgrade_table(&out.stdout))
}

pub struct UpgradeRun {
    pub tally: UpgradeTally,
    pub code: Option<i32>,
}

/// `winget upgrade --all`, silently, streaming progress to the UI.
pub fn upgrade_all(ctx: &RunContext) -> Result<UpgradeRun, String> {
    let mut c = cmd("winget");
    c.args([
        "upgrade",
        "--all",
        "--silent",
        "--accept-source-agreements",
        "--accept-package-agreements",
        "--disable-interactivity",
    ]);
    let out = stream(c, ctx, Duration::from_secs(90 * 60))?;
    Ok(UpgradeRun {
        tally: tally_upgrade(&out.stdout),
        code: out.code,
    })
}
