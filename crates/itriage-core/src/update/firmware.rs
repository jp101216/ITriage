//! Install drivers, BIOS and firmware. MUTATING, needs admin.
//!
//! Windows: the manufacturer's own tool when it's installed (Dell Command |
//! Update, HP Image Assistant, Lenovo Thin Installer), since that's the only
//! supported route for BIOS updates on business machines. Otherwise (custom
//! builds, Surface, or an OEM tool that isn't installed) driver updates come
//! from Windows Update. Running only one of the two avoids "driver ping-pong",
//! where one source replaces the other's driver on every pass.
//!
//! Linux: fwupd (LVFS).

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};

pub struct InstallFirmware;

impl TriageModule for InstallFirmware {
    fn info(&self) -> ModuleInfo {
        let (description, warning) = if cfg!(windows) {
            (
                "Drivers, BIOS and firmware through the OEM tool (Dell, HP, Lenovo), or Windows Update drivers when there isn't one.",
                "May flash BIOS/firmware. Keep laptops on AC power and don't power off until it finishes. A restart is usually needed; BitLocker may ask for its recovery key if it isn't suspended first.",
            )
        } else {
            (
                "Firmware updates from LVFS through fwupd (UEFI, SSDs, docks, peripherals).",
                "May flash firmware. Keep laptops on AC power. UEFI updates are staged and apply on the next reboot.",
            )
        };
        ModuleInfo::new(
            "update.firmware",
            "Install drivers & firmware",
            Category::Updates,
            description,
        )
        .mutating()
        .admin()
        .warning(warning)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::install(ctx)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::update::oem;
    use crate::util::{cmd, exit_label, plural, require_admin, stream};
    use crate::win::wua::{self, Kind};
    use std::time::Duration;

    pub fn install(ctx: &RunContext) -> Result<Output, String> {
        require_admin()?;
        let maker = crate::host::system_manufacturer().unwrap_or_else(|| "Unknown manufacturer".into());
        let mut findings = vec![Finding::info("Manufacturer", maker.clone())];

        // --- The OEM tool, when there is one ---
        if let Some(tool) = oem::for_manufacturer(&maker) {
            match tool.locate() {
                Some(path) => {
                    ctx.log(format!("{maker} detected; running {}", tool.tool));
                    let work = oem::work_dir()?;
                    let mut c = cmd(&path);
                    c.args(tool.args(&work));
                    let out = stream(c, ctx, Duration::from_secs(2 * 3600))?;
                    let (severity, meaning) = tool.meaning(out.code);
                    findings.push(
                        Finding::new(tool.tool, format!("{meaning} ({})", exit_label(out.code)), severity)
                            .with_detail(format!("Logs and reports: {}", work.display())),
                    );
                    return Ok(Output::new(format!("{}: {meaning}", tool.tool), findings));
                }
                None => findings.push(Finding::info(
                    tool.tool,
                    format!("not installed; using Windows Update drivers instead ({})", tool.get_it),
                )),
            }
        }

        // --- Otherwise: driver updates from Windows Update ---
        // WU offers most drivers as "optional", so include those: picking this
        // module is the explicit opt-in.
        ctx.log("Installing driver updates from Windows Update…");
        let report = wua::install(Kind::Driver, true, ctx)?;
        let ok = report.results.iter().filter(|(_, o)| o.succeeded()).count();
        let failed = report.results.len() - ok;
        findings.push(Finding::new(
            "Windows Update drivers",
            if report.results.is_empty() {
                "none offered".to_string()
            } else {
                format!("{ok} installed, {failed} failed")
            },
            if failed > 0 { Severity::Warning } else { Severity::Ok },
        ));
        for (p, outcome) in &report.results {
            findings.push(Finding::new(
                p.title.clone(),
                outcome.label(),
                if outcome.succeeded() { Severity::Ok } else { Severity::Critical },
            ));
        }
        if report.reboot_required {
            findings.push(Finding::warn("Restart required", "yes"));
        }

        let mut summary = if report.results.is_empty() {
            "No driver updates offered".to_string()
        } else {
            format!("Installed {ok} driver update{}", plural(ok))
        };
        if report.reboot_required {
            summary.push_str("; restart required");
        }
        Ok(Output::new(summary, findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::util::{command_exists, exit_label, pkexec_error, privileged_shell, stream};
    use std::time::Duration;

    /// fwupdmgr exits 2 when there's nothing to do.
    const NOTHING_TO_DO: i32 = 2;

    pub fn install(ctx: &RunContext) -> Result<Output, String> {
        if !command_exists("fwupdmgr") {
            return Err("fwupd isn't installed (no fwupdmgr). Install the fwupd package to get firmware updates from LVFS.".into());
        }
        let (command, via_pkexec) =
            privileged_shell("fwupdmgr refresh --force; fwupdmgr update --assume-yes --no-reboot-check")?;
        if via_pkexec {
            ctx.log("Asking for your password (pkexec)…");
        }
        ctx.log("Refreshing LVFS metadata and installing firmware…");
        let out = stream(command, ctx, Duration::from_secs(2 * 3600))?;
        if via_pkexec {
            if let Some(why) = pkexec_error(out.code) {
                return Err(why.to_string());
            }
        }

        let (value, severity, summary) = match out.code {
            Some(0) => (
                "updated; some devices finish on the next reboot".to_string(),
                Severity::Warning,
                "Firmware updated; reboot to finish",
            ),
            Some(NOTHING_TO_DO) => (
                "no firmware updates available".to_string(),
                Severity::Ok,
                "Firmware is current",
            ),
            other => (
                format!("failed ({})", exit_label(other)),
                Severity::Critical,
                "Firmware update failed",
            ),
        };
        Ok(Output::new(summary, vec![Finding::new("fwupd", value, severity)]))
    }
}
