//! Install drivers, BIOS and firmware. MUTATING, needs admin.
//!
//! Invoke-UpdateSystem's flow: report the machine's identity and current
//! BIOS, check power, route BIOS/firmware to the manufacturer's tool, and
//! install driver and firmware updates from Windows Update.
//!
//! * The manufacturer's tool runs when it's installed (Dell Command | Update,
//!   HP Image Assistant, Lenovo Thin Installer), since that's the only
//!   supported route for BIOS updates on business machines. When it isn't,
//!   the result offers to install it with winget. Other makers get pointed at
//!   their own tool; itriage never flashes a BIOS itself.
//! * Windows Update drivers install when no OEM tool ran, so the two don't
//!   keep replacing each other's drivers ("driver ping-pong"). A site
//!   profile can set `updates.windows_update_drivers = "always"` to install
//!   them after the OEM tool too, as the script does.
//! * On battery, nothing runs: a BIOS flash that loses power can brick a
//!   board. Plug in and run it again.
//! * Before the manufacturer's tool runs, BitLocker is suspended for one
//!   restart (see [`crate::bitlocker`]), so a BIOS update doesn't leave the
//!   PC asking for its recovery key. If protection is on and can't be
//!   suspended, nothing is installed. A site profile can turn this off.
//! * The tool is only started from a folder standard users can't write to
//!   (see [`crate::trust`]), and its working folder is made fresh and locked
//!   to administrators for each run.
//!
//! Linux: fwupd (LVFS), behind the same power check.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};

pub struct InstallFirmware;

impl TriageModule for InstallFirmware {
    fn info(&self) -> ModuleInfo {
        let (description, warning) = if cfg!(windows) {
            (
                "Drivers, BIOS and firmware through the manufacturer's tool (Dell, HP, Lenovo), and Windows Update drivers. Won't run on battery.",
                "May flash BIOS/firmware. Keep laptops on AC power and don't power off until it finishes. A restart is usually needed; BitLocker may ask for its recovery key if it isn't suspended first.",
            )
        } else {
            (
                "Firmware updates from LVFS through fwupd (UEFI, SSDs, docks, peripherals). Won't run on battery.",
                "May flash firmware. Keep laptops on AC power. UEFI updates are staged and apply on the next reboot.",
            )
        };
        ModuleInfo::new("update.firmware", "Install drivers & firmware", Category::Updates, description)
            .mutating()
            .admin()
            .warning(warning)
    }

    fn preview(&self, ctx: &RunContext) -> Result<Output, String> {
        let mut findings = identity_findings();
        let power = power_finding();
        let on_battery = power.severity == Severity::Warning;
        findings.push(power);
        findings.extend(imp::plan(ctx));
        let summary = if on_battery {
            "Preview: would stop, because it's on battery. Nothing was changed."
        } else {
            "Preview: nothing was installed."
        };
        Ok(Output::new(summary, findings))
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let mut findings = identity_findings();
        let power = power_finding();
        if power.severity == Severity::Warning {
            findings.push(power);
            return Ok(Output::new("Not started: on battery. Plug in AC power, then run it again", findings));
        }
        findings.push(power);
        imp::install(ctx, findings)
    }
}

/// The machine and its current BIOS, as Invoke-UpdateSystem opens with.
fn identity_findings() -> Vec<Finding> {
    let id = crate::host::identity();
    let mut out = Vec::new();
    if let Some(m) = id.make_and_model() {
        out.push(Finding::info("Model", m));
    }
    out.push(Finding::info("Current BIOS", id.bios().unwrap_or_else(|| "not reported".into())));
    if let Some(board) = id.motherboard() {
        out.push(Finding::info("Motherboard", board));
    }
    out
}

/// The AC power gate. Warning = on battery (stop).
fn power_finding() -> Finding {
    match crate::host::on_ac_power() {
        Some(true) => Finding::ok("Power", "on AC power"),
        Some(false) => Finding::warn("Power", "on battery: plug in AC power before any BIOS or firmware update")
            .with_detail("A flash that loses power part-way can leave the machine unable to start."),
        None => Finding::info("Power", "couldn't tell: keep it plugged in until this finishes"),
    }
}

/// "Restart required" with the Restart in 60 s button.
pub(crate) fn restart_finding(restart: bool) -> Finding {
    if restart {
        Finding::warn("Restart required", "yes").with_action(crate::actions::offer("restart-computer", None))
    } else {
        Finding::ok("Restart required", "no")
    }
}

/// For a tool that doesn't report it (Lenovo Thin Installer run with
/// `-noreboot`): say so, instead of a confident "no".
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn restart_unknown_finding() -> Finding {
    Finding::warn("Restart required", "can't tell: the tool doesn't report it")
        .with_detail("If it installed a BIOS, firmware or driver update, a restart finishes it. Its log lists what it installed.")
        .with_action(crate::actions::offer("restart-computer", None))
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::profile::DriverSource;
    use crate::update::oem::{self, ToolState, Via};
    use crate::util::{cmd, exit_label, plural, require_admin, stream};
    use crate::win::wua::{self, Kind};
    use std::time::Duration;

    /// What the routing says, as findings (shared by preview and install).
    fn route_findings(state_label: bool) -> (Vec<Finding>, Option<(&'static oem::Route, ToolState)>) {
        let id = crate::host::identity();
        let mut out = Vec::new();
        let Some((route, field)) = oem::route(id) else {
            let board = id.motherboard().unwrap_or_else(|| "this board".into());
            out.push(Finding::info(
                "OEM tool",
                format!("manufacturer not recognised for BIOS routing: update the BIOS from the board maker's support page for {board}"),
            ));
            return (out, None);
        };
        let state = route.state();
        let mut f = match (&route.via, &state) {
            (Via::Runner(tool), ToolState::Ready(path)) => Finding::ok(
                format!("OEM tool ({})", route.name),
                format!("{} is installed{}", tool.tool, if state_label { " and will run" } else { "" }),
            )
            .with_detail(path.display().to_string()),
            (Via::Runner(_), ToolState::Installed(name)) => {
                Finding::info(format!("OEM tool ({})", route.name), format!("{name} is installed: open it to review and apply BIOS and firmware updates"))
            }
            (Via::Runner(tool), ToolState::Untrusted(path, why)) => Finding::warn(
                format!("OEM tool ({})", route.name),
                format!("{} is installed, but ITriage won't run it as an administrator from where it is", tool.tool),
            )
            .with_detail(format!(
                "{}: {why}. A program there could have been swapped by anyone signed in. Move it under C:\\Program Files \
                 (or have the folder's permissions limited to administrators) and run this again",
                path.display()
            )),
            (Via::Runner(tool), ToolState::Missing) => {
                let mut f = Finding::info(format!("OEM tool ({})", route.name), format!("not installed ({})", tool.get_it));
                if let Some(id) = route.winget_id {
                    f = f.with_action(crate::actions::offer("install-oem-tool", Some(id)));
                }
                f
            }
            (Via::WindowsUpdate, _) => Finding::info(format!("OEM tool ({})", route.name), "firmware comes through Windows Update"),
            (Via::Manual, _) => Finding::info(
                format!("OEM tool ({})", route.name),
                format!(
                    "no unattended tool: get \"{}\" from the Microsoft Store or the vendor's support site, and let it do the flash",
                    route.search_name
                ),
            ),
        };
        let mut notes = vec![format!("matched on the {field}")];
        notes.extend(route.note.map(str::to_string));
        let detail = match &f.detail {
            Some(d) => format!("{d} · {}", notes.join(" · ")),
            None => notes.join(" · "),
        };
        f = f.with_detail(detail);
        out.push(f);
        (out, Some((route, state)))
    }

    pub fn plan(ctx: &RunContext) -> Vec<Finding> {
        let (mut findings, route) = route_findings(true);
        let oem_runs = matches!(&route, Some((r, ToolState::Ready(_))) if matches!(r.via, Via::Runner(_)));
        if let Some((oem::Route { via: Via::Runner(tool), .. }, ToolState::Ready(path))) = &route {
            if ctx.profile().updates.suspend_bitlocker {
                ctx.log("Checking BitLocker…");
                let (drive, state) = crate::bitlocker::status(ctx);
                findings.push(crate::bitlocker::would_suspend(&drive, &state));
            } else {
                findings.push(Finding::info("BitLocker", "left as it is (the site profile turns suspending off)"));
            }
            // A real run makes a fresh, locked-down folder; this stands in for it.
            let work = crate::win::dirs::program_data().join("itriage").join("work-…");
            findings.push(Finding::info(
                "Would run",
                format!("{} {}", path.display(), tool.args(&work).join(" ")),
            ));
        }
        let wu = !oem_runs || ctx.profile().updates.windows_update_drivers == DriverSource::Always;
        if wu {
            ctx.log("Checking Windows Update for drivers…");
            match wua::pending(Kind::Driver) {
                Ok(list) if list.is_empty() => findings.push(Finding::info("Would install", "no Windows Update drivers offered")),
                Ok(list) => {
                    for p in list {
                        findings.push(Finding::info("Would install", p.title));
                    }
                }
                Err(e) => findings.push(Finding::warn("Windows Update drivers", e)),
            }
        } else {
            findings.push(Finding::info("Windows Update drivers", "skipped: the OEM tool handles drivers"));
        }
        findings
    }

    pub fn install(ctx: &RunContext, mut findings: Vec<Finding>) -> Result<Output, String> {
        require_admin()?;
        let (route_rows, route) = route_findings(false);
        findings.extend(route_rows);
        let mut restart = false;
        let mut summary_parts = Vec::new();

        // --- The OEM tool, when there is one ---
        let mut oem_ran = false;
        let mut restart_unknown = false;
        if let Some((oem::Route { via: Via::Runner(tool), name, .. }, ToolState::Ready(path))) = &route {
            // --- BitLocker first: a firmware change with protection on
            //     means a recovery-key prompt at the next start-up ---
            if ctx.profile().updates.suspend_bitlocker {
                ctx.log("Checking BitLocker before any firmware update…");
                let suspended = crate::bitlocker::suspend(ctx);
                let safe = suspended.safe_to_flash;
                findings.push(suspended.finding);
                if !safe {
                    findings.push(restart_finding(false));
                    return Ok(Output::new("Not started: BitLocker is on and couldn't be suspended", findings));
                }
            }
            ctx.log(format!("Running {}…", tool.tool));
            let work = oem::work_dir()?;
            let pending_before = crate::host::pending_restart().unwrap_or_default();
            let mut c = cmd(path);
            c.args(tool.args(&work));
            let out = stream(c, ctx, Duration::from_secs(2 * 3600))?;
            let (severity, meaning) = tool.meaning(out.code);
            // The tool's exit code, or Windows itself now saying a restart
            // is pending when it wasn't before the tool ran.
            let newly_pending = crate::host::pending_restart()
                .unwrap_or_default()
                .into_iter()
                .any(|reason| !pending_before.contains(&reason));
            let tool_restart = tool.needs_restart(out.code) || newly_pending;
            restart |= tool_restart;
            restart_unknown = tool.restart_unreported && !tool_restart && out.code == Some(0);
            findings.push(
                Finding::new(tool.tool, format!("{meaning} ({})", exit_label(out.code)), severity)
                    .with_detail(format!("Logs and reports: {} (administrators only)", work.display())),
            );
            summary_parts.push(format!("{name}: {meaning}"));
            oem_ran = true;
        }

        // --- Windows Update drivers ---
        let always = ctx.profile().updates.windows_update_drivers == DriverSource::Always;
        if (!oem_ran || always) && !ctx.cancelled() {
            // WU offers most drivers as "optional", so include those: picking
            // this module is the explicit opt-in.
            ctx.log("Installing driver updates from Windows Update…");
            match wua::install(Kind::Driver, true, ctx) {
                Ok(report) => {
                    restart |= report.reboot_required;
                    let ok = report.results.iter().filter(|(_, o)| o.succeeded()).count();
                    let failed = report.results.len() - ok;
                    findings.push(Finding::new(
                        "Windows Update drivers",
                        if report.results.is_empty() { "none offered".to_string() } else { format!("{ok} installed, {failed} failed") },
                        if failed > 0 { Severity::Warning } else { Severity::Ok },
                    ));
                    for (p, outcome) in &report.results {
                        findings.push(Finding::new(
                            p.title.clone(),
                            outcome.label(),
                            if outcome.succeeded() { Severity::Ok } else { Severity::Critical },
                        ));
                    }
                    if ok > 0 {
                        summary_parts.push(format!("installed {ok} driver update{}", plural(ok)));
                    } else if report.results.is_empty() && !oem_ran {
                        summary_parts.push("no driver updates offered".into());
                    }
                }
                Err(e) => findings.push(Finding::crit("Windows Update drivers", e)),
            }
        } else if oem_ran {
            findings.push(Finding::info("Windows Update drivers", "skipped: the OEM tool handles drivers"));
        }

        if restart_unknown && !restart {
            findings.push(restart_unknown_finding());
        } else {
            findings.push(restart_finding(restart));
        }
        let mut summary = if summary_parts.is_empty() { "Nothing to install".to_string() } else { summary_parts.join("; ") };
        if restart {
            summary.push_str("; restart required");
        } else if restart_unknown {
            summary.push_str("; restart if BIOS or firmware was installed");
        }
        Ok(Output::new(crate::triage::network::capitalize(&summary), findings).restart_required(restart))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::util::{command_exists, exit_label, pkexec_error, privileged_shell, stream};
    use std::time::Duration;

    /// fwupdmgr exits 2 when there's nothing to do.
    const NOTHING_TO_DO: i32 = 2;

    pub fn plan(_ctx: &RunContext) -> Vec<Finding> {
        if command_exists("fwupdmgr") {
            vec![Finding::info("Would run", "fwupdmgr refresh --force; fwupdmgr update --assume-yes --no-reboot-check")]
        } else {
            vec![Finding::warn("fwupd", "not installed, so there's nothing to run")]
        }
    }

    pub fn install(ctx: &RunContext, mut findings: Vec<Finding>) -> Result<Output, String> {
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

        let (value, severity, summary, restart) = match out.code {
            Some(0) => (
                "updated; some devices finish on the next reboot".to_string(),
                Severity::Warning,
                "Firmware updated; reboot to finish",
                true,
            ),
            Some(NOTHING_TO_DO) => ("no firmware updates available".to_string(), Severity::Ok, "Firmware is current", false),
            other => (format!("failed ({})", exit_label(other)), Severity::Critical, "Firmware update failed", false),
        };
        findings.push(Finding::new("fwupd", value, severity));
        if restart {
            findings.push(restart_finding(true));
        }
        Ok(Output::new(summary, findings).restart_required(restart))
    }
}
