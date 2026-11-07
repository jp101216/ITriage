//! Available-updates scan. READ-ONLY: it lists what's pending and installs
//! nothing. Installing is done by the two separate (mutating) modules.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};

pub struct AvailableUpdates;

impl TriageModule for AvailableUpdates {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Pending Windows Update patches, winget app upgrades, restart state, and the OEM driver/BIOS tool. Installs nothing."
        } else {
            "Pending package and firmware updates, and whether a reboot is required. Installs nothing."
        };
        ModuleInfo::new("update.scan", "Available updates", Category::Updates, description)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::scan(ctx)
    }
}

/// "3 Windows updates · 5 app upgrades · restart pending", capitalised.
fn summarize(parts: &[String]) -> String {
    if parts.is_empty() {
        return "Everything is up to date.".to_string();
    }
    let joined = parts.join(" · ");
    let mut chars = joined.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => joined,
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::update::{oem, winget, LIST_MAX};
    use crate::util::plural;
    use crate::win::wua::{self, Kind};

    pub fn scan(ctx: &RunContext) -> Result<Output, String> {
        let mut findings = Vec::new();
        let mut parts = Vec::new();

        // --- Windows Update (OS patches) ---
        ctx.log("Searching Windows Update…");
        match wua::pending(Kind::Software) {
            Ok(list) => {
                let (important, optional): (Vec<_>, Vec<_>) = list.into_iter().partition(|p| !p.optional);
                findings.push(Finding::new(
                    "Windows Update",
                    format!("{} important · {} optional", important.len(), optional.len()),
                    if important.is_empty() { Severity::Ok } else { Severity::Warning },
                ));
                for p in important.iter().take(LIST_MAX) {
                    let severity = match p.msrc.as_deref() {
                        Some("Critical") => Severity::Critical,
                        Some("Important") => Severity::Warning,
                        _ => Severity::Info,
                    };
                    let mut f = Finding::new(p.label(), p.title.clone(), severity);
                    if let Some(m) = &p.msrc {
                        f = f.with_detail(format!("MSRC severity: {m}"));
                    }
                    findings.push(f);
                }
                if !important.is_empty() {
                    parts.push(format!("{} Windows update{}", important.len(), plural(important.len())));
                }
            }
            Err(e) => findings.push(Finding::warn("Windows Update", e)),
        }

        // --- Restart state ---
        match wua::reboot_pending() {
            Some(true) => {
                findings.push(Finding::warn("Restart pending", "yes; restart to finish earlier updates"));
                parts.push("restart pending".into());
            }
            Some(false) => findings.push(Finding::ok("Restart pending", "no")),
            None => {}
        }

        // --- Apps via winget ---
        if winget::available() {
            ctx.log("Checking winget for app upgrades…");
            match winget::pending() {
                Ok(rows) => {
                    findings.push(Finding::new(
                        "winget apps",
                        format!("{} upgradable", rows.len()),
                        if rows.is_empty() { Severity::Ok } else { Severity::Warning },
                    ));
                    for r in rows.iter().take(LIST_MAX) {
                        findings.push(Finding::info(
                            format!("{} ({})", r.name, r.id),
                            format!("{} → {}", r.version, r.available),
                        ));
                    }
                    if rows.len() > LIST_MAX {
                        findings.push(Finding::info("More apps", format!("{} more", rows.len() - LIST_MAX)));
                    }
                    if !rows.is_empty() {
                        parts.push(format!("{} app upgrade{}", rows.len(), plural(rows.len())));
                    }
                }
                Err(e) => findings.push(Finding::warn("winget apps", e)),
            }
        } else {
            findings.push(Finding::warn(
                "winget apps",
                "winget not found; install App Installer from the Microsoft Store",
            ));
        }

        // --- Drivers / BIOS: which tool will handle them ---
        let maker = crate::host::system_manufacturer();
        let label = match &maker {
            Some(m) => format!("Driver/BIOS tool ({m})"),
            None => "Driver/BIOS tool".to_string(),
        };
        let finding = match maker.as_deref().and_then(oem::for_manufacturer) {
            Some(tool) if tool.locate().is_some() => Finding::ok(label, format!("{} is installed", tool.tool)),
            Some(tool) => Finding::info(label, format!("{} isn't installed; {}", tool.tool, tool.get_it)),
            None => Finding::info(label, "no OEM tool for this make; driver installs will use Windows Update"),
        };
        findings.push(finding);

        Ok(Output::new(summarize(&parts), findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::pkg::fwupd_updates;
    use crate::update::pkgmgr::{reboot_required, PkgMgr};
    use crate::update::LIST_MAX;
    use crate::util::{capture, cmd, command_exists, plural};

    pub fn scan(ctx: &RunContext) -> Result<Output, String> {
        let mut findings = Vec::new();
        let mut parts = Vec::new();

        // --- Packages ---
        match PkgMgr::detect() {
            Some(pm) => {
                ctx.log(format!("Checking {} for upgrades…", pm.name()));
                match pm.pending() {
                    Ok(list) => {
                        let mut head = Finding::new(
                            format!("{} packages", pm.name()),
                            format!("{} upgradable", list.len()),
                            if list.is_empty() { Severity::Ok } else { Severity::Warning },
                        );
                        if let Some(note) = pm.scan_note() {
                            head = head.with_detail(note);
                        }
                        findings.push(head);
                        for u in list.iter().take(LIST_MAX) {
                            findings.push(Finding::info(u.name.clone(), u.change()));
                        }
                        if list.len() > LIST_MAX {
                            findings.push(Finding::info("More packages", format!("{} more", list.len() - LIST_MAX)));
                        }
                        if !list.is_empty() {
                            parts.push(format!("{} package upgrade{}", list.len(), plural(list.len())));
                        }
                    }
                    Err(e) => findings.push(Finding::warn(format!("{} packages", pm.name()), e)),
                }
            }
            None => findings.push(Finding::warn(
                "Packages",
                "no supported package manager found (apt, dnf, pacman, zypper)",
            )),
        }

        // --- Firmware via fwupd (LVFS) ---
        if command_exists("fwupdmgr") {
            ctx.log("Checking fwupd for firmware updates…");
            let mut c = cmd("fwupdmgr");
            c.args(["get-updates", "--json"]).env("LC_ALL", "C");
            match capture(c) {
                Ok(out) => {
                    let ups = fwupd_updates(&out.stdout);
                    findings.push(Finding::new(
                        "Firmware (fwupd)",
                        if ups.is_empty() { "no updates reported".to_string() } else { format!("{} device update{}", ups.len(), plural(ups.len())) },
                        if ups.is_empty() { Severity::Ok } else { Severity::Warning },
                    ));
                    for u in &ups {
                        findings.push(Finding::info(u.name.clone(), u.change()));
                    }
                    if !ups.is_empty() {
                        parts.push(format!("{} firmware update{}", ups.len(), plural(ups.len())));
                    }
                }
                Err(e) => findings.push(Finding::warn("Firmware (fwupd)", e)),
            }
        } else {
            findings.push(Finding::info(
                "Firmware (fwupd)",
                "fwupd not installed; firmware updates aren't checked",
            ));
        }

        // --- Reboot state ---
        if let Some(why) = reboot_required() {
            findings.push(Finding::warn("Reboot required", "yes").with_detail(why));
            parts.push("reboot required".into());
        }

        Ok(Output::new(summarize(&parts), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::summarize;

    #[test]
    fn summaries_read_naturally() {
        assert_eq!(summarize(&[]), "Everything is up to date.");
        assert_eq!(
            summarize(&["3 package upgrades".into(), "reboot required".into()]),
            "3 package upgrades · reboot required"
        );
        assert_eq!(summarize(&["restart pending".into()]), "Restart pending");
    }
}
