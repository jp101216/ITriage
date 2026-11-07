//! Install OS & app updates. MUTATING, needs admin.
//!
//! Windows: Windows Update (software: security/quality, .NET, Defender) via
//! the WUA COM API, then `winget upgrade --all`. Optional/preview updates are
//! skipped. Linux: the package manager's full non-interactive upgrade, run as
//! root through pkexec.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};

pub struct InstallUpdates;

impl TriageModule for InstallUpdates {
    fn info(&self) -> ModuleInfo {
        let (description, warning) = if cfg!(windows) {
            (
                "Installs pending Windows Update patches (security & quality) and upgrades winget apps. Optional/preview updates are skipped.",
                "Installs every pending Windows update and app upgrade. This can take 30+ minutes, apps being upgraded may close, and a restart is usually needed afterwards.",
            )
        } else {
            (
                "Refreshes package lists and upgrades every package (apt, dnf, pacman or zypper).",
                "Upgrades every installed package non-interactively. Services may restart, and kernel updates need a reboot.",
            )
        };
        ModuleInfo::new("update.apply", "Install OS & app updates", Category::Updates, description)
            .mutating()
            .admin()
            .warning(warning)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::apply(ctx)
    }

    /// Lists what a real run would install, using the same searches the scan
    /// does. Needs no admin rights and changes nothing.
    fn preview(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::preview(ctx)
    }
}

/// "Preview: would install 3 Windows updates and 2 app upgrades. Nothing was changed."
fn preview_summary(parts: &[String]) -> String {
    if parts.is_empty() {
        "Preview: nothing to install. Nothing was changed.".to_string()
    } else {
        format!("Preview: would install {}. Nothing was changed.", parts.join(" and "))
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::update::{winget, LIST_MAX};
    use crate::util::{exit_label, plural, require_admin};
    use crate::win::wua::{self, Kind};

    pub fn apply(ctx: &RunContext) -> Result<Output, String> {
        require_admin()?;
        let mut findings = Vec::new();
        let mut installed = Vec::new();
        let mut restart = false;

        // --- 1. Windows Update ---
        match wua::install(Kind::Software, false, ctx) {
            Ok(report) => {
                restart |= report.reboot_required;
                let ok = report.results.iter().filter(|(_, o)| o.succeeded()).count();
                let skipped = report.results.iter().filter(|(_, o)| matches!(o, wua::Outcome::Skipped)).count();
                let failed = report.results.len() - ok - skipped;
                let mut value = if report.results.is_empty() {
                    "nothing to install".to_string()
                } else {
                    format!("{ok} installed, {failed} failed")
                };
                if skipped > 0 {
                    value.push_str(&format!(", {skipped} skipped"));
                }
                findings.push(Finding::new(
                    "Windows Update",
                    value,
                    if failed > 0 || skipped > 0 { Severity::Warning } else { Severity::Ok },
                ));
                for (p, outcome) in &report.results {
                    let severity = match outcome {
                        o if o.succeeded() => Severity::Ok,
                        wua::Outcome::Skipped => Severity::Info,
                        _ => Severity::Critical,
                    };
                    findings.push(Finding::new(p.label(), outcome.label(), severity).with_detail(p.title.clone()));
                }
                if ok > 0 {
                    installed.push(format!("{ok} Windows update{}", plural(ok)));
                }
            }
            Err(e) => findings.push(Finding::crit("Windows Update", e)),
        }

        // --- 2. Apps via winget ---
        if ctx.cancelled() {
            findings.push(Finding::info("winget apps", "skipped (run cancelled)"));
        } else if winget::available() {
            ctx.log("Upgrading apps with winget…");
            match winget::upgrade_all(ctx) {
                Ok(run) => {
                    let t = run.tally;
                    let clean = run.code == Some(0) || t.nothing_to_do;
                    let severity = if t.failed > 0 || !clean { Severity::Warning } else { Severity::Ok };
                    let value = if t.nothing_to_do {
                        "nothing to upgrade".to_string()
                    } else {
                        format!("{} upgraded, {} failed", t.upgraded, t.failed)
                    };
                    let mut f = Finding::new("winget apps", value, severity);
                    if severity != Severity::Ok {
                        f = f.with_detail(format!(
                            "winget finished with {}; the log shows which package failed",
                            exit_label(run.code)
                        ));
                    }
                    findings.push(f);
                    if t.upgraded > 0 {
                        installed.push(format!("{} app upgrade{}", t.upgraded, plural(t.upgraded)));
                    }
                }
                Err(e) => findings.push(Finding::warn("winget apps", e)),
            }
        } else {
            findings.push(Finding::info("winget apps", "winget not found; skipped"));
        }

        // --- 3. Restart state ---
        restart = restart || wua::reboot_pending().unwrap_or(false);
        findings.push(crate::update::firmware::restart_finding(restart));

        let mut summary = if installed.is_empty() {
            "Nothing new installed".to_string()
        } else {
            format!("Installed {}", installed.join(" and "))
        };
        if restart {
            summary.push_str("; restart required");
        }
        Ok(Output::new(summary, findings).restart_required(restart))
    }

    pub fn preview(ctx: &RunContext) -> Result<Output, String> {
        let mut findings = Vec::new();
        let mut parts = Vec::new();

        // The same selection install() makes: important updates, optional ones skipped.
        ctx.log("Searching Windows Update…");
        match wua::pending(Kind::Software) {
            Ok(list) => {
                let (chosen, optional): (Vec<_>, Vec<_>) = list.into_iter().partition(|p| !p.optional);
                let mut head = Finding::info(
                    "Windows Update",
                    if chosen.is_empty() {
                        "nothing to install".to_string()
                    } else {
                        format!("would install {} update{}", chosen.len(), plural(chosen.len()))
                    },
                );
                if !optional.is_empty() {
                    head = head.with_detail(format!("{} optional update{} would be skipped", optional.len(), plural(optional.len())));
                }
                findings.push(head);
                for p in chosen.iter().take(LIST_MAX) {
                    findings.push(Finding::info(p.label(), p.title.clone()));
                }
                if chosen.len() > LIST_MAX {
                    findings.push(Finding::info("More updates", format!("{} more", chosen.len() - LIST_MAX)));
                }
                if !chosen.is_empty() {
                    parts.push(format!("{} Windows update{}", chosen.len(), plural(chosen.len())));
                }
            }
            Err(e) => findings.push(Finding::warn("Windows Update", e)),
        }

        if winget::available() {
            ctx.log("Checking winget for app upgrades…");
            match winget::pending() {
                Ok(rows) => {
                    findings.push(Finding::info(
                        "winget apps",
                        if rows.is_empty() {
                            "nothing to upgrade".to_string()
                        } else {
                            format!("would upgrade {} app{}", rows.len(), plural(rows.len()))
                        },
                    ));
                    for r in rows.iter().take(LIST_MAX) {
                        findings.push(Finding::info(format!("{} ({})", r.name, r.id), format!("{} → {}", r.version, r.available)));
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
            findings.push(Finding::info("winget apps", "winget not found; apps would be skipped"));
        }

        Ok(Output::new(preview_summary(&parts), findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::pkg::apt_result_line;
    use crate::parse::text::truncate_chars;
    use crate::update::pkgmgr::{reboot_required, PkgMgr};
    use crate::update::LIST_MAX;
    use crate::util::{exit_label, pkexec_error, plural, privileged_shell, stream};
    use std::time::Duration;

    pub fn apply(ctx: &RunContext) -> Result<Output, String> {
        let pm = PkgMgr::detect()
            .ok_or("No supported package manager found (apt, dnf, pacman, zypper).")?;
        let (command, via_pkexec) = privileged_shell(pm.upgrade_script())?;
        if via_pkexec {
            ctx.log("Asking for your password (pkexec)…");
        }
        ctx.log(format!("Upgrading packages with {}…", pm.name()));
        let out = stream(command, ctx, Duration::from_secs(2 * 3600))?;
        if via_pkexec {
            if let Some(why) = pkexec_error(out.code) {
                return Err(why.to_string());
            }
        }

        let ok = out.success();
        let result_line = match pm {
            PkgMgr::Apt => apt_result_line(&out.stdout),
            _ => out.stdout.lines().rev().map(str::trim).find(|l| !l.is_empty()).map(str::to_string),
        };
        let mut head = Finding::new(
            format!("{} upgrade", pm.name()),
            if ok { "completed".to_string() } else { format!("failed ({})", exit_label(out.code)) },
            if ok { Severity::Ok } else { Severity::Critical },
        );
        if let Some(line) = &result_line {
            head = head.with_detail(truncate_chars(line, 200));
        }
        let mut findings = vec![head];

        let reboot = reboot_required();
        match &reboot {
            Some(why) => findings.push(crate::update::firmware::restart_finding(true).with_detail(why.clone())),
            None => findings.push(Finding::ok("Restart required", "not flagged")),
        }

        let mut summary = if ok {
            result_line.unwrap_or_else(|| format!("{} upgrade completed", pm.name()))
        } else {
            format!("{} upgrade failed", pm.name())
        };
        if reboot.is_some() {
            summary.push_str("; reboot required");
        }
        let restart = reboot.is_some();
        Ok(Output::new(summary, findings).restart_required(restart))
    }

    pub fn preview(ctx: &RunContext) -> Result<Output, String> {
        let pm = PkgMgr::detect()
            .ok_or("No supported package manager found (apt, dnf, pacman, zypper).")?;
        ctx.log(format!("Checking {} for upgrades…", pm.name()));
        let list = pm.pending()?;
        let mut head = Finding::info(
            format!("{} upgrade", pm.name()),
            if list.is_empty() {
                "nothing to upgrade".to_string()
            } else {
                format!("would upgrade {} package{}", list.len(), plural(list.len()))
            },
        );
        if let Some(note) = pm.scan_note() {
            head = head.with_detail(note);
        }
        let mut findings = vec![head];
        for u in list.iter().take(LIST_MAX) {
            findings.push(Finding::info(u.name.clone(), u.change()));
        }
        if list.len() > LIST_MAX {
            findings.push(Finding::info("More packages", format!("{} more", list.len() - LIST_MAX)));
        }
        let parts = if list.is_empty() {
            Vec::new()
        } else {
            vec![format!("{} package upgrade{}", list.len(), plural(list.len()))]
        };
        Ok(Output::new(preview_summary(&parts), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::preview_summary;

    #[test]
    fn preview_summaries_say_nothing_changed() {
        assert_eq!(preview_summary(&[]), "Preview: nothing to install. Nothing was changed.");
        assert_eq!(
            preview_summary(&["3 Windows updates".into(), "2 app upgrades".into()]),
            "Preview: would install 3 Windows updates and 2 app upgrades. Nothing was changed."
        );
    }
}
