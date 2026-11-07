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
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::update::winget;
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
                let failed = report.results.len() - ok;
                findings.push(Finding::new(
                    "Windows Update",
                    if report.results.is_empty() {
                        "nothing to install".to_string()
                    } else {
                        format!("{ok} installed, {failed} failed")
                    },
                    if failed > 0 { Severity::Warning } else { Severity::Ok },
                ));
                for (p, outcome) in &report.results {
                    findings.push(
                        Finding::new(
                            p.label(),
                            outcome.label(),
                            if outcome.succeeded() { Severity::Ok } else { Severity::Critical },
                        )
                        .with_detail(p.title.clone()),
                    );
                }
                if ok > 0 {
                    installed.push(format!("{ok} Windows update{}", plural(ok)));
                }
            }
            Err(e) => findings.push(Finding::crit("Windows Update", e)),
        }

        // --- 2. Apps via winget ---
        if winget::available() {
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
        findings.push(if restart {
            Finding::warn("Restart required", "yes")
        } else {
            Finding::ok("Restart required", "no")
        });

        let mut summary = if installed.is_empty() {
            "Nothing new installed".to_string()
        } else {
            format!("Installed {}", installed.join(" and "))
        };
        if restart {
            summary.push_str("; restart required");
        }
        Ok(Output::new(summary, findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::pkg::apt_result_line;
    use crate::parse::text::truncate_chars;
    use crate::update::pkgmgr::{reboot_required, PkgMgr};
    use crate::util::{exit_label, pkexec_error, privileged_shell, stream};
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
            Some(why) => findings.push(Finding::warn("Reboot required", "yes").with_detail(why.clone())),
            None => findings.push(Finding::ok("Reboot required", "not flagged")),
        }

        let mut summary = if ok {
            result_line.unwrap_or_else(|| format!("{} upgrade completed", pm.name()))
        } else {
            format!("{} upgrade failed", pm.name())
        };
        if reboot.is_some() {
            summary.push_str("; reboot required");
        }
        Ok(Output::new(summary, findings))
    }
}
