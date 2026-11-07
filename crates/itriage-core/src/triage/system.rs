//! System information: OS, kernel, host, CPU and memory, plus the baseline
//! Invoke-NetTriage and Invoke-UpdateSystem open with: make and model, serial
//! number (redactable), BIOS version and date, motherboard, who is signed
//! in, uptime against the site's threshold, and whether a restart is pending
//! and why. Read-only.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::{human_bytes, human_duration};
use sysinfo::System;

pub struct SystemInfo;

impl TriageModule for SystemInfo {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "system.info",
            "System information",
            Category::System,
            "OS, CPU and memory, make and model, serial number, BIOS version, who is signed in, uptime (warns past 7 days) and any pending restart.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let profile = ctx.profile();
        let sys = System::new_all();

        let os = os_name();
        let kernel = System::kernel_version().unwrap_or_else(|| "unknown".into());
        let host = System::host_name().unwrap_or_else(|| "unknown".into());
        let uptime = System::uptime();

        let cpu_model = sys
            .cpus()
            .first()
            .map(|c| c.brand().trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into());
        let cores = sys.cpus().len();

        let mut findings = vec![
            Finding::info("Hostname", host.clone()),
            Finding::info("OS", os),
            Finding::info("Kernel", kernel),
            Finding::info("Architecture", std::env::consts::ARCH),
            Finding::info("CPU", format!("{cpu_model} ({cores} logical cores)")),
            Finding::info("Total memory", human_bytes(sys.total_memory())),
        ];

        // --- Identity (SMBIOS) ---
        let id = crate::host::identity();
        if let Some(model) = id.make_and_model() {
            let detail = [id.family.clone(), id.chassis_name().map(str::to_string)]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · ");
            findings.push(Finding::info("Model", model).with_detail(detail));
        }
        findings.push(Finding::info(
            "Serial number",
            match &id.serial {
                _ if profile.privacy.redact_serial => "REDACTED".to_string(),
                Some(s) => s.clone(),
                None if cfg!(windows) => "not reported by the firmware".to_string(),
                None => "not readable (root only) or not set".to_string(),
            },
        ));
        if let Some(bios) = id.bios() {
            findings.push(Finding::info("BIOS", bios).with_detail(id.bios_vendor.clone().unwrap_or_default()));
        }
        if let Some(board) = id.motherboard() {
            findings.push(Finding::info("Motherboard", board));
        }

        // --- Who, how long, and whether it wants a restart ---
        findings.push(Finding::info(
            "Signed-in user",
            crate::host::signed_in_user().unwrap_or_else(|| "nobody at the console".into()),
        ));
        let days = uptime as f64 / 86_400.0;
        let uptime_severity = profile.thresholds.uptime_days.high(days);
        let mut up = Finding::new("Uptime", human_duration(uptime), uptime_severity).with_metric((days * 10.0).round() / 10.0, "days", true);
        if uptime_severity.rank() >= Severity::Warning.rank() {
            up = up.with_detail(format!("Up {:.1} days: consider a restart.", days));
        }
        findings.push(up);

        let mut summary = format!("{host}, up {}", human_duration(uptime));
        match crate::host::pending_restart() {
            Ok(reasons) if !reasons.is_empty() => {
                findings.push(
                    Finding::warn("Restart pending", format!("yes: {}", reasons.join(", ")))
                        .with_action(crate::actions::offer("restart-computer", None)),
                );
                summary.push_str("; restart pending");
            }
            Ok(_) => findings.push(Finding::ok("Restart pending", "no")),
            Err(e) => findings.push(Finding::info("Restart pending", format!("couldn't check: {e}"))),
        }
        Ok(Output::new(summary, findings))
    }
}

/// "Windows 11 Pro 24H2 (build 26100.2314)" / "Windows Server 2025 Datacenter
/// 24H2 (build 26100.1742)". The product name comes from the registry (what
/// sysinfo's long version reads), not from the build number, which can't tell
/// a client from a server release.
#[cfg(windows)]
fn os_name() -> String {
    use crate::win::registry::{read_dword, read_string, HKLM};
    const NT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product = System::long_os_version().unwrap_or_else(|| "Windows".into());
    let mut s = product;
    if let Some(release) = read_string(HKLM, NT, "DisplayVersion") {
        if !s.contains(&release) {
            s = format!("{s} {release}");
        }
    }
    if let Some(build) = read_string(HKLM, NT, "CurrentBuild") {
        match read_dword(HKLM, NT, "UBR") {
            Some(ubr) => s = format!("{s} (build {build}.{ubr})"),
            None => s = format!("{s} (build {build})"),
        }
    }
    s
}

#[cfg(not(windows))]
fn os_name() -> String {
    let name = System::name().unwrap_or_default();
    let version = System::os_version().unwrap_or_default();
    if name.is_empty() {
        System::long_os_version().unwrap_or_else(|| "unknown".into())
    } else {
        format!("{name} {version}").trim().to_string()
    }
}
