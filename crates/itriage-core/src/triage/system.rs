//! System information: OS, kernel, host, uptime, CPU, total RAM. Read-only.

use crate::model::{Category, Finding, ModuleInfo, Output};
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
            "OS, kernel, hostname, uptime, CPU and total memory.",
        )
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
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
            Finding::info("Uptime", human_duration(uptime)),
        ];
        if let Some(maker) = crate::host::system_manufacturer() {
            findings.push(Finding::info("Manufacturer", maker));
        }

        let summary = format!("{host}, up {}", human_duration(uptime));
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
