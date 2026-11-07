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

        let name = System::name().unwrap_or_default();
        let version = System::os_version().unwrap_or_default();
        let os = if name.is_empty() {
            System::long_os_version().unwrap_or_else(|| "unknown".into())
        } else {
            format!("{name} {version}").trim().to_string()
        };
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
