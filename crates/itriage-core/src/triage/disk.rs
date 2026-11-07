//! Disk usage per mount point. Flags low free space. Read-only.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::human_bytes;
use sysinfo::Disks;

pub struct DiskUsage;

impl TriageModule for DiskUsage {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "system.disk",
            "Disk usage",
            Category::System,
            "Free vs. total space per volume. Warns under 10% free, critical under 5%.",
        )
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let disks = Disks::new_with_refreshed_list();
        let mut findings = Vec::new();
        let mut worst_free_pct = 100.0_f64;

        for disk in &disks {
            let total = disk.total_space();
            if total == 0 {
                continue; // skip pseudo/empty volumes
            }
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            let used_pct = used as f64 / total as f64 * 100.0;
            let free_pct = 100.0 - used_pct;
            worst_free_pct = worst_free_pct.min(free_pct);

            let severity = if free_pct < 5.0 {
                Severity::Critical
            } else if free_pct < 10.0 {
                Severity::Warning
            } else {
                Severity::Ok
            };

            let mount = disk.mount_point().display().to_string();
            let fs = disk.file_system().to_string_lossy();
            let value = format!(
                "{} free of {} ({:.0}% used) · {}",
                human_bytes(available),
                human_bytes(total),
                used_pct,
                fs
            );
            findings.push(Finding::new(mount, value, severity));
        }

        if findings.is_empty() {
            return Ok(Output::new("No usable volumes found.", Vec::new()));
        }

        let summary = if worst_free_pct < 5.0 {
            "Critically low free space on at least one volume.".to_string()
        } else if worst_free_pct < 10.0 {
            "Low free space on at least one volume.".to_string()
        } else {
            format!("All volumes healthy (lowest {:.0}% free).", worst_free_pct)
        };
        Ok(Output::new(summary, findings))
    }
}
