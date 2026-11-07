//! RAM and swap pressure. Read-only.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::human_bytes;
use sysinfo::System;

pub struct MemoryUsage;

impl TriageModule for MemoryUsage {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "system.memory",
            "Memory usage",
            Category::System,
            "RAM and swap in use. Warns at 80% used, critical at 90% (the site profile can change both).",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let band = ctx.profile().thresholds.memory_pct;
        let mut sys = System::new();
        sys.refresh_memory();

        let total = sys.total_memory();
        if total == 0 {
            return Ok(Output::new("Memory information unavailable.", Vec::new()));
        }
        let used = sys.used_memory();
        let available = sys.available_memory();
        let used_pct = used as f64 / total as f64 * 100.0;

        let severity = band.high(used_pct.round());

        let mut findings = vec![Finding::new(
            "RAM",
            format!(
                "{} used of {} ({:.0}%), {} available",
                human_bytes(used),
                human_bytes(total),
                used_pct,
                human_bytes(available)
            ),
            severity,
        )
        .with_metric(used_pct.round(), "%", true)];

        let total_swap = sys.total_swap();
        if total_swap > 0 {
            let used_swap = sys.used_swap();
            let swap_pct = used_swap as f64 / total_swap as f64 * 100.0;
            let swap_severity = if swap_pct > 50.0 {
                Severity::Warning
            } else {
                Severity::Ok
            };
            findings.push(Finding::new(
                "Swap / page file",
                format!(
                    "{} used of {} ({:.0}%)",
                    human_bytes(used_swap),
                    human_bytes(total_swap),
                    swap_pct
                ),
                swap_severity,
            ));
        } else {
            findings.push(Finding::info("Swap / page file", "none configured"));
        }

        Ok(Output::new(format!("{:.0}% RAM in use", used_pct), findings))
    }
}
