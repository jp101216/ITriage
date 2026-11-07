//! What's eating this box: the biggest memory users plus any CPU hogs.
//! Read-only.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::human_bytes;
use std::cmp::Reverse;
use sysinfo::{Process, ProcessesToUpdate, System};

/// Biggest memory users listed.
const TOP_MEMORY: usize = 10;
/// CPU hogs added on top, when they aren't already in the memory list.
const TOP_CPU: usize = 3;
/// A process at or above this share of one core is flagged.
const HOT_CPU: f32 = 80.0;
/// A process holding at least this fraction of physical RAM is flagged.
const HEAVY_MEMORY: f64 = 0.25;

pub struct TopProcesses;

impl TriageModule for TopProcesses {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "proc.top",
            "Top processes",
            Category::Processes,
            "The biggest memory users plus any CPU hogs. Flags anything pinning a core or holding a quarter of RAM.",
        )
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let mut sys = System::new_all();
        // Per-process CPU% is the delta between two process refreshes, so
        // sample twice, a short interval apart.
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_processes(ProcessesToUpdate::All, true);
        let total_memory = sys.total_memory().max(1);

        // On Linux sysinfo also lists each thread as a "process" carrying its
        // parent's full memory figure, so one app would fill the list. Keep
        // real processes only (thread_kind is None for those).
        let procs: Vec<&Process> = sys
            .processes()
            .values()
            .filter(|p| p.thread_kind().is_none())
            .collect();

        let mut chosen: Vec<&Process> = procs.clone();
        chosen.sort_by_key(|p| Reverse(p.memory()));
        chosen.truncate(TOP_MEMORY);

        let mut by_cpu = procs.clone();
        by_cpu.sort_by(|a, b| b.cpu_usage().total_cmp(&a.cpu_usage()));
        for p in by_cpu.into_iter().take(TOP_CPU) {
            if p.cpu_usage() >= 10.0 && !chosen.iter().any(|c| c.pid() == p.pid()) {
                chosen.push(p);
            }
        }

        let mut findings: Vec<Finding> = chosen
            .iter()
            .map(|p| {
                let share = p.memory() as f64 / total_memory as f64;
                let hot = p.cpu_usage() >= HOT_CPU || share >= HEAVY_MEMORY;
                Finding::new(
                    format!("{} (pid {})", p.name().to_string_lossy(), p.pid()),
                    format!("{} RAM · {:.1}% CPU", human_bytes(p.memory()), p.cpu_usage()),
                    if hot { Severity::Warning } else { Severity::Info },
                )
            })
            .collect();
        // Flagged processes first; the sort is stable, so the rest stay by memory.
        findings.sort_by_key(|f| Reverse(f.severity.rank()));

        let hot = findings.iter().filter(|f| f.severity == Severity::Warning).count();
        let mut summary = format!("{} processes running", procs.len());
        if hot > 0 {
            summary.push_str(&format!(" · {hot} using heavy CPU or memory"));
        }
        Ok(Output::new(summary, findings))
    }
}
