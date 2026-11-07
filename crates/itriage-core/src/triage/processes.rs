//! What's eating this box: overall CPU load against the site's threshold
//! (Invoke-NetTriage's 75% / 90%), the busiest processes right now and the
//! biggest memory users. CPU is shared of the whole machine, as Task Manager
//! and NetTriage show it. Read-only.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::human_bytes;
use std::cmp::Reverse;
use sysinfo::{Process, ProcessesToUpdate, System};

/// Biggest memory users listed.
const TOP_MEMORY: usize = 10;
/// CPU hogs added on top, when they aren't already in the memory list.
const TOP_CPU: usize = 3;
/// A process pinning a core (at or above this share of one core) is flagged.
const HOT_CORE: f32 = 90.0;
/// A process using this share of the whole machine is flagged.
const HOT_MACHINE: f64 = 50.0;
/// How long CPU is measured over; NetTriage samples for 700 ms.
const SAMPLE: std::time::Duration = std::time::Duration::from_millis(1000);
/// A process holding at least this fraction of physical RAM is flagged.
const HEAVY_MEMORY: f64 = 0.25;

pub struct TopProcesses;

impl TriageModule for TopProcesses {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "proc.top",
            "Top processes",
            Category::Processes,
            "Overall CPU load (warns at 75%), the busiest processes right now, and the biggest memory users. Flags anything pinning a core or holding a quarter of RAM.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let band = ctx.profile().thresholds.cpu_pct;
        let mut sys = System::new_all();
        // CPU% is the delta between two refreshes, so sample twice, a second
        // apart (cumulative CPU time since start says nothing about "slow now").
        std::thread::sleep(SAMPLE.max(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL));
        sys.refresh_cpu_usage();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        let total_memory = sys.total_memory().max(1);
        let cores = sys.cpus().len().max(1) as f64;
        let load = f64::from(sys.global_cpu_usage());

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

        let mut rows: Vec<Finding> = chosen
            .iter()
            .map(|p| {
                let share = p.memory() as f64 / total_memory as f64;
                let machine = f64::from(p.cpu_usage()) / cores;
                let hot = p.cpu_usage() >= HOT_CORE || machine >= HOT_MACHINE || share >= HEAVY_MEMORY;
                Finding::new(
                    format!("{} (pid {})", p.name().to_string_lossy(), p.pid()),
                    format!("{} RAM · {:.1}% CPU", human_bytes(p.memory()), machine),
                    if hot { Severity::Warning } else { Severity::Info },
                )
            })
            .collect();
        // Flagged processes first; the sort is stable, so the rest stay by memory.
        rows.sort_by_key(|f| Reverse(f.severity.rank()));
        let hot = rows.iter().filter(|f| f.severity == Severity::Warning).count();

        // The busiest three right now, as NetTriage's "Top CPU" line.
        let busiest: Vec<String> = by_cpu_names(&procs, cores);
        let load_severity = band.high(load);
        let mut cpu = Finding::new("CPU load", format!("{load:.0}%"), load_severity).with_metric(load.round(), "%", true);
        if !busiest.is_empty() {
            cpu = cpu.with_detail(format!("Busiest: {}", busiest.join(", ")));
        }
        let mut findings = vec![cpu];
        findings.extend(rows);

        let mut summary = format!("CPU {load:.0}% · {} processes running", procs.len());
        if hot > 0 {
            summary.push_str(&format!(" · {hot} using heavy CPU or memory"));
        }
        Ok(Output::new(summary, findings))
    }
}

/// "MsMpEng (31%), chrome (6%), Teams (2%)": the top CPU users as a share
/// of the whole machine.
fn by_cpu_names(procs: &[&Process], cores: f64) -> Vec<String> {
    let mut by_cpu = procs.to_vec();
    by_cpu.sort_by(|a, b| b.cpu_usage().total_cmp(&a.cpu_usage()));
    by_cpu
        .into_iter()
        .filter(|p| p.cpu_usage() > 0.5)
        .take(TOP_CPU)
        .map(|p| {
            let name = p.name().to_string_lossy();
            let name = name.strip_suffix(".exe").unwrap_or(&name).to_string();
            format!("{name} ({:.0}%)", f64::from(p.cpu_usage()) / cores)
        })
        .collect()
}
