//! Disk space per volume and disk latency. Read-only.
//!
//! Free space is graded against the site profile (Invoke-NetTriage's 15% /
//! 10% free by default). Latency is the average time per transfer across
//! the physical disks over one second, with the queue length: Windows'
//! "Avg. Disk sec/Transfer" counter, or the same sum from /proc/diskstats.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::human_bytes;
use std::time::Duration;
use sysinfo::Disks;

pub struct DiskUsage;

const SAMPLE: Duration = Duration::from_secs(1);

impl TriageModule for DiskUsage {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "system.disk",
            "Disk space & latency",
            Category::System,
            "Free vs. total space per volume (warns under 15% free) and disk latency with queue length (warns at 15 ms).",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let th = &ctx.profile().thresholds;
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
            let free_pct = (100.0 - used_pct).max(0.0);
            worst_free_pct = worst_free_pct.min(free_pct);

            let mount = disk.mount_point().display().to_string();
            let fs = disk.file_system().to_string_lossy();
            let value = format!(
                "{} free of {} ({:.0}% used) · {}",
                human_bytes(available),
                human_bytes(total),
                used_pct,
                fs
            );
            findings.push(
                Finding::new(mount, value, th.disk_free_pct.low(free_pct.round()))
                    .with_metric(free_pct.round(), "% free", false),
            );
        }

        let space_note = if findings.is_empty() {
            "no usable volumes".to_string()
        } else {
            match th.disk_free_pct.low(worst_free_pct.round()) {
                Severity::Critical => "critically low free space".to_string(),
                Severity::Warning => "low free space".to_string(),
                _ => format!("lowest {:.0}% free", worst_free_pct),
            }
        };

        ctx.log("Measuring disk latency for a second…");
        let latency_note = match imp::latency(SAMPLE) {
            Ok((ms, queue)) => {
                let severity = th.disk_latency_ms.high(ms);
                let mut f = Finding::new("Disk latency", format!("{ms:.1} ms per transfer · queue {queue:.1}"), severity)
                    .with_metric((ms * 10.0).round() / 10.0, "ms", true);
                if severity.rank() >= Severity::Warning.rank() {
                    f = f.with_detail("Slow storage makes everything feel slow: check for a failing drive, full disk, or heavy background I/O (indexing, scans, updates).");
                }
                findings.push(f);
                (severity.rank() >= Severity::Warning.rank()).then(|| format!("disk latency {ms:.0} ms"))
            }
            Err(e) => {
                findings.push(Finding::info("Disk latency", format!("couldn't measure: {e}")));
                None
            }
        };

        let mut summary = crate::triage::network::capitalize(&space_note);
        if let Some(l) = latency_note {
            summary.push_str(&format!(" · {l}"));
        }
        Ok(Output::new(summary, findings))
    }
}

#[cfg(windows)]
mod imp {
    pub fn latency(sample: std::time::Duration) -> Result<(f64, f64), String> {
        crate::win::pdh::disk_latency(sample)
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::parse::diskstats::{latency as between, totals};

    pub fn latency(sample: std::time::Duration) -> Result<(f64, f64), String> {
        let read = || std::fs::read_to_string("/proc/diskstats").map_err(|e| format!("can't read /proc/diskstats: {e}"));
        let before = totals(&read()?);
        std::thread::sleep(sample);
        let after = totals(&read()?);
        if after.ios == 0 && before.ios == 0 {
            return Err("no physical disks listed in /proc/diskstats".into());
        }
        Ok(between(before, after, sample.as_millis() as u64))
    }
}
