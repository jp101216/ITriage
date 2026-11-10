//! Live telemetry for the HUD: frequent, cheap samples of CPU, memory,
//! network and disk activity.
//!
//! Unlike the triage modules (one-shot reports), a `Sampler` keeps state
//! between calls, because CPU% and throughput are deltas between two
//! refreshes. A shell holds one sampler and calls `sample()` about once a
//! second; each call costs a few milliseconds.

use serde::Serialize;
use std::collections::HashMap;
use std::time::Instant;
use sysinfo::{DiskRefreshKind, Disks, Networks, System};

/// How often free space (and the list of volumes) is re-read. Asking every
/// volume for its free space each second is the expensive part of a sample,
/// and a network drive that has gone away can make it stall.
const STORAGE_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// One snapshot. Rates are per second over the time since the last sample.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Telemetry {
    /// Whole-machine CPU use, 0–100.
    pub cpu: f32,
    /// Per logical core, 0–100.
    pub cores: Vec<f32>,
    /// Physical memory in use, 0–100, plus the raw figures in bytes.
    pub mem_pct: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    /// Bytes per second across all non-loopback interfaces.
    pub net_rx: u64,
    pub net_tx: u64,
    /// Bytes per second across physical disks.
    pub disk_read: u64,
    pub disk_write: u64,
    /// The fullest volume: percent used and where it's mounted.
    pub fullest_pct: f32,
    pub fullest_mount: String,
}

pub struct Sampler {
    sys: System,
    networks: Networks,
    disks: Disks,
    last: Instant,
    storage_read: Instant,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

impl Sampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage(); // baseline for the first delta
        Self {
            sys,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            last: Instant::now(),
            storage_read: Instant::now(),
        }
    }

    pub fn sample(&mut self) -> Telemetry {
        let secs = self.last.elapsed().as_secs_f64().max(0.05);
        self.last = Instant::now();
        let per_sec = |bytes: u64| (bytes as f64 / secs) as u64;

        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.networks.refresh(true);
        // Read/write counters every sample; sizes and the volume list now
        // and then.
        if self.storage_read.elapsed() >= STORAGE_EVERY {
            self.disks.refresh(true);
            self.storage_read = Instant::now();
        } else {
            self.disks.refresh_specifics(false, DiskRefreshKind::nothing().with_io_usage());
        }

        let (rx, tx) = self
            .networks
            .iter()
            .filter(|(name, _)| !is_loopback(name))
            .fold((0u64, 0u64), |(r, t), (_, d)| (r + d.received(), t + d.transmitted()));

        // The same device can be mounted more than once (bind mounts,
        // subvolumes), and each mount reports the device's I/O. Count each
        // device once.
        let mut io: HashMap<String, (u64, u64)> = HashMap::new();
        let mut fullest = (0.0f32, String::new());
        for disk in self.disks.list() {
            let usage = disk.usage();
            io.entry(disk.name().to_string_lossy().into_owned())
                .or_insert((usage.read_bytes, usage.written_bytes));
            let total = disk.total_space();
            if total > 0 {
                let pct = ((total - disk.available_space().min(total)) as f64 / total as f64 * 100.0) as f32;
                if pct > fullest.0 {
                    fullest = (pct, disk.mount_point().display().to_string());
                }
            }
        }
        let (read, write) = io.values().fold((0u64, 0u64), |(r, w), (dr, dw)| (r + dr, w + dw));

        let mem_total = self.sys.total_memory();
        let mem_used = self.sys.used_memory();
        Telemetry {
            cpu: self.sys.global_cpu_usage().clamp(0.0, 100.0),
            cores: self.sys.cpus().iter().map(|c| c.cpu_usage().clamp(0.0, 100.0)).collect(),
            mem_pct: if mem_total > 0 { (mem_used as f64 / mem_total as f64 * 100.0) as f32 } else { 0.0 },
            mem_used,
            mem_total,
            net_rx: per_sec(rx),
            net_tx: per_sec(tx),
            disk_read: per_sec(read),
            disk_write: per_sec(write),
            fullest_pct: fullest.0,
            fullest_mount: fullest.1,
        }
    }
}

fn is_loopback(name: &str) -> bool {
    name == "lo" || name.starts_with("lo:") || name.to_ascii_lowercase().contains("loopback")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_sane() {
        let mut s = Sampler::new();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        let t = s.sample();
        assert!((0.0..=100.0).contains(&t.cpu), "{}", t.cpu);
        assert!(!t.cores.is_empty());
        assert!(t.mem_total > 0 && t.mem_used <= t.mem_total);
        assert!((0.0..=100.0).contains(&t.mem_pct));
        assert!((0.0..=100.0).contains(&t.fullest_pct));
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback("lo"));
        assert!(is_loopback("Loopback Pseudo-Interface 1"));
        assert!(!is_loopback("eth0"));
        assert!(!is_loopback("wlo1"));
    }
}
