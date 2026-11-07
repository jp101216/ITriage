//! Disk latency on Linux from `/proc/diskstats`, measured the way Windows'
//! "Avg. Disk sec/Transfer" counter is: time spent on I/O divided by the
//! number of I/Os completed, over a short interval.

/// Cumulative counters, summed over whole disks.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DiskCounters {
    /// Reads and writes completed.
    pub ios: u64,
    /// Milliseconds spent reading and writing.
    pub io_ms: u64,
    /// Weighted milliseconds spent doing I/O (time × queue depth).
    pub weighted_ms: u64,
}

/// Whole disks only (sda, nvme0n1, vda, mmcblk0), not their partitions or
/// virtual devices (loop, ram, zram, dm, md).
pub fn is_whole_disk(name: &str) -> bool {
    let letters_only = |rest: &str| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_lowercase());
    for prefix in ["sd", "vd", "xvd", "hd"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return letters_only(rest);
        }
    }
    if let Some(rest) = name.strip_prefix("nvme") {
        // nvme0n1, not nvme0n1p2 or the controller nvme0c0n1.
        let mut parts = rest.split('n');
        return matches!((parts.next(), parts.next(), parts.next()),
            (Some(c), Some(n), None) if !c.is_empty() && c.chars().all(|x| x.is_ascii_digit())
                && !n.is_empty() && n.chars().all(|x| x.is_ascii_digit()));
    }
    if let Some(rest) = name.strip_prefix("mmcblk") {
        return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit());
    }
    false
}

/// Sum the counters of every whole disk in a `/proc/diskstats` snapshot.
pub fn totals(text: &str) -> DiskCounters {
    let mut t = DiskCounters::default();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 14 || !is_whole_disk(f[2]) {
            continue;
        }
        let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        // After major, minor, name: reads, merged, sectors, ms reading,
        // writes, merged, sectors, ms writing, in flight, ms doing I/O,
        // weighted ms.
        t.ios += n(3) + n(7);
        t.io_ms += n(6) + n(10);
        t.weighted_ms += n(13);
    }
    t
}

/// Average milliseconds per I/O and the average queue depth between two
/// snapshots taken `interval_ms` apart. An idle disk reads 0 ms.
pub fn latency(before: DiskCounters, after: DiskCounters, interval_ms: u64) -> (f64, f64) {
    let ios = after.ios.saturating_sub(before.ios);
    let busy = after.io_ms.saturating_sub(before.io_ms);
    let latency = if ios == 0 { 0.0 } else { busy as f64 / ios as f64 };
    let queue = after.weighted_ms.saturating_sub(before.weighted_ms) as f64 / interval_ms.max(1) as f64;
    (latency, queue)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_whole_disks() {
        for yes in ["sda", "sdab", "vda", "xvdb", "nvme0n1", "nvme12n3", "mmcblk0"] {
            assert!(is_whole_disk(yes), "{yes}");
        }
        for no in ["sda1", "nvme0n1p2", "nvme0c0n1", "mmcblk0p1", "loop0", "dm-0", "md127", "zram0", "sr0", "nvme"] {
            assert!(!is_whole_disk(no), "{no}");
        }
    }

    #[test]
    fn measures_latency_between_snapshots() {
        let a = "   8       0 sda 1000 0 0 4000 500 0 0 6000 0 0 12000 0 0 0 0\n   8       1 sda1 900 0 0 3900 400 0 0 5900 0 0 11000\n 259 0 nvme0n1 10 0 0 10 10 0 0 10 0 0 40\n";
        let b = "   8       0 sda 1100 0 0 4500 600 0 0 7500 2 0 14000 0 0 0 0\n   8       1 sda1 1000 0 0 4400 500 0 0 7400 2 0 13000\n 259 0 nvme0n1 10 0 0 10 10 0 0 10 0 0 40\n";
        let (before, after) = (totals(a), totals(b));
        assert_eq!(before.ios, 1520, "partitions don't double-count");
        let (ms, queue) = latency(before, after, 1000);
        assert_eq!(ms, 10.0, "2000 ms busy over 200 I/Os");
        assert_eq!(queue, 2.0);
        assert_eq!(latency(after, after, 1000), (0.0, 0.0), "idle");
    }
}
