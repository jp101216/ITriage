//! Ping results: the summary `ping` prints on Linux (iputils and BusyBox),
//! and the numbers both platforms report from (sent, received, round trips).

/// Echo statistics for one target, the way Invoke-NetTriage reports them.
#[derive(Debug, Clone, PartialEq)]
pub struct PingStats {
    pub sent: u32,
    pub received: u32,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
}

impl PingStats {
    /// From individual round-trip times (Windows ICMP replies).
    pub fn from_samples(sent: u32, rtts: &[f64]) -> Self {
        let n = rtts.len() as f64;
        let (min, max) = rtts
            .iter()
            .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| (lo.min(v), hi.max(v)));
        Self {
            sent,
            received: rtts.len() as u32,
            min_ms: (!rtts.is_empty()).then_some(min),
            avg_ms: (!rtts.is_empty()).then(|| rtts.iter().sum::<f64>() / n),
            max_ms: (!rtts.is_empty()).then_some(max),
        }
    }

    /// Packet loss as a whole percentage (NetTriage rounds the same way).
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            return 100.0;
        }
        (f64::from(self.sent.saturating_sub(self.received)) / f64::from(self.sent) * 100.0).round()
    }

    /// "avg 4 ms (2–7) · 0% loss" / "no reply · 100% loss".
    pub fn describe(&self) -> String {
        match (self.avg_ms, self.min_ms, self.max_ms) {
            (Some(avg), Some(min), Some(max)) => format!(
                "avg {} (min {} / max {}) · {}% loss",
                ms(avg),
                ms(min),
                ms(max),
                self.loss_pct()
            ),
            _ => format!("no reply · {}% loss", self.loss_pct()),
        }
    }
}

/// A round trip as people read it: "<1 ms" below a millisecond.
pub fn ms(v: f64) -> String {
    if v < 1.0 {
        "<1 ms".to_string()
    } else {
        format!("{} ms", v.round())
    }
}

/// The statistics block from Linux `ping`:
///
/// ```text
/// 4 packets transmitted, 3 received, 25% packet loss, time 3004ms
/// rtt min/avg/max/mdev = 0.391/0.475/0.512/0.049 ms
/// ```
///
/// BusyBox writes "4 packets received" and "round-trip min/avg/max = …".
pub fn linux_summary(out: &str) -> Option<PingStats> {
    let counts = out.lines().find(|l| l.contains("packets transmitted"))?;
    let numbers: Vec<u32> = counts
        .split(',')
        .take(2)
        .filter_map(|part| part.split_whitespace().next()?.parse().ok())
        .collect();
    let (sent, received) = match numbers[..] {
        [s, r, ..] => (s, r),
        _ => return None,
    };
    let mut stats = PingStats {
        sent,
        received,
        min_ms: None,
        avg_ms: None,
        max_ms: None,
    };
    if let Some(rtt) = out.lines().find(|l| l.contains("min/avg/max")) {
        let values: Vec<f64> = rtt
            .split('=')
            .nth(1)
            .unwrap_or("")
            .trim()
            .trim_end_matches("ms")
            .trim()
            .split('/')
            .filter_map(|v| v.trim().parse().ok())
            .collect();
        if values.len() >= 3 {
            stats.min_ms = Some(values[0]);
            stats.avg_ms = Some(values[1]);
            stats.max_ms = Some(values[2]);
        }
    }
    Some(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iputils() {
        let out = "PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.\n\
                   64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.512 ms\n\n\
                   --- 10.0.0.1 ping statistics ---\n\
                   4 packets transmitted, 3 received, 25% packet loss, time 3004ms\n\
                   rtt min/avg/max/mdev = 0.391/2.475/7.512/0.049 ms\n";
        let s = linux_summary(out).unwrap();
        assert_eq!((s.sent, s.received), (4, 3));
        assert_eq!(s.loss_pct(), 25.0);
        assert_eq!(s.avg_ms, Some(2.475));
        assert_eq!(s.describe(), "avg 2 ms (min <1 ms / max 8 ms) · 25% loss");
    }

    #[test]
    fn parses_busybox_and_total_loss() {
        let bb = "--- 1.1.1.1 ping statistics ---\n4 packets transmitted, 4 packets received, 0% packet loss\n\
                  round-trip min/avg/max = 9.1/10.2/12.0 ms\n";
        let s = linux_summary(bb).unwrap();
        assert_eq!((s.sent, s.received, s.max_ms), (4, 4, Some(12.0)));
        let lost = "--- 10.9.9.9 ping statistics ---\n4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 3061ms\n";
        let s = linux_summary(lost).unwrap();
        assert_eq!(s.loss_pct(), 100.0);
        assert_eq!(s.describe(), "no reply · 100% loss");
        assert!(linux_summary("ping: unknown host").is_none());
    }

    #[test]
    fn builds_from_samples() {
        let s = PingStats::from_samples(4, &[3.0, 5.0, 4.0]);
        assert_eq!((s.min_ms, s.avg_ms, s.max_ms), (Some(3.0), Some(4.0), Some(5.0)));
        assert_eq!(s.loss_pct(), 25.0);
        assert_eq!(PingStats::from_samples(0, &[]).loss_pct(), 100.0);
    }
}
