//! Bounded lightweight recordings. No packet bodies, process command lines,
//! screenshots or authentication material are captured.
use crate::module::RunContext;
use crate::{Category, Finding, ModuleInfo, ModuleResult, Sampler, Target};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_SAMPLES: usize = 1800;
pub const MAX_MARKERS: usize = 100;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub seconds: u64,
    pub interval_ms: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            seconds: 60,
            interval_ms: 1000,
        }
    }
}
impl Config {
    pub fn bounded(&self) -> Self {
        Self {
            seconds: self.seconds.clamp(5, 1800),
            interval_ms: self.interval_ms.clamp(1000, 10000),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Marker {
    pub at_ms: u64,
    pub label: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub at_ms: u64,
    pub cpu_pct: f32,
    pub memory_pct: f32,
    pub disk_read: u64,
    pub disk_write: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub tcp_ms: Option<f64>,
    pub tcp_error: Option<String>,
    pub dns_ms: Option<f64>,
    pub dns_error: Option<String>,
    pub wifi: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recording {
    pub started: String,
    pub config: Config,
    pub target: Option<String>,
    pub samples: Vec<Sample>,
    pub markers: Vec<Marker>,
    pub stopped_early: bool,
    pub gaps: Vec<String>,
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
pub fn mark(markers: &Mutex<Vec<Marker>>, label: &str) -> Result<Marker, String> {
    let mut rows = markers.lock().map_err(|_| "The marker list is unavailable.")?;
    if rows.len() >= MAX_MARKERS {
        return Err("This recording already has 100 markers.".into());
    }
    let label: String = label.trim().chars().filter(|c| !c.is_control()).take(200).collect();
    let marker = Marker {
        at_ms: now_ms(),
        label: if label.is_empty() { "Problem happened now".into() } else { label },
    };
    rows.push(marker.clone());
    Ok(marker)
}

pub fn record(
    config: Config,
    target: Option<&Target>,
    ctx: &RunContext,
    markers: &Mutex<Vec<Marker>>,
    mut sample_ready: impl FnMut(&Sample),
) -> Result<Recording, String> {
    let config = config.bounded();
    let mut recording = Recording {
        started: crate::parse::time::epoch_to_rfc3339(crate::util::now_epoch()),
        config: config.clone(),
        target: None,
        samples: Vec::new(),
        markers: Vec::new(),
        stopped_early: false,
        gaps: Vec::new(),
    };
    let target = target
        .and_then(|t| t.ports.first().map(|p| (t.host.clone(), *p)))
        .or_else(|| ctx.profile().network.tcp_probe_target());
    let addresses = target.as_ref().and_then(|(host, _)| {
        let host = host.clone();
        crate::util::within(Duration::from_secs(3), move || crate::net::resolve(&host))
            .and_then(Result::ok)
            .map(|r| r.addresses)
    });
    if let Some((host, port)) = &target {
        recording.target = Some(format!("{host}:{port}"));
        if addresses.is_none() {
            recording
                .gaps
                .push("The target did not resolve within three seconds; TCP sampling is unavailable.".into());
        }
    } else {
        recording
            .gaps
            .push("No TCP target was configured; only local telemetry and Wi-Fi state are sampled.".into());
    }
    let dns = if let Some(name) = ctx.profile().network.dns_probe_name() {
        crate::net::default_route()
            .ok()
            .and_then(|r| r.dns_servers.first().copied())
            .map(|server| (server, name))
    } else {
        None
    };
    if dns.is_none() {
        recording
            .gaps
            .push("No permitted DNS probe / upstream server was available; DNS sampling is unavailable.".into());
    }
    let mut sampler = Sampler::new();
    let start = Instant::now();
    let mut next = start;
    let mut wifi = None;
    while start.elapsed() < Duration::from_secs(config.seconds) && recording.samples.len() < MAX_SAMPLES {
        if ctx.cancelled() {
            recording.stopped_early = true;
            break;
        }
        if Instant::now() < next {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let telemetry = sampler.sample();
        let mut sample = Sample {
            at_ms: now_ms(),
            cpu_pct: telemetry.cpu,
            memory_pct: telemetry.mem_pct,
            disk_read: telemetry.disk_read,
            disk_write: telemetry.disk_write,
            net_rx: telemetry.net_rx,
            net_tx: telemetry.net_tx,
            tcp_ms: None,
            tcp_error: None,
            dns_ms: None,
            dns_error: None,
            wifi: wifi.clone(),
        };
        if let (Some(addresses), Some((_, port))) = (&addresses, &target) {
            let check = crate::net::tcp_check(addresses, *port, Duration::from_millis(250));
            if let Some((_, time)) = check.connected() {
                sample.tcp_ms = Some(time.as_secs_f64() * 1000.0);
            } else {
                sample.tcp_error = Some(check.error());
            }
        }
        if recording.samples.len().is_multiple_of(5) {
            if let Some((server, name)) = &dns {
                match crate::net::dns_query(*server, name, Duration::from_millis(250)) {
                    Ok((answer, time)) if answer.rcode == 0 => sample.dns_ms = Some(time.as_secs_f64() * 1000.0),
                    Ok((answer, _)) => sample.dns_error = Some(format!("DNS response code {}", answer.rcode)),
                    Err(_) => sample.dns_error = Some("DNS probe did not answer within 250 ms".into()),
                }
            }
            wifi = crate::investigate::wireless::snapshot();
            sample.wifi = wifi.clone();
        }
        sample_ready(&sample);
        recording.samples.push(sample);
        next += Duration::from_millis(config.interval_ms);
        if next < Instant::now() {
            next = Instant::now() + Duration::from_millis(config.interval_ms);
        }
    }
    recording.markers = markers.lock().map_err(|_| "The marker list is unavailable.")?.clone();
    if wifi.is_none() {
        recording
            .gaps
            .push("Wi-Fi state was unavailable (wired-only host, missing tool or permissions).".into());
    }
    if recording.samples.is_empty() {
        return Err("Recording stopped before the first sample.".into());
    }
    Ok(recording)
}

pub fn result(recording: &Recording) -> ModuleResult {
    let info = ModuleInfo::new("capture.recording", "Intermittent problem recording", Category::System, "");
    let mut result = ModuleResult::failed(&info, "");
    result.error = None;
    let failures = recording.samples.iter().filter(|s| s.tcp_error.is_some()).count();
    let cpu = recording.samples.iter().map(|s| s.cpu_pct).fold(0.0, f32::max);
    let memory = recording.samples.iter().map(|s| s.memory_pct).fold(0.0, f32::max);
    result.summary = format!(
        "{} samples · {} marker(s){}",
        recording.samples.len(),
        recording.markers.len(),
        if recording.stopped_early { " · stopped by user" } else { "" }
    );
    result.findings = vec![
        Finding::info("Peak CPU", format!("{cpu:.1}%")).with_metric(cpu as f64, "%", true),
        Finding::info("Peak RAM use", format!("{memory:.1}%")).with_metric(memory as f64, "%", true),
    ];
    if recording.target.is_some() {
        result.findings.push(if failures > 0 {
            Finding::warn("TCP samples", format!("{failures} connection attempt(s) failed"))
        } else {
            Finding::ok("TCP samples", "all sampled connections answered")
        });
    }
    result
        .findings
        .extend(recording.gaps.iter().map(|g| Finding::info("Recording coverage", g)));
    result
}

pub fn csv(recording: &Recording) -> String {
    let mut out =
        String::from("at_utc,cpu_pct,memory_pct,disk_read_bps,disk_write_bps,net_rx_bps,net_tx_bps,tcp_ms,dns_ms,tcp_failed,dns_failed\n");
    for s in &recording.samples {
        out.push_str(&format!(
            "{},{:.2},{:.2},{},{},{},{},{},{},{},{}\n",
            crate::parse::time::epoch_to_rfc3339(s.at_ms / 1000),
            s.cpu_pct,
            s.memory_pct,
            s.disk_read,
            s.disk_write,
            s.net_rx,
            s.net_tx,
            s.tcp_ms.map(|v| format!("{v:.2}")).unwrap_or_default(),
            s.dns_ms.map(|v| format!("{v:.2}")).unwrap_or_default(),
            s.tcp_error.is_some(),
            s.dns_error.is_some()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recording_and_marker_limits_are_enforced() {
        let config = Config {
            seconds: u64::MAX,
            interval_ms: 0,
        }
        .bounded();
        assert_eq!((config.seconds, config.interval_ms), (1800, 1000));
        let markers = Mutex::new(Vec::new());
        assert_eq!(mark(&markers, "  observed\nnow ").unwrap().label, "observednow");
        for _ in 1..MAX_MARKERS {
            mark(&markers, "event").unwrap();
        }
        assert!(mark(&markers, "overflow").is_err());
    }
}
