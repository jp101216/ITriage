//! Bounded lightweight recordings. No packet bodies, process command lines,
//! screenshots or authentication material are captured.
use crate::module::RunContext;
use crate::{Category, Finding, ModuleInfo, ModuleResult, Sampler, Severity, Target};
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
    /// The Wi-Fi link in words. Read every fifth sample and carried between.
    pub wifi: Option<String>,
    /// 0–100, and the access point's address: a change of address between
    /// two samples is a roam.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi_signal: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi_bssid: Option<String>,
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
    append_marker(&mut rows, label)
}
pub fn append_marker(rows: &mut Vec<Marker>, label: &str) -> Result<Marker, String> {
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
        recording.target = Some(if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        });
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
    // CPU load and the disk and network rates are differences between two
    // readings. Without this first one, thrown away, sample 1 would compare
    // against a reading taken microseconds earlier: a made-up CPU figure
    // (which could then be the recording's "peak") and rates of zero.
    let mut sampler = Sampler::new();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(250)));
    sampler.sample();
    let start = Instant::now();
    let mut next = start;
    let mut wifi: Option<crate::investigate::wireless::WifiState> = None;
    let mut wifi_seen = false;
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
            wifi: None,
            wifi_signal: None,
            wifi_bssid: None,
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
            wifi = crate::investigate::wireless::state();
            wifi_seen |= wifi.is_some();
        }
        if let Some(link) = &wifi {
            sample.wifi = Some(link.describe());
            sample.wifi_signal = link.signal;
            sample.wifi_bssid = link.bssid.clone();
        }
        sample_ready(&sample);
        recording.samples.push(sample);
        next += Duration::from_millis(config.interval_ms);
        if next < Instant::now() {
            next = Instant::now() + Duration::from_millis(config.interval_ms);
        }
    }
    recording.markers = markers.lock().map_err(|_| "The marker list is unavailable.")?.clone();
    if !wifi_seen {
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
    let attempts = recording
        .samples
        .iter()
        .filter(|s| s.tcp_error.is_some() || s.tcp_ms.is_some())
        .count();
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
        let slowest = recording.samples.iter().filter_map(|s| s.tcp_ms).fold(0.0, f64::max);
        result.findings.push(if attempts == 0 {
            Finding::info("TCP samples", "No TCP attempts could be sampled; inspect coverage gaps")
        } else if failures > 0 {
            Finding::warn("TCP samples", format!("{failures} of {attempts} connection attempt(s) failed"))
                .with_detail(failure_times(recording))
        } else {
            let slowest = if slowest < 1.0 { "under 1 ms".to_string() } else { format!("{slowest:.0} ms") };
            Finding::ok("TCP samples", format!("all {attempts} sampled connections answered · slowest {slowest}"))
        });
    }
    let dns_attempts = recording
        .samples
        .iter()
        .filter(|s| s.dns_ms.is_some() || s.dns_error.is_some())
        .count();
    let dns_failures = recording.samples.iter().filter(|s| s.dns_error.is_some()).count();
    if dns_attempts > 0 {
        result.findings.push(if dns_failures > 0 {
            Finding::warn("DNS samples", format!("{dns_failures} of {dns_attempts} probes failed"))
        } else {
            Finding::ok("DNS samples", format!("{dns_attempts} probes answered"))
        });
    }
    if let Some(wifi) = wifi_summary(recording) {
        result.findings.push(wifi);
    }
    result
        .findings
        .extend(recording.gaps.iter().map(|g| Finding::info("Recording coverage", g)));
    result
}

/// When the failed connection attempts were, for matching against the
/// markers: the first few times, then a count.
fn failure_times(recording: &Recording) -> String {
    let times: Vec<String> = recording
        .samples
        .iter()
        .filter(|s| s.tcp_error.is_some())
        .map(|s| crate::parse::time::epoch_to_rfc3339(s.at_ms / 1000))
        .collect();
    let shown = times.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
    if times.len() > 8 {
        format!("Failed at (UTC): {shown}, and {} more.", times.len() - 8)
    } else {
        format!("Failed at (UTC): {shown}.")
    }
}

/// How many times the PC moved to another access point, in the samples
/// that saw one. Wi-Fi is read every fifth sample, so two quick roams
/// between readings count once.
pub fn roams(recording: &Recording) -> usize {
    let mut seen = recording.samples.iter().filter_map(|s| s.wifi_bssid.as_deref());
    let Some(mut last) = seen.next() else {
        return 0;
    };
    let mut count = 0;
    for ap in seen {
        if !ap.eq_ignore_ascii_case(last) {
            count += 1;
            last = ap;
        }
    }
    count
}

fn wifi_summary(recording: &Recording) -> Option<Finding> {
    let signals: Vec<u32> = recording.samples.iter().filter_map(|s| s.wifi_signal).collect();
    let roamed = roams(recording);
    let (low, high) = (signals.iter().min()?, signals.iter().max()?);
    let range = if low == high { format!("signal {low}%") } else { format!("signal {low}–{high}%") };
    let moved = match roamed {
        0 => "stayed on one access point".to_string(),
        1 => "moved to another access point once".to_string(),
        n => format!("moved between access points {n} times"),
    };
    let finding = Finding::new("Wi-Fi during the recording", format!("{range} · {moved}"), if *low < 30 { Severity::Warning } else { Severity::Info });
    Some(finding.with_detail("Read every fifth sample. A drop in signal or a move at the moment of a marker is worth a look; neither is a fault alone."))
}

/// One value in a CSV row: quoted when it holds a comma, a quote or a line
/// break, and never starting with a character a spreadsheet would run as a
/// formula (a marker is whatever the technician typed).
fn csv_field(text: &str) -> String {
    let text = if text.starts_with(['=', '+', '-', '@']) { format!("'{text}") } else { text.to_string() };
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

/// The samples as a spreadsheet. A marker is written on the first sample
/// taken at or after it (the last sample, for one made after that).
pub fn csv(recording: &Recording) -> String {
    let mut out = String::from(
        "at_utc,cpu_pct,memory_pct,disk_read_bps,disk_write_bps,net_rx_bps,net_tx_bps,tcp_ms,dns_ms,tcp_failed,dns_failed,wifi_signal_pct,wifi_access_point,marker\n",
    );
    let mut markers: Vec<Vec<&str>> = vec![Vec::new(); recording.samples.len()];
    for m in &recording.markers {
        if let Some(last) = recording.samples.len().checked_sub(1) {
            let at = recording.samples.iter().position(|s| s.at_ms >= m.at_ms).unwrap_or(last);
            markers[at].push(&m.label);
        }
    }
    for (s, marked) in recording.samples.iter().zip(&markers) {
        out.push_str(&format!(
            "{},{:.2},{:.2},{},{},{},{},{},{},{},{},{},{},{}\n",
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
            s.dns_error.is_some(),
            s.wifi_signal.map(|v| v.to_string()).unwrap_or_default(),
            csv_field(s.wifi_bssid.as_deref().unwrap_or_default()),
            csv_field(&marked.join(" | ")),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsampled_connections_never_get_a_success_verdict() {
        let capture = Recording {
            started: "2026-11-10T12:00:00Z".into(),
            config: Config::default(),
            target: Some("unresolved.example:443".into()),
            samples: vec![],
            markers: vec![],
            stopped_early: false,
            gaps: vec!["Name lookup failed".into()],
        };
        let r = result(&capture);
        assert!(r
            .findings
            .iter()
            .any(|f| f.label == "TCP samples" && f.severity == crate::Severity::Info));
        assert!(!r
            .findings
            .iter()
            .any(|f| f.label == "TCP samples" && f.severity == crate::Severity::Ok));
    }
    fn sample(at_ms: u64) -> Sample {
        Sample {
            at_ms,
            cpu_pct: 10.0,
            memory_pct: 50.0,
            disk_read: 0,
            disk_write: 0,
            net_rx: 0,
            net_tx: 0,
            tcp_ms: Some(12.0),
            tcp_error: None,
            dns_ms: None,
            dns_error: None,
            wifi: None,
            wifi_signal: None,
            wifi_bssid: None,
        }
    }

    fn capture(samples: Vec<Sample>, markers: Vec<Marker>) -> Recording {
        Recording {
            started: "2026-11-10T12:00:00Z".into(),
            config: Config::default(),
            target: Some("appserver:443".into()),
            samples,
            markers,
            stopped_early: false,
            gaps: vec![],
        }
    }

    #[test]
    fn a_real_recording_starts_with_a_measured_sample() {
        let ctx = RunContext::new(&|_: &str| {});
        let started = Instant::now();
        let recording = record(Config { seconds: 5, interval_ms: 1000 }, None, &ctx, &Mutex::new(Vec::new()), |_| {}).unwrap();
        assert!(started.elapsed() < Duration::from_secs(9));
        assert!((4..=6).contains(&recording.samples.len()), "{} samples", recording.samples.len());
        // The first sample covers a real stretch of time, like the others.
        let first = &recording.samples[0];
        let second = &recording.samples[1];
        assert!(second.at_ms - first.at_ms >= 900, "samples are an interval apart");
        assert!((0.0..=100.0).contains(&first.cpu_pct));
    }

    #[test]
    fn wifi_moves_and_failures_are_summarised_and_markers_reach_the_csv() {
        let mut samples: Vec<Sample> = (0..6).map(|i| sample(1_794_300_000_000 + i * 1000)).collect();
        for (s, (signal, ap)) in samples.iter_mut().zip([(70, "aa:aa"), (68, "aa:aa"), (41, "bb:bb"), (44, "BB:BB"), (72, "aa:aa"), (71, "aa:aa")]) {
            s.wifi_signal = Some(signal);
            s.wifi_bssid = Some(ap.into());
        }
        samples[2].tcp_ms = None;
        samples[2].tcp_error = Some("timed out".into());
        let markers = vec![
            Marker { at_ms: 1_794_300_001_500, label: "Call dropped, \"again\"".into() },
            Marker { at_ms: 1_794_300_999_000, label: "=after the end".into() },
        ];
        let recording = capture(samples, markers);
        assert_eq!(roams(&recording), 2, "case alone isn't a move");
        let r = result(&recording);
        let get = |label: &str| r.findings.iter().find(|f| f.label == label).unwrap();
        assert_eq!(get("Wi-Fi during the recording").value, "signal 41–72% · moved between access points 2 times");
        assert_eq!(get("TCP samples").value, "1 of 6 connection attempt(s) failed");
        assert!(get("TCP samples").detail.as_deref().unwrap().contains("2026-11-10T"));
        let csv = csv(&recording);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 7);
        assert!(lines[0].ends_with(",wifi_signal_pct,wifi_access_point,marker"));
        assert!(lines[3].ends_with(",true,false,41,bb:bb,\"Call dropped, \"\"again\"\"\""), "{}", lines[3]);
        assert!(lines[6].ends_with(",'=after the end"), "a marker can't become a formula: {}", lines[6]);
        // A wired PC has nothing to say about Wi-Fi.
        assert!(result(&capture(vec![sample(1)], vec![])).findings.iter().all(|f| !f.label.starts_with("Wi-Fi")));
    }

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
