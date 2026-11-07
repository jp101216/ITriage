//! Clock & time sync. Read-only.
//!
//! Measures this clock against a time server with one SNTP exchange and
//! reports where the OS takes its time from. Kerberos refuses domain sign-in
//! once a clock is more than 5 minutes off the domain controller, and
//! workstation clocks end up in documentation timestamps, so drift matters
//! long before it breaks sign-in.

use crate::actions::offer;
use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::sntp;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct ClockSync;

/// Drift thresholds in seconds: past these the offset is a warning, then critical.
const WARN_AFTER: f64 = 10.0;
const CRIT_AFTER: f64 = 180.0;

impl TriageModule for ClockSync {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.time",
            "Clock & time sync",
            Category::Workstation,
            "Clock offset against the time server, where the time comes from, and the time zone. Domain sign-in fails past 5 minutes of drift.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let profile = ctx.profile();
        let source = imp::source();
        let mut findings = vec![source.finding];

        let server = profile.time.server.clone().or(source.server);
        let mut summary = None;
        match &server {
            Some(server) => {
                ctx.log(format!("Measuring the clock against {server} (SNTP, UDP 123)…"));
                match measure(server) {
                    Ok(s) => {
                        let drift = s.offset.abs();
                        let severity = if drift > CRIT_AFTER {
                            Severity::Critical
                        } else if drift > WARN_AFTER {
                            Severity::Warning
                        } else {
                            Severity::Ok
                        };
                        let described = sntp::describe_offset(s.offset);
                        let mut f = Finding::new(format!("Offset vs {server}"), described.clone(), severity).with_detail(
                            format!("round trip {:.0} ms · server stratum {}", s.delay * 1000.0, s.stratum),
                        );
                        if severity != Severity::Ok {
                            f = f.with_action(offer("resync-time", None));
                        }
                        findings.push(f);
                        summary = Some(if severity == Severity::Ok {
                            format!("Clock in sync with {server}")
                        } else {
                            format!("Clock is {described} against {server}")
                        });
                    }
                    Err(e) => findings.push(Finding::info(format!("Offset vs {server}"), format!("not measured: {e}"))),
                }
            }
            None => findings.push(Finding::info(
                "Offset",
                "not measured: no time server known (set [time] server in the site profile)",
            )),
        }

        if let Some(zone) = source.zone {
            match &profile.time.zone {
                Some(want) if !zone.eq_ignore_ascii_case(want) => {
                    findings.push(Finding::warn("Time zone", format!("{zone} · the site profile expects {want}")))
                }
                _ => findings.push(Finding::info("Time zone", zone)),
            }
        }
        findings.extend(source.extra);

        let worst = findings.iter().map(|f| f.severity).max_by_key(|s| s.rank()).unwrap_or(Severity::Ok);
        let summary = summary.unwrap_or_else(|| {
            if worst.rank() >= Severity::Warning.rank() {
                "Time sync needs attention".to_string()
            } else {
                "Time source looks right; offset not measured".to_string()
            }
        });
        Ok(Output::new(summary, findings))
    }
}

/// Where the OS gets its time, as found by the platform code.
struct Source {
    finding: Finding,
    /// A server worth measuring against, if the OS names one.
    server: Option<String>,
    zone: Option<String>,
    extra: Vec<Finding>,
}

/// One SNTP exchange (two tries) against `server`.
fn measure(server: &str) -> Result<sntp::Sample, String> {
    let addr = (server, 123)
        .to_socket_addrs()
        .map_err(|e| format!("can't resolve {server}: {e}"))?
        .next()
        .ok_or_else(|| format!("{server} has no address"))?;
    let socket = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|e| format!("can't open a UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    socket.connect(addr).map_err(|e| format!("can't reach {addr}: {e}"))?;

    let mut last_error = "no reply within 2 s (UDP 123 may be blocked on this network)".to_string();
    for _ in 0..2 {
        let t1 = now();
        let request = sntp::request(t1);
        if let Err(e) = socket.send(&request) {
            last_error = format!("can't send: {e}");
            continue;
        }
        let mut buf = [0u8; 256];
        // Skip a late reply to the previous attempt; it won't match this request.
        while let Ok(n) = socket.recv(&mut buf) {
            match sntp::parse_reply(&buf[..n], &request, t1, now()) {
                Err(e) if e.contains("match") => continue,
                other => return other,
            }
        }
    }
    Err(last_error)
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// First server in a W32Time `NtpServer` list ("time.example.org,0x9 pool.ntp.org,0x9").
#[cfg_attr(not(windows), allow(dead_code))]
fn first_ntp_server(list: &str) -> Option<String> {
    list.split_whitespace()
        .next()
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::win::domain::{join_info, logon_server, Join};
    use crate::win::registry::{read_string, HKLM};
    use crate::win::scm;

    pub fn source() -> Source {
        const PARAMS: &str = r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters";
        let kind = read_string(HKLM, PARAMS, "Type").unwrap_or_default();
        let ntp_list = read_string(HKLM, PARAMS, "NtpServer").unwrap_or_default();
        let joined = matches!(join_info(), Some(Join::Domain(_)));

        let mut extra = Vec::new();
        match scm::query("W32Time") {
            Ok(None) => extra.push(Finding::warn("Windows Time service", "not installed")),
            Ok(Some(s)) if !s.running && joined => extra.push(
                Finding::warn("Windows Time service", format!("{} · domain time sync needs it", s.state))
                    .with_action(offer("start-service", Some("W32Time"))),
            ),
            Ok(Some(s)) if !s.running => {
                extra.push(Finding::info("Windows Time service", format!("{} · starts on demand", s.state)))
            }
            Ok(Some(_)) => extra.push(Finding::ok("Windows Time service", "running")),
            Err(e) => extra.push(Finding::info("Windows Time service", e)),
        }

        let (finding, server) = match kind.to_ascii_uppercase().as_str() {
            "NT5DS" => {
                let dc = logon_server();
                let text = match &dc {
                    Some(d) => format!("domain hierarchy (signed in via {d})"),
                    None => "domain hierarchy".to_string(),
                };
                (Finding::ok("Time source", text), dc)
            }
            "NTP" | "ALLSYNC" => {
                let shown = if ntp_list.is_empty() { "no server set".to_string() } else { ntp_list.clone() };
                let severity = if ntp_list.is_empty() { Severity::Warning } else { Severity::Ok };
                (Finding::new("Time source", format!("NTP: {shown}"), severity), first_ntp_server(&ntp_list))
            }
            "NOSYNC" => (Finding::warn("Time source", "sync disabled (NoSync): the clock is free-running"), None),
            "" => (Finding::info("Time source", "not configured"), first_ntp_server(&ntp_list)),
            other => (Finding::info("Time source", other.to_string()), first_ntp_server(&ntp_list)),
        };
        let zone = read_string(HKLM, r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation", "TimeZoneKeyName");
        Source { finding, server, zone, extra }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::text::key_values;
    use crate::util::{capture, cmd, command_exists};

    pub fn source() -> Source {
        if !command_exists("timedatectl") {
            return Source {
                finding: Finding::info("Time source", "timedatectl not found (no systemd), sync state unknown"),
                server: None,
                zone: std::fs::read_to_string("/etc/timezone").ok().map(|s| s.trim().to_string()),
                extra: Vec::new(),
            };
        }
        let show = |args: &[&str]| {
            let mut c = cmd("timedatectl");
            c.args(args).env("LC_ALL", "C");
            capture(c).ok().filter(|o| o.success()).map(|o| o.stdout)
        };
        let kv = show(&["show"]).map(|s| key_values(&s)).unwrap_or_default();
        let finding = match (kv.get("NTP").map(String::as_str), kv.get("NTPSynchronized").map(String::as_str)) {
            (Some("no"), _) => Finding::warn("Time source", "network time sync is turned off (timedatectl set-ntp true)"),
            (_, Some("yes")) => Finding::ok("Time source", "NTP, synchronised"),
            (Some("yes"), Some("no")) => {
                Finding::warn("Time source", "NTP is on but not synchronised").with_action(offer("resync-time", None))
            }
            _ => Finding::info("Time source", "sync state unknown"),
        };
        let server = show(&["show-timesync", "--property=ServerName", "--value"])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(chrony_reference);
        Source {
            finding,
            server,
            zone: kv.get("Timezone").cloned().filter(|z| !z.is_empty()),
            extra: Vec::new(),
        }
    }

    /// The server chrony is following, from `chronyc -n -c tracking` (CSV;
    /// the second field is the reference's address).
    fn chrony_reference() -> Option<String> {
        if !command_exists("chronyc") {
            return None;
        }
        let mut c = cmd("chronyc");
        c.args(["-n", "-c", "tracking"]);
        let out = capture(c).ok().filter(|o| o.success())?;
        let field = out.stdout.lines().next()?.split(',').nth(1)?.trim().to_string();
        (!field.is_empty() && field != "0.0.0.0" && !field.starts_with("127.")).then_some(field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_first_w32time_server() {
        assert_eq!(first_ntp_server("time.example.org,0x9 pool.ntp.org,0x9").as_deref(), Some("time.example.org"));
        assert_eq!(first_ntp_server("10.0.0.1").as_deref(), Some("10.0.0.1"));
        assert_eq!(first_ntp_server("  "), None);
    }
}
