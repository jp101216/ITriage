//! Wired 802.1X and NAC quarantine. Read-only, Windows only.
//!
//! `net.wifi-auth` covers wireless; this is the wall jack behind ISE or
//! ClearPass. A PC that failed 802.1X gets no network or a guest VLAN; one
//! that failed a posture check lands in a remediation VLAN, where "the
//! network works but nothing loads". The Wired AutoConfig log says which;
//! the site profile's `[network] quarantine_subnets` says when an address
//! is in the remediation VLAN.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::wired::{self, Subnet, WiredEvent};

pub struct WiredAuthentication;

impl TriageModule for WiredAuthentication {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "net.wired-auth",
            "Wired 802.1X & NAC",
            Category::Network,
            "The wired 802.1X service, the last day's authentications and failures with their reasons, each wired port's state, and an address in one of the site's NAC quarantine subnets.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        Ok(assemble(&imp::gather(&ctx.profile().network.quarantine_subnets)?, crate::util::now_epoch()))
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("Wired 802.1X is checked on Windows (the Wired AutoConfig service).".into())
    }
}

/// What was read. Plain data, so the rows are tested on any OS.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// Wired AutoConfig: installed, running.
    pub service: Option<bool>,
    /// Connected wired adapters and their addresses.
    pub wired: Vec<(String, Vec<std::net::IpAddr>)>,
    /// The adapter the default route leaves by.
    pub route_via: Option<String>,
    pub events: Vec<WiredEvent>,
    pub events_error: Option<String>,
    /// `netsh lan show interfaces`: name and state, when it could be read.
    pub ports: Vec<(String, String)>,
    pub subnets: Vec<String>,
}

pub fn assemble(f: &Facts, now: u64) -> Output {
    let mut rows = Vec::new();
    let used = f.events.iter().any(|e| matches!(e.kind, wired::Kind::Succeeded | wired::Kind::Failed) || e.enabled == Some(true));
    // NAC quarantine first: it's the answer when it's there.
    let mut subnets = Vec::new();
    for s in &f.subnets {
        match Subnet::parse(s) {
            Ok(n) => subnets.push(n),
            Err(e) => rows.push(Finding::info("Quarantine subnet ignored", e)),
        }
    }
    for (adapter, ip, subnet) in wired::quarantined(&f.wired, &subnets) {
        rows.push(
            Finding::crit("NAC quarantine", format!("{adapter} has {ip}, in the quarantine subnet {subnet}"))
                .with_detail("NAC placed this PC in a remediation VLAN: check ISE or ClearPass for the posture failure (an out-of-date agent, antivirus, or patch level) before touching the PC's network settings."),
        );
    }
    match f.service {
        None => rows.push(Finding::info("Wired AutoConfig service", "not installed")),
        Some(true) => rows.push(Finding::ok("Wired AutoConfig service", "running")),
        Some(false) if used => rows.push(
            Finding::warn("Wired AutoConfig service", "stopped, but this PC used wired 802.1X in the last day")
                .with_detail("Without it, a port that requires 802.1X doesn't let the PC on (or puts it in a guest VLAN). Group Policy normally sets it to start automatically."),
        ),
        Some(false) => rows.push(Finding::info("Wired AutoConfig service", "stopped: this PC doesn't use wired 802.1X")),
    }
    if f.wired.is_empty() {
        rows.push(Finding::info(
            "Wired connection",
            match &f.route_via {
                Some(via) => format!("none connected; the network is reached through {via}"),
                None => "none connected".into(),
            },
        ));
    }
    match &f.events_error {
        Some(e) => rows.push(Finding::info("Wired 802.1X", format!("history not available: {e}"))),
        None => rows.extend(wired::findings(&f.events, now)),
    }
    for (name, state) in &f.ports {
        let lower = state.to_ascii_lowercase();
        let severity = if lower.contains("fail") { Severity::Warning } else { Severity::Info };
        rows.push(Finding::new(format!("{name}: 802.1X"), state.clone(), severity));
    }
    let attention = rows.iter().filter(|r| r.severity.rank() >= Severity::Warning.rank()).count();
    let summary = if let Some(q) = rows.iter().find(|r| r.label == "NAC quarantine") {
        format!("NAC quarantine: {}", q.value)
    } else if let Some(a) = rows.iter().find(|r| r.label == "Wired 802.1X") {
        format!("Wired 802.1X: {}", a.value)
    } else {
        format!("{attention} wired finding{} need{} attention", crate::util::plural(attention), if attention == 1 { "s" } else { "" })
    };
    Output::new(summary, rows)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::time::Duration;

    pub fn gather(subnets: &[String]) -> Result<Facts, String> {
        let mut f = Facts { subnets: subnets.to_vec(), ..Facts::default() };
        f.service = crate::win::scm::query("dot3svc")?.map(|s| s.running);
        let interfaces = crate::net::interfaces().unwrap_or_default();
        f.wired = interfaces
            .iter()
            .filter(|i| i.up && i.ethernet && i.addresses.iter().any(|a| crate::net::is_usable(a.ip)))
            .map(|i| (i.name.clone(), i.addresses.iter().map(|a| a.ip).filter(|ip| crate::net::is_usable(*ip)).collect()))
            .collect();
        f.route_via = crate::net::default_route().ok().and_then(|r| r.interface);
        const DAY: &str = "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]";
        match crate::win::eventlog::query_xml(wired::CHANNEL, DAY, 200) {
            Ok(rows) => f.events = rows.iter().filter_map(|x| wired::from_event(x)).collect(),
            Err(e) => f.events_error = Some(e),
        }
        if f.service == Some(true) {
            let mut c = crate::util::cmd("netsh");
            c.args(["lan", "show", "interfaces"]);
            if let Ok(out) = crate::util::capture_for(c, Duration::from_secs(10)) {
                f.ports = wired::netsh_interfaces(&out.stdout).unwrap_or_default();
            }
        }
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(at: u64) -> WiredEvent {
        WiredEvent {
            epoch: at,
            kind: wired::Kind::Failed,
            adapter: "Intel(R) Ethernet Connection I219-LM".into(),
            identity: "host/WS-07.corp.example.org".into(),
            reason_code: Some(0x50005),
            reason_text: "The authenticator is no longer present.".into(),
            error_code: None,
            peer: String::new(),
            block_seconds: None,
            enabled: None,
            eap: String::new(),
        }
    }

    #[test]
    fn quarantine_is_the_headline() {
        let f = Facts {
            service: Some(true),
            wired: vec![("Ethernet".into(), vec!["10.250.4.17".parse().unwrap()])],
            subnets: vec!["10.250.0.0/16".into(), "not a subnet".into()],
            ..Facts::default()
        };
        let out = assemble(&f, 1_794_600_000);
        assert_eq!(out.summary, "NAC quarantine: Ethernet has 10.250.4.17, in the quarantine subnet 10.250.0.0/16");
        assert!(out.findings.iter().any(|r| r.label == "Quarantine subnet ignored"));
        assert_eq!(out.findings.iter().find(|r| r.label == "NAC quarantine").unwrap().severity, Severity::Critical);
    }

    #[test]
    fn a_stopped_service_matters_only_when_802_1x_was_in_use() {
        let quiet = assemble(&Facts { service: Some(false), route_via: Some("Wi-Fi".into()), ..Facts::default() }, 0);
        assert_eq!(quiet.findings[0].severity, Severity::Info);
        assert_eq!(quiet.findings[1].value, "none connected; the network is reached through Wi-Fi");
        let used = assemble(&Facts { service: Some(false), events: vec![failed(100)], ..Facts::default() }, 400);
        assert_eq!(used.findings[0].severity, Severity::Warning);
        assert!(used.summary.starts_with("Wired 802.1X: failing: The authenticator is no longer present"));
        let ports = assemble(&Facts { service: Some(true), ports: vec![("Ethernet 3".into(), "Authentication failed".into())], ..Facts::default() }, 0);
        assert_eq!(ports.findings.iter().find(|r| r.label == "Ethernet 3: 802.1X").unwrap().severity, Severity::Warning);
    }
}
