//! Wireless/wired authentication event history, with reason codes as
//! evidence. These checks never enable tracing or alter the connection.
use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessEvent {
    pub at: String,
    pub channel: String,
    pub event_id: u32,
    pub level: u8,
    pub details: Vec<(String, String)>,
}

pub struct WirelessAuthentication;
impl TriageModule for WirelessAuthentication {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "net.wifi-auth",
            "Wi-Fi roaming & network authentication",
            Category::Network,
            "Recent Wi-Fi associations, disconnects, 802.1X and certificate-validation events, including wired authentication.",
        )
    }
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        platform()
    }
}

pub fn from_xml(channel: &str, xml: &str) -> Option<WirelessEvent> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    let fields = crate::parse::evtxml::event_data(xml)
        .into_iter()
        .filter(|(key, _)| {
            let k = key.to_ascii_lowercase();
            [
                "reason",
                "ssid",
                "bssid",
                "profile",
                "interface",
                "eap",
                "error",
                "status",
                "connectionmode",
                "authentication",
                "result",
                "subject",
                "issuer",
            ]
            .iter()
            .any(|s| k.contains(s))
        })
        .map(|(k, v)| (k, v.chars().take(400).collect()))
        .take(12)
        .collect();
    Some(WirelessEvent {
        at: system.time_created?,
        channel: channel.into(),
        event_id: system.event_id,
        level: system.level,
        details: fields,
    })
}

pub fn summarize(events: &[WirelessEvent]) -> Vec<Finding> {
    let mut out = Vec::new();
    let associations = events.iter().filter(|e| e.event_id == 8001 && e.channel.contains("WLAN")).count();
    let disconnects = events.iter().filter(|e| e.event_id == 8003 && e.channel.contains("WLAN")).count();
    out.push(Finding::info("Wireless session history (collected events)", format!("{associations} successful association(s), {disconnects} disconnect(s)"))
        .with_detail("An association or a disconnect alone does not prove a roam or a fault. Compare access-point identifiers and the problem's time."));
    for e in events.iter().take(80) {
        let severity = match e.level {
            1 | 2 => Severity::Warning,
            _ => Severity::Info,
        };
        out.push(
            Finding::new(
                format!("{} · {} {}", e.at, e.channel, e.event_id),
                if e.details.is_empty() {
                    "No summarized reason fields in this event; inspect the source event for additional detail.".into()
                } else {
                    e.details.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(" · ")
                },
                severity,
            )
            .with_detail("A certificate event must match the same time and connection before it can explain an authentication failure."),
        );
    }
    out
}

#[cfg(windows)]
fn platform() -> Result<Output, String> {
    const QUERY: &str = "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]";
    let mut events = Vec::new();
    let mut gaps = Vec::new();
    for channel in [
        "Microsoft-Windows-WLAN-AutoConfig/Operational",
        "Microsoft-Windows-Wired-AutoConfig/Operational",
        "Microsoft-Windows-EapHost/Operational",
        "Microsoft-Windows-CAPI2/Operational",
    ] {
        match crate::win::eventlog::query_xml(channel, QUERY, 40) {
            Ok(xml) => events.extend(xml.iter().filter_map(|x| from_xml(channel, x))),
            Err(e) => gaps.push(Finding::info(channel, format!("not available: {e}"))),
        }
    }
    events.sort_by(|a, b| b.at.cmp(&a.at));
    let mut findings = summarize(&events);
    findings.extend(gaps);
    findings.push(Finding::info(
        "Collection scope",
        "Up to 40 recent events per channel from the last 24 hours; only 80 event rows are summarized. Existing logs only. A disabled or inaccessible channel is a gap, not a successful authentication check.",
    ));
    Ok(Output::new(
        format!("{} recent network-authentication event(s)", events.len()),
        findings,
    ))
}

#[cfg(not(windows))]
fn platform() -> Result<Output, String> {
    use crate::util::{capture_for, cmd, command_exists};
    if !command_exists("journalctl") {
        return Err("journalctl isn't available for NetworkManager / supplicant history.".into());
    }
    let mut c = cmd("journalctl");
    c.args([
        "--since",
        "24 hours ago",
        "--no-pager",
        "-o",
        "json",
        "-n",
        "160",
        "-u",
        "NetworkManager",
        "-u",
        "wpa_supplicant",
    ])
    .env("LC_ALL", "C");
    let out = capture_for(c, std::time::Duration::from_secs(5))?;
    if !out.success() {
        return Err("NetworkManager history couldn't be read; journal permissions may be required.".into());
    }
    let mut rows = Vec::new();
    for line in out.stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let message = v["MESSAGE"].as_str().unwrap_or_default();
        if !["auth", "roam", "disconnect", "supplicant", "certificate", "reason"]
            .iter()
            .any(|s| message.to_ascii_lowercase().contains(s))
        {
            continue;
        }
        let at = v["__REALTIME_TIMESTAMP"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|s| crate::parse::time::epoch_to_rfc3339(s / 1_000_000))
            .unwrap_or_default();
        let priority = v["PRIORITY"].as_str().and_then(|s| s.parse::<u8>().ok()).unwrap_or(6);
        rows.push(Finding::new(
            at,
            message.chars().take(700).collect::<String>(),
            if priority <= 3 { Severity::Warning } else { Severity::Info },
        ));
    }
    if rows.is_empty() {
        rows.push(Finding::info(
            "Network authentication history",
            "No matching events visible; journal permissions and enabled logging determine coverage.",
        ));
    }
    Ok(Output::new(format!("{} network history finding(s)", rows.len()), rows))
}

pub fn snapshot() -> Option<String> {
    #[cfg(windows)]
    {
        crate::win::wlan::interfaces().ok().map(|items| {
            items
                .into_iter()
                .map(|i| {
                    format!(
                        "{} · {} · signal {}",
                        i.adapter,
                        i.ssid.as_deref().unwrap_or("disconnected"),
                        i.signal.map(|n| n.to_string()).unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
    }
    #[cfg(not(windows))]
    {
        use crate::util::{capture_for, cmd, command_exists};
        if !command_exists("nmcli") {
            return None;
        }
        let mut c = cmd("nmcli");
        c.args(["-t", "-f", "IN-USE,SSID,SIGNAL,BSSID", "device", "wifi", "list", "--rescan", "no"])
            .env("LC_ALL", "C");
        capture_for(c, std::time::Duration::from_millis(600))
            .ok()
            .filter(|o| o.success())
            .map(|o| {
                o.stdout
                    .lines()
                    .find(|l| l.starts_with('*'))
                    .unwrap_or("no active Wi-Fi listed")
                    .chars()
                    .take(300)
                    .collect()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_reasons_survive_without_collecting_secrets() {
        let xml = "<Event><System><Provider Name='WLAN'/><EventID>8002</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-10T12:00:00Z'/></System><EventData><Data Name='ReasonCode'>23</Data><Data Name='SSID'>Corp</Data><Data Name='Password'>secret</Data></EventData></Event>";
        let event = from_xml("WLAN", xml).unwrap();
        assert_eq!(event.details.len(), 2);
        let findings = summarize(&[event]);
        assert_eq!(findings[1].severity, Severity::Warning);
        assert!(!serde_json::to_string(&findings).unwrap().contains("secret"));
    }
}
