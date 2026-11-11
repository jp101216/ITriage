//! Wireless/wired authentication event history, with reason codes as
//! evidence, and the Wi-Fi link as it is right now (for recordings). These
//! checks never enable tracing or alter the connection.
use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use serde::{Deserialize, Serialize};

/// Event rows kept in a report.
const MAX_ROWS: usize = 80;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessEvent {
    /// UTC, to the second.
    pub at: String,
    pub channel: String,
    pub event_id: u32,
    pub level: u8,
    /// What happened, in a sentence.
    pub summary: String,
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

/// The short name a channel's rows go by: "Wi-Fi 8001" reads better beside
/// a time than "Microsoft-Windows-WLAN-AutoConfig/Operational 8001".
fn short_channel(channel: &str) -> &'static str {
    let c = channel.to_ascii_lowercase();
    if c.contains("wlan") {
        "Wi-Fi"
    } else if c.contains("wired") {
        "Wired 802.1X"
    } else if c.contains("eap") {
        "EAP"
    } else if c.contains("capi2") {
        "Certificates"
    } else {
        "Network"
    }
}

/// The events worth naming when Windows has no message text for them, and
/// whether each one is a failure whatever level it was logged at.
fn known(channel: &str, event_id: u32) -> Option<(&'static str, bool)> {
    if !channel.to_ascii_lowercase().contains("wlan") {
        return None;
    }
    Some(match event_id {
        8000 => ("Connection started", false),
        8001 => ("Connected", false),
        8002 => ("Failed to connect", true),
        8003 => ("Disconnected", false),
        11000 => ("Association started", false),
        11001 => ("Association succeeded", false),
        11002 => ("Association failed", true),
        11004 => ("Securing the connection: finished setting up", false),
        11005 => ("Wireless security succeeded", false),
        11006 => ("Wireless security failed", true),
        11010 => ("Wireless security started", false),
        12011 => ("802.1X authentication started", false),
        12012 => ("802.1X authentication succeeded", false),
        12013 => ("802.1X authentication failed", true),
        _ => return None,
    })
}

pub fn from_event(channel: &str, xml: &str, message: Option<&str>) -> Option<WirelessEvent> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    let at = system.time_created.as_deref().and_then(crate::parse::time::iso8601_utc_to_epoch).map(crate::parse::time::epoch_to_rfc3339)?;
    let details: Vec<(String, String)> = crate::parse::evtxml::event_data(xml)
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
    // The first line of the message is the sentence; the rest repeats the
    // fields, and can name things the list above deliberately leaves out.
    let first_line = message
        .map(|m| m.replace(['\u{200e}', '\u{200f}'], ""))
        .and_then(|m| m.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| l.chars().take(200).collect::<String>()));
    let summary = first_line
        .or_else(|| known(channel, system.event_id).map(|(text, _)| text.to_string()))
        .unwrap_or_else(|| format!("{} event {}", system.provider, system.event_id));
    Some(WirelessEvent {
        at,
        channel: channel.into(),
        event_id: system.event_id,
        level: system.level,
        summary,
        details,
    })
}

pub fn summarize(events: &[WirelessEvent]) -> Vec<Finding> {
    let mut out = Vec::new();
    let wlan = |e: &&WirelessEvent, id: u32| e.event_id == id && e.channel.to_ascii_lowercase().contains("wlan");
    let associations = events.iter().filter(|e| wlan(e, 8001)).count();
    let disconnects = events.iter().filter(|e| wlan(e, 8003)).count();
    let failed = |e: &WirelessEvent| matches!(e.level, 1 | 2) || known(&e.channel, e.event_id).is_some_and(|(_, bad)| bad);
    let failures = events.iter().filter(|e| failed(e)).count();
    out.push(
        Finding::new(
            "Wireless session history (collected events)",
            format!(
                "{associations} successful association(s), {disconnects} disconnect(s){}",
                if failures > 0 { format!(", {failures} failure(s)") } else { String::new() }
            ),
            if failures > 0 { Severity::Warning } else { Severity::Info },
        )
        .with_detail("An association or a disconnect alone does not prove a roam or a fault. Compare access-point identifiers and the problem's time."),
    );
    for e in events.iter().take(MAX_ROWS) {
        let fields = e.details.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(" · ");
        out.push(
            Finding::new(
                format!("{} · {} {}", e.at, short_channel(&e.channel), e.event_id),
                &e.summary,
                if failed(e) { Severity::Warning } else { Severity::Info },
            )
            .with_detail(if fields.is_empty() {
                format!("{} · No reason fields in this event; open it in Event Viewer for more.", e.channel)
            } else {
                format!("{} · {fields}", e.channel)
            }),
        );
    }
    out
}

#[cfg(windows)]
fn platform() -> Result<Output, String> {
    const DAY: &str = "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]";
    // When someone has switched the CAPI2 log on, it records every
    // certificate check on the PC: only the ones that failed are evidence.
    const DAY_FAILURES: &str = "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
    let mut events = Vec::new();
    let mut gaps = Vec::new();
    for (channel, query) in [
        ("Microsoft-Windows-WLAN-AutoConfig/Operational", DAY),
        ("Microsoft-Windows-Wired-AutoConfig/Operational", DAY),
        ("Microsoft-Windows-EapHost/Operational", DAY),
        ("Microsoft-Windows-CAPI2/Operational", DAY_FAILURES),
    ] {
        match crate::win::eventlog::query_rendered(channel, query, 40) {
            Ok(rows) => events.extend(rows.iter().filter_map(|r| from_event(channel, &r.xml, r.message.as_deref()))),
            Err(e) => gaps.push(Finding::info(channel, format!("not available: {e}"))),
        }
    }
    events.sort_by(|a, b| b.at.cmp(&a.at));
    let mut findings = summarize(&events);
    findings.extend(gaps);
    findings.push(Finding::info(
        "Collection scope",
        "Up to 40 recent events per channel from the last 24 hours (certificate events: failures only); only 80 event rows are summarized. Existing logs only. A disabled or inaccessible channel is a gap, not a successful authentication check.",
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
        // A row without a time can't be placed on a timeline: leave it out.
        let Some(at) = v["__REALTIME_TIMESTAMP"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|s| crate::parse::time::epoch_to_rfc3339(s / 1_000_000))
        else {
            continue;
        };
        let unit = v["_SYSTEMD_UNIT"].as_str().unwrap_or("journal").trim_end_matches(".service");
        let priority = v["PRIORITY"].as_str().and_then(|s| s.parse::<u8>().ok()).unwrap_or(6);
        rows.push(Finding::new(
            format!("{at} · {unit}"),
            message.chars().take(700).collect::<String>(),
            if priority <= 3 { Severity::Warning } else { Severity::Info },
        ));
    }
    // Newest first, like every other event list.
    rows.reverse();
    rows.truncate(MAX_ROWS);
    let events = rows.len();
    if rows.is_empty() {
        rows.push(Finding::info(
            "Network authentication history",
            "No matching events visible; journal permissions and enabled logging determine coverage.",
        ));
    }
    Ok(Output::new(format!("{events} recent network-authentication event(s)"), rows))
}

/// The Wi-Fi link right now.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WifiState {
    pub ssid: Option<String>,
    /// The access point's address. A different one on the same network
    /// means the PC roamed.
    pub bssid: Option<String>,
    /// 0–100.
    pub signal: Option<u32>,
}

impl WifiState {
    pub fn connected(&self) -> bool {
        self.ssid.is_some() || self.bssid.is_some() || self.signal.is_some()
    }

    pub fn describe(&self) -> String {
        if !self.connected() {
            return "not connected".into();
        }
        let mut parts = vec![self.ssid.clone().unwrap_or_else(|| "network name hidden".into())];
        if let Some(signal) = self.signal {
            parts.push(format!("signal {signal}%"));
        }
        if let Some(ap) = &self.bssid {
            parts.push(format!("AP {ap}"));
        }
        parts.join(" · ")
    }
}

/// The connected Wi-Fi link (or a "not connected" state), or `None` when
/// this PC has no Wi-Fi to ask about, or no tool that will say.
pub fn state() -> Option<WifiState> {
    #[cfg(windows)]
    {
        let all = crate::win::wlan::interfaces().ok()?;
        if all.is_empty() {
            return None;
        }
        Some(
            all.into_iter()
                .find(|i| i.connected)
                .map(|i| WifiState {
                    ssid: i.ssid,
                    bssid: i.bssid,
                    signal: i.signal,
                })
                .unwrap_or_default(),
        )
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
        let out = capture_for(c, std::time::Duration::from_millis(600)).ok().filter(|o| o.success())?;
        Some(nmcli_in_use(&out.stdout))
    }
}

/// The network in use from `nmcli -t -f IN-USE,SSID,SIGNAL,BSSID device wifi list`.
#[cfg_attr(windows, allow(dead_code))]
fn nmcli_in_use(out: &str) -> WifiState {
    out.lines()
        .map(crate::parse::net::nmcli_fields)
        .find(|f| f.len() >= 4 && f[0] == "*")
        .map(|f| WifiState {
            ssid: (!f[1].is_empty()).then(|| f[1].clone()),
            signal: f[2].parse().ok(),
            bssid: (!f[3].is_empty()).then(|| f[3].to_ascii_lowercase()),
        })
        .unwrap_or_default()
}

/// The link as one line of text, for older callers and for display.
pub fn snapshot() -> Option<String> {
    state().map(|s| s.describe())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_reasons_survive_without_collecting_secrets() {
        let xml = "<Event><System><Provider Name='WLAN'/><EventID>8002</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-10T12:00:00.1234567Z'/></System><EventData><Data Name='ReasonCode'>23</Data><Data Name='SSID'>Corp</Data><Data Name='Password'>secret</Data></EventData></Event>";
        let event = from_event("WLAN", xml, None).unwrap();
        assert_eq!(event.details.len(), 2);
        assert_eq!(event.at, "2026-11-10T12:00:00Z", "times are whole seconds, whatever Windows wrote");
        let findings = summarize(&[event]);
        assert_eq!(findings[1].severity, Severity::Warning);
        assert!(!serde_json::to_string(&findings).unwrap().contains("secret"));
    }

    #[test]
    fn rows_say_what_happened_in_words() {
        let event = |id: u32, level: u8| {
            format!("<Event><System><Provider Name='Microsoft-Windows-WLAN-AutoConfig'/><EventID>{id}</EventID><Level>{level}</Level><TimeCreated SystemTime='2026-11-10T12:00:0{}Z'/></System><EventData><Data Name='SSID'>Corp</Data></EventData></Event>", id % 10)
        };
        const WLAN: &str = "Microsoft-Windows-WLAN-AutoConfig/Operational";
        let events = vec![
            // Windows' own sentence when it has one, without the field list under it.
            from_event(WLAN, &event(8001, 4), Some("WLAN AutoConfig service has successfully connected to a wireless network.\r\n\r\nNetwork Adapter: Intel(R) Wi-Fi 6E AX211\r\nSSID: Corp")).unwrap(),
            from_event(WLAN, &event(8003, 4), None).unwrap(),
            // A failure counts as one even when it was logged as information.
            from_event(WLAN, &event(12013, 4), None).unwrap(),
        ];
        let rows = summarize(&events);
        assert_eq!(rows[0].value, "1 successful association(s), 1 disconnect(s), 1 failure(s)");
        assert_eq!(rows[0].severity, Severity::Warning);
        assert_eq!(rows[1].label, "2026-11-10T12:00:01Z · Wi-Fi 8001");
        assert_eq!(rows[1].value, "WLAN AutoConfig service has successfully connected to a wireless network.");
        assert_eq!(rows[2].value, "Disconnected");
        assert_eq!((rows[3].value.as_str(), rows[3].severity), ("802.1X authentication failed", Severity::Warning));
        assert!(rows[1].detail.as_deref().unwrap().contains("SSID: Corp"));
        assert_eq!(short_channel("Microsoft-Windows-CAPI2/Operational"), "Certificates");
    }

    #[test]
    fn reads_the_network_in_use_and_its_access_point() {
        let out = " :Guest:40:11\\:22\\:33\\:44\\:55\\:66\n*:Corp\\:Staff:72:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n";
        let state = nmcli_in_use(out);
        assert_eq!(state.ssid.as_deref(), Some("Corp:Staff"));
        assert_eq!(state.signal, Some(72));
        assert_eq!(state.bssid.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(state.describe(), "Corp:Staff · signal 72% · AP aa:bb:cc:dd:ee:ff");
        assert_eq!(nmcli_in_use("").describe(), "not connected");
    }
}
