//! Wired 802.1X: the Wired AutoConfig (dot3svc) event log, `netsh lan show
//! interfaces`, and NAC quarantine subnets.
//!
//! The event IDs and field names are the provider's own (its manifest, read
//! on a Windows Server 2025 runner): 15503 started, 15504 restarted, 15505
//! succeeded, 15514 failed (each of the last two with `Identity`,
//! `ReasonCode`, `ReasonText`, `ErrorCode`), 15506 suspended after failures
//! (`BlockingTime` seconds), 15500/15501 unplugged/connected, 15502 the
//! profile applied. The events are the source of truth; netsh's text is
//! localized, so it's only read for the interface state, and only in English.

use crate::model::Finding;
use crate::parse::time::epoch_to_rfc3339;
use crate::util::ago;
use std::net::IpAddr;

pub const CHANNEL: &str = "Microsoft-Windows-Wired-AutoConfig/Operational";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Started,
    Restarted,
    Succeeded,
    Failed,
    Suspended,
    Resumed,
    Unplugged,
    Connected,
    ProfileApplied,
}

impl Kind {
    pub fn from_id(id: u32) -> Option<Kind> {
        Some(match id {
            15503 => Kind::Started,
            15504 => Kind::Restarted,
            15505 => Kind::Succeeded,
            15514 => Kind::Failed,
            15506 => Kind::Suspended,
            15507 => Kind::Resumed,
            15500 => Kind::Unplugged,
            15501 => Kind::Connected,
            15502 => Kind::ProfileApplied,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WiredEvent {
    pub epoch: u64,
    pub kind: Kind,
    pub adapter: String,
    pub identity: String,
    pub reason_code: Option<u32>,
    pub reason_text: String,
    pub error_code: Option<u32>,
    /// The switch port's MAC, as Windows logs it.
    pub peer: String,
    pub block_seconds: Option<u32>,
    /// From a 15502: is 802.1X enabled in the applied profile, and its EAP type.
    pub enabled: Option<bool>,
    pub eap: String,
}

fn hex(value: &str) -> Option<u32> {
    let v = value.trim();
    let v = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).unwrap_or(v);
    u32::from_str_radix(v, 16).ok()
}

pub fn from_event(xml: &str) -> Option<WiredEvent> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    let kind = Kind::from_id(system.event_id)?;
    let epoch = system.time_created.as_deref().and_then(crate::parse::time::iso8601_utc_to_epoch)?;
    let data = crate::parse::evtxml::event_data(xml);
    let get = |name: &str| data.iter().find(|(k, _)| k == name).map(|(_, v)| v.trim().to_string()).unwrap_or_default();
    let content = get("ProfileContent");
    let line = |key: &str| content.lines().map(str::trim).find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()));
    Some(WiredEvent {
        epoch,
        kind,
        adapter: get("InterfaceDescription"),
        identity: get("Identity"),
        reason_code: hex(&get("ReasonCode")).filter(|c| *c != 0),
        reason_text: get("ReasonText"),
        error_code: hex(&get("ErrorCode")).filter(|c| *c != 0),
        peer: get("SwitchMAC"),
        block_seconds: get("BlockingTime").parse().ok(),
        enabled: content.lines().map(str::trim).find(|l| l.starts_with("802.1x: Enabled") || l.starts_with("802.1x: Disabled")).map(|l| l.ends_with("Enabled")),
        eap: line("EAP type:").unwrap_or_default(),
    })
}

/// Certificate errors an EAP-TLS or PEAP failure can carry: the HRESULTs
/// Windows' certificate chain engine uses.
fn certificate_error(code: u32) -> Option<&'static str> {
    Some(match code {
        0x8009_2010 => "the certificate is revoked",
        0x8009_2012 => "revocation couldn't be checked",
        0x8009_2013 => "the revocation server was offline",
        0x800B_0101 => "a certificate has expired",
        0x800B_0109 => "the root certificate isn't trusted",
        0x800B_010F => "the certificate's name doesn't match",
        _ => return None,
    })
}

impl WiredEvent {
    /// The reason in words: the event's own text, else a certificate error
    /// it names, else the codes.
    pub fn reason(&self) -> String {
        let cert = self.error_code.and_then(certificate_error);
        match (self.reason_text.is_empty(), cert) {
            (false, Some(c)) => format!("{} ({c})", self.reason_text.trim_end_matches('.')),
            (false, None) => self.reason_text.trim_end_matches('.').to_string(),
            (true, Some(c)) => c.to_string(),
            (true, None) => match (self.reason_code, self.error_code) {
                (Some(r), Some(e)) => format!("reason 0x{r:X}, error 0x{e:08X}"),
                (Some(r), None) => format!("reason 0x{r:X}"),
                (None, Some(e)) => format!("error 0x{e:08X}"),
                (None, None) => "no reason given".into(),
            },
        }
    }

    /// Did a certificate stop it? Either the code or the text says so.
    pub fn certificate(&self) -> bool {
        self.error_code.and_then(certificate_error).is_some() || self.reason_text.to_ascii_lowercase().contains("certificate")
    }
}

/// `netsh lan show interfaces` (English): each interface's name and state.
/// "The Wired AutoConfig Service (dot3svc) is not running." gives `Err`.
pub fn netsh_interfaces(text: &str) -> Result<Vec<(String, String)>, String> {
    if text.contains("(dot3svc) is not running") {
        return Err("the Wired AutoConfig service isn't running".into());
    }
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        match key.trim() {
            "Name" => name = Some(value.trim().to_string()),
            "State" => {
                if let Some(n) = name.take() {
                    out.push((n, value.trim().to_string()));
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// An address/prefix from the profile (`10.250.0.0/16`, `fd00:250::/48`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    pub network: IpAddr,
    pub prefix: u8,
}

impl Subnet {
    pub fn parse(text: &str) -> Result<Subnet, String> {
        let (ip, prefix) = text.trim().split_once('/').ok_or_else(|| format!("`{text}` needs a prefix length, like 10.250.0.0/16"))?;
        let network: IpAddr = ip.trim().parse().map_err(|_| format!("`{ip}` isn't an IP address"))?;
        let prefix: u8 = prefix.trim().parse().map_err(|_| format!("`{prefix}` isn't a prefix length"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("/{prefix} is longer than an address"));
        }
        Ok(Subnet { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let bits = |n: u128, len: u32, prefix: u8| if prefix == 0 { 0 } else { n >> (len - u32::from(prefix)) };
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => bits(u32::from(n).into(), 32, self.prefix) == bits(u32::from(a).into(), 32, self.prefix),
            (IpAddr::V6(n), IpAddr::V6(a)) => bits(u128::from(n), 128, self.prefix) == bits(u128::from(a), 128, self.prefix),
            _ => false,
        }
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Wired addresses that fall in a quarantine subnet: (adapter, address, subnet).
pub fn quarantined(wired: &[(String, Vec<IpAddr>)], subnets: &[Subnet]) -> Vec<(String, IpAddr, Subnet)> {
    let mut out = Vec::new();
    for (name, addresses) in wired {
        for ip in addresses {
            if let Some(s) = subnets.iter().find(|s| s.contains(*ip)) {
                out.push((name.clone(), *ip, *s));
            }
        }
    }
    out
}

/// The 802.1X rows from a day of events, newest first or not.
pub fn findings(events: &[WiredEvent], now: u64) -> Vec<Finding> {
    let mut events: Vec<&WiredEvent> = events.iter().collect();
    events.sort_by_key(|e| e.epoch);
    let outcomes: Vec<&&WiredEvent> = events.iter().filter(|e| matches!(e.kind, Kind::Succeeded | Kind::Failed)).collect();
    let failures: Vec<&&WiredEvent> = outcomes.iter().copied().filter(|e| e.kind == Kind::Failed).collect();
    let mut out = Vec::new();
    match outcomes.last() {
        None => {
            let profile = events.iter().rev().find(|e| e.kind == Kind::ProfileApplied);
            out.push(match profile.and_then(|p| p.enabled) {
                Some(true) => Finding::info("Wired 802.1X", format!("enabled ({}), no authentication in the last 24 h", profile.map(|p| p.eap.as_str()).filter(|e| !e.is_empty()).unwrap_or("EAP")))
                    .with_detail("The port may not ask for 802.1X (no NAC on this switch port), or the cable hasn't been reconnected since the log was cleared."),
                _ => Finding::info("Wired 802.1X", "no authentication in the last 24 h"),
            });
        }
        Some(last) if last.kind == Kind::Succeeded => {
            let who = if last.identity.is_empty() { String::new() } else { format!(" as {}", last.identity) };
            let mut row = Finding::ok("Wired 802.1X", format!("authenticated{who} · {}", ago(now.saturating_sub(last.epoch))));
            if !failures.is_empty() {
                let latest = failures.last().unwrap();
                row = Finding::warn(
                    "Wired 802.1X",
                    format!("authenticated{who} {}, after {} failure{} in 24 h", ago(now.saturating_sub(last.epoch)), failures.len(), if failures.len() == 1 { "" } else { "s" }),
                )
                .with_detail(format!("Last failure: {} UTC, {}.", epoch_to_rfc3339(latest.epoch), latest.reason()));
            }
            out.push(row.with_metric(failures.len() as f64, "failures", true));
        }
        Some(last) => {
            let since_success = outcomes.iter().rev().take_while(|e| e.kind == Kind::Failed).count();
            out.push(
                Finding::crit(
                    "Wired 802.1X",
                    format!(
                        "failing: {} · {} in a row, last {}",
                        last.reason(),
                        if since_success == 1 { "once".to_string() } else { format!("{since_success} times") },
                        ago(now.saturating_sub(last.epoch))
                    ),
                )
                .with_detail(format!(
                    "{} on {}{}{}. Microsoft-Windows-Wired-AutoConfig/Operational event 15514.",
                    epoch_to_rfc3339(last.epoch),
                    if last.adapter.is_empty() { "the wired adapter" } else { &last.adapter },
                    if last.identity.is_empty() { String::new() } else { format!(", identity {}", last.identity) },
                    if last.peer.is_empty() { String::new() } else { format!(", switch {}", last.peer) },
                ))
                .with_metric(failures.len() as f64, "failures", true),
            );
        }
    }
    // Suspended after failures, and not resumed or succeeded since.
    if let Some(s) = events.iter().rev().find(|e| e.kind == Kind::Suspended) {
        let cleared = events.iter().any(|e| e.epoch >= s.epoch && matches!(e.kind, Kind::Resumed | Kind::Succeeded) && !std::ptr::eq(*e, *s));
        if !cleared {
            out.push(
                Finding::warn(
                    "Wired 802.1X attempts",
                    format!("suspended {}{}", ago(now.saturating_sub(s.epoch)), s.block_seconds.map(|b| format!(" for {b} s")).unwrap_or_default()),
                )
                .with_detail("Windows stops trying for a while after repeated failures (event 15506). Reconnecting the cable starts it again."),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    const NOW: u64 = 1_794_600_000;

    fn event(id: u32, at: u64, fields: &[(&str, &str)]) -> String {
        let data: String = fields.iter().map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>")).collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Wired-AutoConfig' Guid='{{b92cf7fd-dc10-4c6b-a72d-1613bf25e597}}'/><EventID>{id}</EventID><Version>0</Version><Level>{}</Level><TimeCreated SystemTime='{}'/><Channel>{CHANNEL}</Channel><Computer>WS-07</Computer></System><EventData>{data}</EventData></Event>",
            if id == 15514 { 2 } else { 4 },
            crate::parse::time::epoch_to_rfc3339(at)
        )
    }

    fn outcome(id: u32, at: u64, reason: &str, error: &str) -> WiredEvent {
        from_event(&event(
            id,
            at,
            &[
                ("InterfaceGuid", "{60be424d-bb22-49da-a96e-746348f840a8}"),
                ("InterfaceDescription", "Intel(R) Ethernet Connection (16) I219-LM"),
                ("SwitchMAC", "00:1A:2B:3C:4D:5E"),
                ("LocalMAC", "E4:FA:DE:4A:13:99"),
                ("ConnectionID", "0x5"),
                ("Identity", "host/WS-07.corp.example.org"),
                ("User", ""),
                ("Domain", ""),
                ("ReasonCode", if id == 15505 { "0x0" } else { "0x50005" }),
                ("ReasonText", reason),
                ("ErrorCode", error),
                ("ExplicitCredentials", "false"),
            ],
        ))
        .unwrap()
    }

    #[test]
    fn reads_the_real_profile_event_and_the_manifest_fields() {
        let real = from_event(include_str!("fixtures/wired-15502.xml")).unwrap();
        assert_eq!((real.kind, real.enabled, real.eap.as_str(), real.adapter.as_str()), (Kind::ProfileApplied, Some(true), "Microsoft: Protected EAP (PEAP)", "Hyper-V Virtual Ethernet Adapter"));
        let failed = outcome(15514, NOW - 600, "The authenticator is no longer present.", "0x80092013");
        assert_eq!(failed.reason(), "The authenticator is no longer present (the revocation server was offline)");
        assert!(failed.certificate());
        assert_eq!(failed.reason_code, Some(0x50005));
        let bare = WiredEvent { reason_text: String::new(), error_code: Some(0x80420014), ..failed.clone() };
        assert_eq!(bare.reason(), "reason 0x50005, error 0x80420014");
        assert!(!bare.certificate());
    }

    #[test]
    fn grades_the_latest_outcome() {
        let fail = |at| outcome(15514, at, "The network does not support authentication.", "0x0");
        let ok = |at| outcome(15505, at, "", "0x0");
        let rows = findings(&[fail(NOW - 900), ok(NOW - 3_600), fail(NOW - 300)], NOW);
        assert_eq!(rows[0].severity, Severity::Critical);
        assert_eq!(rows[0].value, "failing: The network does not support authentication · 2 times in a row, last 5m ago");
        assert!(rows[0].detail.as_deref().unwrap().contains("identity host/WS-07.corp.example.org, switch 00:1A:2B:3C:4D:5E"));
        let recovered = findings(&[fail(NOW - 900), ok(NOW - 60)], NOW);
        assert_eq!((recovered[0].severity, recovered[0].value.as_str()), (Severity::Warning, "authenticated as host/WS-07.corp.example.org 1m ago, after 1 failure in 24 h"));
        let clean = findings(&[ok(NOW - 60)], NOW);
        assert_eq!(clean[0].severity, Severity::Ok);
        let profile = from_event(include_str!("fixtures/wired-15502.xml")).unwrap();
        assert_eq!(findings(&[profile], NOW)[0].value, "enabled (Microsoft: Protected EAP (PEAP)), no authentication in the last 24 h");
        assert_eq!(findings(&[], NOW)[0].value, "no authentication in the last 24 h");
    }

    #[test]
    fn a_suspension_shows_until_it_clears() {
        let fail = outcome(15514, NOW - 400, "", "0x0");
        let suspended = from_event(&event(15506, NOW - 390, &[("InterfaceDescription", "Ethernet"), ("ReasonCode", "0x50005"), ("BlockingTime", "60")])).unwrap();
        let rows = findings(&[fail.clone(), suspended.clone()], NOW);
        assert_eq!(rows[1].value, "suspended 6m ago for 60 s");
        let resumed = from_event(&event(15507, NOW - 300, &[("InterfaceDescription", "Ethernet")])).unwrap();
        assert_eq!(findings(&[fail, suspended, resumed], NOW).len(), 1);
    }

    #[test]
    fn reads_real_netsh_output() {
        assert_eq!(netsh_interfaces(include_str!("fixtures/netsh-lan-interfaces.txt")).unwrap(), vec![("Ethernet 3".to_string(), "Attempting to authenticate".to_string())]);
        assert!(netsh_interfaces(include_str!("fixtures/netsh-lan-no-interface.txt")).unwrap().is_empty());
        assert!(netsh_interfaces(include_str!("fixtures/netsh-lan-not-running.txt")).is_err());
    }

    #[test]
    fn subnets_contain_what_they_should() {
        let q = Subnet::parse("10.250.0.0/16").unwrap();
        assert!(q.contains("10.250.4.17".parse().unwrap()));
        assert!(!q.contains("10.251.0.1".parse().unwrap()));
        assert!(!q.contains("fd00::1".parse().unwrap()));
        assert!(Subnet::parse("0.0.0.0/0").unwrap().contains("192.0.2.1".parse().unwrap()));
        assert!(Subnet::parse("fd00:250::/48").unwrap().contains("fd00:250::abcd".parse().unwrap()));
        assert!(Subnet::parse("10.250.0.0").is_err() && Subnet::parse("10.250.0.0/33").is_err() && Subnet::parse("ward/8").is_err());
        let hits = quarantined(&[("Ethernet".into(), vec!["10.250.4.17".parse().unwrap()]), ("Wi-Fi".into(), vec![])], &[q]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2.to_string(), "10.250.0.0/16");
    }
}
