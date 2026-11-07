//! Wi-Fi & VPN. Read-only.
//!
//! The connected network, signal quality (graded against the site profile's
//! thresholds, Invoke-NetTriage's 70% / 50% by default: carts that roam a
//! ward drop their sessions on weak signal), the security in use (802.1X or
//! not), radio, channel and link rates.
//!
//! VPN evidence is gathered the way NetTriage does it: whether the Cisco
//! Secure Client or Zscaler client is running (its services or processes),
//! and which tunnel adapters are up with a usable address. Each reads as
//! "Tunnel interface active", "Client running - tunnel unverified" or "VPN
//! interface active", with the tunnel's addresses.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::net::{self, Interface};
use crate::parse::net::{is_tunnel_interface, is_vpn_adapter, signal_grade, vpn_client};
use crate::profile::Band;

pub struct WifiVpn;

impl TriageModule for WifiVpn {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.wifi",
            "Wi-Fi & VPN",
            Category::Workstation,
            "The connected Wi-Fi network, signal strength (warns at 70%), security (802.1X or not), radio and link rate, and VPN client and tunnel evidence.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let band = ctx.profile().thresholds.wifi_signal_pct;
        let (mut findings, wifi_summary) = imp::wifi(band);
        let (vpn, vpn_summary) = vpn_evidence();
        findings.extend(vpn);
        let summary = match vpn_summary {
            Some(v) => format!("{wifi_summary} · {v}"),
            None => wifi_summary,
        };
        Ok(Output::new(summary, findings))
    }
}

/// The signal row and its summary word.
fn signal_finding(quality: u32, band: Band) -> (Finding, &'static str) {
    let (grade, _) = signal_grade(quality);
    let severity = band.low(f64::from(quality));
    let mut f = Finding::new("Signal", format!("{quality}% · {grade}"), severity)
        .with_metric(f64::from(quality), "%", false);
    if severity.rank() >= Severity::Warning.rank() {
        f = f.with_detail("Weak signal drops remote sessions as the device moves. Note where it happens for the network team.");
    }
    (f, grade)
}

/// A VPN client NetTriage looks for by name.
struct Client {
    name: &'static str,
    services: &'static [&'static str],
    processes: &'static [&'static str],
    adapter: fn(&str) -> bool,
}

const CLIENTS: [Client; 2] = [
    Client {
        name: "Cisco Secure Client",
        services: &["vpnagent"],
        processes: &["vpnui", "vpnagent", "vpnagentd"],
        adapter: |d| {
            let d = d.to_ascii_lowercase();
            d.contains("anyconnect") || (d.contains("cisco") && d.contains("secure client")) || d.starts_with("cscotun")
        },
    },
    Client {
        name: "Zscaler",
        services: &["ZSATunnel", "ZSAService"],
        processes: &["zsatunnel", "zsaservice", "zstunnel"],
        adapter: |d| d.to_ascii_lowercase().contains("zscaler"),
    },
];

/// Running process names, lowercased, without `.exe`.
fn process_names() -> Vec<String> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    sys.processes()
        .values()
        .map(|p| {
            let n = p.name().to_string_lossy().to_ascii_lowercase();
            n.strip_suffix(".exe").map(str::to_string).unwrap_or(n)
        })
        .collect()
}

/// Is this interface a VPN tunnel?
fn is_tunnel(i: &Interface) -> bool {
    if cfg!(windows) {
        is_vpn_adapter(&i.description)
    } else {
        is_tunnel_interface(&i.name)
    }
}

fn vpn_evidence() -> (Vec<Finding>, Option<String>) {
    let procs = process_names();
    let running: Vec<bool> = CLIENTS
        .iter()
        .map(|c| {
            imp::any_service_running(c.services) || c.processes.iter().any(|p| procs.iter().any(|q| q == p))
        })
        .collect();
    let mut observed = [false; CLIENTS.len()];
    let mut findings = Vec::new();
    let mut states = Vec::new();
    let interfaces = match net::interfaces() {
        Ok(list) => list,
        Err(e) => {
            states.push("Tunnel inspection incomplete".to_string());
            findings.push(Finding::info("VPN", format!("couldn't list adapters: {e}")));
            Vec::new()
        }
    };

    let mut idle = Vec::new();
    for i in interfaces.iter().filter(|i| is_tunnel(i)) {
        let addresses: Vec<String> = i.usable_addresses().map(|a| a.ip.to_string()).collect();
        let describe = if i.description.is_empty() { i.name.clone() } else { format!("{} · {}", i.name, i.description) };
        let known = CLIENTS.iter().position(|c| (c.adapter)(&i.description) || (c.adapter)(&i.name));
        let provider = known
            .map(|k| CLIENTS[k].name)
            .or_else(|| vpn_client(&i.description))
            .unwrap_or("Unidentified VPN");
        if !i.up || addresses.is_empty() {
            if !idle.contains(&provider) {
                idle.push(provider);
                findings.push(Finding::info(format!("VPN ({provider})"), "installed, not connected").with_detail(describe));
            }
            continue;
        }
        let state = match known {
            Some(k) => {
                observed[k] = true;
                format!("Tunnel interface active - {provider}")
            }
            None => format!("VPN interface active - {}", i.name),
        };
        findings.push(
            Finding::info(format!("VPN ({provider})"), state.clone())
                .with_detail(format!("{describe} · tunnel address {}", addresses.join(", "))),
        );
        states.push(state);
    }
    for (k, c) in CLIENTS.iter().enumerate() {
        if running[k] && !observed[k] {
            let state = format!("Client running - tunnel unverified - {}", c.name);
            findings.retain(|f| f.label != format!("VPN ({})", c.name));
            findings.push(Finding::info(format!("VPN ({})", c.name), "client running, tunnel unverified").with_detail(
                "The client is running but no tunnel adapter is up: a cloud-proxy client (Zscaler) works this way, a full-tunnel VPN shouldn't.",
            ));
            states.push(state);
        }
    }
    if findings.is_empty() {
        findings.push(Finding::info("VPN", "No VPN indicators detected"));
    }
    let summary = (!states.is_empty()).then(|| format!("VPN: {}", states.join(" | ")));
    (findings, summary)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::net::{auth_is_weak, auth_name, radio_name};
    use crate::win::{scm, wlan};

    pub fn any_service_running(names: &[&str]) -> bool {
        names.iter().any(|n| scm::query(n).ok().flatten().is_some_and(|s| s.running))
    }

    pub fn wifi(band: Band) -> (Vec<Finding>, String) {
        let list = match wlan::interfaces() {
            Ok(l) if !l.is_empty() => l,
            _ => {
                return (
                    vec![Finding::info("Wi-Fi", "no Wi-Fi adapter (normal on a wired desktop)")],
                    "Wired".to_string(),
                )
            }
        };
        let mut findings = Vec::new();
        let mut summary = "Wi-Fi not connected".to_string();
        for w in list {
            if !w.connected {
                findings.push(Finding::info(format!("Wi-Fi ({})", w.adapter), "not connected"));
                continue;
            }
            findings.push(match &w.ssid {
                Some(s) => Finding::ok("Network", s.clone()).with_detail(w.adapter.clone()),
                None => Finding::info("Network", "name hidden by Windows location privacy").with_detail(
                    "Windows 11 24H2 and later hide network names from apps without location access \
                     (Settings → Privacy & security → Location).",
                ),
            });
            let mut grade = "connected";
            if let Some(q) = w.signal {
                let (f, g) = signal_finding(q, band);
                findings.push(f);
                grade = g;
            }
            if let Some(a) = w.auth {
                let name = format!("{}{}", auth_name(a), if w.one_x { " · 802.1X" } else { "" });
                let severity = if auth_is_weak(a) { Severity::Warning } else { Severity::Ok };
                findings.push(Finding::new("Security", name, severity));
            }
            let radio = [w.phy.and_then(radio_name).map(str::to_string), w.channel.map(|c| format!("channel {c}"))]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            if !radio.is_empty() {
                findings.push(Finding::info("Radio", radio.join(" · ")));
            }
            if let Some(rx) = w.rx_kbps {
                let tx = w.tx_kbps.map(|t| format!(" · send {} Mbps", t / 1000)).unwrap_or_default();
                findings.push(Finding::info("Link rate", format!("receive {} Mbps{tx}", rx / 1000)));
            }
            summary = match &w.ssid {
                Some(s) => format!("Wi-Fi {s}, signal {grade}"),
                None => format!("Wi-Fi connected, signal {grade}"),
            };
        }
        (findings, summary)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::net::nmcli_active_wifi;
    use crate::util::{capture, cmd, command_exists};

    pub fn any_service_running(names: &[&str]) -> bool {
        // The Linux clients ship as systemd units named after their daemons.
        names.iter().any(|n| {
            let mut c = cmd("systemctl");
            c.args(["is-active", "--quiet", &format!("{}.service", n.to_ascii_lowercase())]);
            command_exists("systemctl") && capture(c).is_ok_and(|o| o.success())
        })
    }

    pub fn wifi(band: Band) -> (Vec<Finding>, String) {
        if !command_exists("nmcli") {
            return (
                vec![Finding::info("Wi-Fi", "NetworkManager (nmcli) not found; Wi-Fi details unavailable")],
                "Wi-Fi state unknown".into(),
            );
        }
        let run = |extra: &[&str]| {
            let mut c = cmd("nmcli");
            c.args(["-t", "-f", "ACTIVE,SSID,SIGNAL,SECURITY,RATE,DEVICE", "dev", "wifi", "list"])
                .args(extra)
                .env("LC_ALL", "C");
            capture(c).ok().filter(|o| o.success()).map(|o| o.stdout)
        };
        // `--rescan no` keeps this read-only and instant; older nmcli lacks it.
        let out = run(&["--rescan", "no"]).or_else(|| run(&[])).unwrap_or_default();
        let links = nmcli_active_wifi(&out);
        if links.is_empty() {
            return (vec![Finding::info("Wi-Fi", "not connected (or no adapter)")], "Wi-Fi not connected".into());
        }
        let mut findings = Vec::new();
        let mut summary = String::new();
        for l in links {
            findings.push(Finding::ok("Network", l.ssid.clone()).with_detail(l.device.clone()));
            let mut grade = "connected";
            if let Some(q) = l.signal {
                let (f, g) = signal_finding(q, band);
                findings.push(f);
                grade = g;
            }
            let open = l.security == "Open";
            findings.push(Finding::new(
                "Security",
                l.security.clone(),
                if open { Severity::Warning } else { Severity::Ok },
            ));
            if !l.rate.is_empty() {
                findings.push(Finding::info("Link rate", l.rate.clone()));
            }
            summary = format!("Wi-Fi {}, signal {grade}", l.ssid);
        }
        (findings, summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_follows_the_nettriage_thresholds() {
        let band = crate::profile::Thresholds::default().wifi_signal_pct;
        assert_eq!(signal_finding(82, band).0.severity, Severity::Ok);
        assert_eq!(signal_finding(70, band).0.severity, Severity::Warning);
        assert_eq!(signal_finding(50, band).0.severity, Severity::Critical);
        let (f, grade) = signal_finding(34, band);
        assert_eq!((f.severity, grade), (Severity::Critical, "weak"));
        assert_eq!(f.metric.unwrap().value, 34.0);
    }

    #[test]
    fn knows_the_nettriage_clients() {
        assert!((CLIENTS[0].adapter)("Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64"));
        assert!((CLIENTS[0].adapter)("cscotun0"));
        assert!((CLIENTS[1].adapter)("Zscaler Network Adapter 1.0.2.0"));
        assert!(!(CLIENTS[1].adapter)("Intel(R) Wi-Fi 6E AX211 160MHz"));
    }
}
