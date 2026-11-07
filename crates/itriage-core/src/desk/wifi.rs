//! Wi-Fi & VPN. Read-only.
//!
//! The connected network, signal quality (carts that roam a ward drop their
//! sessions on weak signal), the security in use (802.1X or not), and which
//! VPN tunnels are up.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::net::signal_grade;

pub struct WifiVpn;

impl TriageModule for WifiVpn {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.wifi",
            "Wi-Fi & VPN",
            Category::Workstation,
            "The connected Wi-Fi network, signal strength, security (802.1X or not), link rate, and any VPN tunnel.",
        )
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let (mut findings, wifi_summary) = imp::wifi();
        let (vpn, vpn_summary) = imp::vpn();
        findings.extend(vpn);
        let summary = match vpn_summary {
            Some(v) => format!("{wifi_summary} · {v}"),
            None => wifi_summary,
        };
        Ok(Output::new(summary, findings))
    }
}

/// The signal row and its summary word.
fn signal_finding(quality: u32) -> (Finding, &'static str) {
    let (grade, severity) = signal_grade(quality);
    let mut f = Finding::new("Signal", format!("{quality}% · {grade}"), severity);
    if severity == Severity::Warning {
        f = f.with_detail("Weak signal drops remote sessions as the device moves. Note where it happens for the network team.");
    }
    (f, grade)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::net::{auth_is_weak, auth_name, vpn_client};
    use crate::win::{adapters, wlan};

    pub fn wifi() -> (Vec<Finding>, String) {
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
                let (f, g) = signal_finding(q);
                findings.push(f);
                grade = g;
            }
            if let Some(a) = w.auth {
                let name = format!("{}{}", auth_name(a), if w.one_x { " · 802.1X" } else { "" });
                let severity = if auth_is_weak(a) { Severity::Warning } else { Severity::Ok };
                findings.push(Finding::new("Security", name, severity));
            }
            if let Some(kbps) = w.rx_kbps {
                findings.push(Finding::info("Link rate", format!("{} Mbps", kbps / 1000)));
            }
            summary = match &w.ssid {
                Some(s) => format!("Wi-Fi {s}, signal {grade}"),
                None => format!("Wi-Fi connected, signal {grade}"),
            };
        }
        (findings, summary)
    }

    pub fn vpn() -> (Vec<Finding>, Option<String>) {
        let list = match adapters::adapters() {
            Ok(l) => l,
            Err(e) => return (vec![Finding::info("VPN", format!("couldn't list adapters: {e}"))], None),
        };
        let mut findings = Vec::new();
        let mut up = Vec::new();
        let mut seen = Vec::new();
        for a in &list {
            let Some(client) = vpn_client(&a.description) else { continue };
            if seen.contains(&(client, a.up)) {
                continue;
            }
            seen.push((client, a.up));
            if a.up {
                up.push(client);
            }
            findings.push(
                Finding::info(format!("VPN ({client})"), if a.up { "connected" } else { "installed, not connected" })
                    .with_detail(format!("{} · {}", a.name, a.description)),
            );
        }
        if findings.is_empty() {
            findings.push(Finding::info("VPN", "no VPN client adapter found"));
        }
        let summary = (!up.is_empty()).then(|| format!("VPN up ({})", up.join(", ")));
        (findings, summary)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::net::{is_tunnel_interface, nmcli_active_wifi};
    use crate::util::{capture, cmd, command_exists};

    pub fn wifi() -> (Vec<Finding>, String) {
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
                let (f, g) = signal_finding(q);
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

    pub fn vpn() -> (Vec<Finding>, Option<String>) {
        let mut up = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if !is_tunnel_interface(&name) {
                    continue;
                }
                let state = std::fs::read_to_string(e.path().join("operstate")).unwrap_or_default();
                // Tunnels often report "unknown" while carrying traffic.
                if matches!(state.trim(), "up" | "unknown") {
                    up.push(name);
                }
            }
        }
        up.sort();
        if up.is_empty() {
            (vec![Finding::info("VPN", "no tunnel interface up")], None)
        } else {
            let findings = up.iter().map(|n| Finding::info(format!("VPN tunnel ({n})"), "up")).collect();
            (findings, Some(format!("VPN up ({})", up.join(", "))))
        }
    }
}
