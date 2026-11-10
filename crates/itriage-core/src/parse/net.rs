//! Wi-Fi and VPN helpers: security names, signal grading, VPN adapter
//! recognition, and NetworkManager's terse output.

use crate::model::Severity;

/// A DOT11_AUTH_ALGORITHM value as people say it.
pub fn auth_name(algorithm: i32) -> &'static str {
    match algorithm {
        1 => "Open",
        2 => "WEP (shared key)",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        5 => "WPA",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 => "WPA3-Enterprise 192-bit",
        9 => "WPA3-Personal",
        10 => "Enhanced Open (OWE)",
        11 => "WPA3-Enterprise",
        _ => "unknown",
    }
}

/// A DOT11_PHY_TYPE as the Wi-Fi generation people know.
pub fn radio_name(phy: i32) -> Option<&'static str> {
    Some(match phy {
        4 => "802.11a",
        5 => "802.11b",
        6 => "802.11g",
        7 => "Wi-Fi 4 (802.11n)",
        8 => "Wi-Fi 5 (802.11ac)",
        9 => "802.11ad",
        10 => "Wi-Fi 6 (802.11ax)",
        11 => "Wi-Fi 7 (802.11be)",
        _ => return None,
    })
}

/// Open networks, WEP and first-generation WPA are legacy security.
pub fn auth_is_weak(algorithm: i32) -> bool {
    matches!(algorithm, 1..=5)
}

/// Signal quality (0–100) to a grade. A cart that roams between access points
/// starts dropping sessions in the weak band.
pub fn signal_grade(quality: u32) -> (&'static str, Severity) {
    match quality {
        70.. => ("strong", Severity::Ok),
        50..=69 => ("good", Severity::Ok),
        35..=49 => ("fair", Severity::Info),
        _ => ("weak", Severity::Warning),
    }
}

/// The VPN client behind a Windows network adapter, from its description.
pub fn vpn_client(description: &str) -> Option<&'static str> {
    let d = description.to_ascii_lowercase();
    let table: [(&[&str], &str); 11] = [
        (&["anyconnect", "cisco secure client"], "Cisco Secure Client"),
        (&["pangp"], "GlobalProtect"),
        (&["zscaler"], "Zscaler"),
        (&["fortinet", "fortissl"], "FortiClient"),
        (&["juniper", "pulse secure", "ivanti"], "Ivanti Secure Access"),
        (&["f5 networks", "f5 vpn"], "F5 BIG-IP Edge"),
        (&["check point", "checkpoint"], "Check Point"),
        (&["sonicwall"], "SonicWall"),
        (&["wireguard"], "WireGuard"),
        (&["tailscale"], "Tailscale"),
        (&["tap-windows", "openvpn", "wintun"], "OpenVPN"),
    ];
    table
        .iter()
        .find(|(needles, _)| needles.iter().any(|n| d.contains(n)))
        .map(|(_, name)| *name)
}

/// Invoke-NetTriage's VPN adapter test: its description pattern
/// (`Cisco…AnyConnect|Secure Client`, `Zscaler`, `VPN`, `WireGuard`, `Wintun`,
/// `TAP-Windows`, `OpenVPN`, `GlobalProtect`, `Fortinet`, `FortiClient`,
/// `SonicWall`), plus every client [`vpn_client`] knows by name.
pub fn is_vpn_adapter(description: &str) -> bool {
    let d = description.to_ascii_lowercase();
    let cisco = d.contains("cisco") && (d.contains("anyconnect") || d.contains("secure client"));
    cisco
        || [
            "anyconnect", "zscaler", "vpn", "wireguard", "wintun", "tap-windows", "openvpn", "globalprotect",
            "fortinet", "forticlient", "sonicwall",
        ]
        .iter()
        .any(|n| d.contains(n))
        || vpn_client(description).is_some()
}

/// Where an interface address came from (Windows' NL_PREFIX_ORIGIN; on Linux,
/// "dynamic" addresses are leased and the rest were set by hand).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrOrigin {
    Other,
    Manual,
    WellKnown,
    Dhcp,
    RouterAdvertisement,
    Unknown,
}

impl AddrOrigin {
    pub fn from_windows(value: i32) -> Self {
        match value {
            0 => AddrOrigin::Other,
            1 => AddrOrigin::Manual,
            2 => AddrOrigin::WellKnown,
            3 => AddrOrigin::Dhcp,
            4 => AddrOrigin::RouterAdvertisement,
            _ => AddrOrigin::Unknown,
        }
    }
}

/// Whether resetting the TCP/IP stack is safe: it wipes static addresses,
/// so Invoke-EndpointTuneUp only resets when every address is DHCP, router
/// advertisement, well-known or "other".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackSafety {
    /// No address was set by hand.
    Clear,
    /// This many addresses are static.
    Static(usize),
    /// Couldn't tell (no addresses, or an origin we don't recognise).
    Unknown,
}

pub fn stack_reset_safety(origins: &[AddrOrigin]) -> StackSafety {
    let manual = origins.iter().filter(|o| **o == AddrOrigin::Manual).count();
    if manual > 0 {
        StackSafety::Static(manual)
    } else if !origins.is_empty() && origins.iter().all(|o| *o != AddrOrigin::Unknown) {
        StackSafety::Clear
    } else {
        StackSafety::Unknown
    }
}

/// Linux interface names used by tunnels: tun0, wg0, tailscale0, ppp0, zt…
pub fn is_tunnel_interface(name: &str) -> bool {
    ["tun", "tap", "wg", "tailscale", "ppp", "zt", "vpn", "nordlynx", "cscotun", "gpd"]
        .iter()
        .any(|p| name.starts_with(p))
}

/// Split one line of `nmcli -t` output: `:` separates fields, `\:` and `\\`
/// are escapes.
pub fn nmcli_fields(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    fields.last_mut().unwrap().push(next);
                }
            }
            ':' => fields.push(String::new()),
            _ => fields.last_mut().unwrap().push(c),
        }
    }
    fields
}

#[derive(Debug, Clone, PartialEq)]
pub struct WifiLink {
    pub ssid: String,
    pub signal: Option<u32>,
    pub security: String,
    pub rate: String,
    pub device: String,
}

/// Connected networks from
/// `nmcli -t -f ACTIVE,SSID,SIGNAL,SECURITY,RATE,DEVICE dev wifi list`.
pub fn nmcli_active_wifi(out: &str) -> Vec<WifiLink> {
    out.lines()
        .map(nmcli_fields)
        .filter(|f| f.len() >= 6 && f[0] == "yes")
        .map(|f| WifiLink {
            ssid: f[1].clone(),
            signal: f[2].parse().ok(),
            security: if f[3].is_empty() || f[3] == "--" { "Open".into() } else { f[3].clone() },
            rate: f[4].clone(),
            device: f[5].clone(),
        })
        .collect()
}

/// `nmcli -t -f DEVICE,TYPE,STATE,CON-UUID device`: the wired and Wi-Fi
/// devices that are connected, each with the UUID of its active connection
/// when NetworkManager gives one.
pub fn nmcli_connected(out: &str) -> Vec<(String, Option<String>)> {
    out.lines()
        .map(nmcli_fields)
        .filter(|f| f.len() >= 3 && matches!(f[1].as_str(), "ethernet" | "wifi") && f[2].starts_with("connected"))
        .map(|f| {
            let uuid = f.get(3).filter(|u| u.len() == 36 && u.chars().all(|c| c.is_ascii_hexdigit() || c == '-')).cloned();
            (f[0].clone(), uuid)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_grades() {
        assert_eq!(auth_name(6), "WPA2-Enterprise");
        assert_eq!(auth_name(11), "WPA3-Enterprise");
        assert!(auth_is_weak(2) && !auth_is_weak(6) && !auth_is_weak(10));
        assert_eq!(signal_grade(82).0, "strong");
        assert_eq!(signal_grade(38), ("fair", Severity::Info));
        assert_eq!(signal_grade(20).1, Severity::Warning);
    }

    #[test]
    fn recognises_vpn_adapters() {
        assert_eq!(
            vpn_client("Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64"),
            Some("Cisco Secure Client")
        );
        assert_eq!(vpn_client("PANGP Virtual Ethernet Adapter Secure"), Some("GlobalProtect"));
        assert_eq!(vpn_client("Intel(R) Wi-Fi 6E AX211 160MHz"), None);
        assert!(is_tunnel_interface("wg0") && is_tunnel_interface("tailscale0"));
        assert!(!is_tunnel_interface("enp3s0") && !is_tunnel_interface("wlp2s0"));
    }

    #[test]
    fn matches_nettriage_vpn_adapters() {
        assert!(is_vpn_adapter("Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64"));
        assert!(is_vpn_adapter("Zscaler Network Adapter 1.0.2.0"));
        assert!(is_vpn_adapter("Wintun Userspace Tunnel"));
        assert!(is_vpn_adapter("PANGP Virtual Ethernet Adapter Secure"));
        assert!(!is_vpn_adapter("Intel(R) Ethernet Connection (17) I219-LM"));
    }

    #[test]
    fn stack_reset_needs_every_address_leased() {
        use AddrOrigin::*;
        assert_eq!(stack_reset_safety(&[Dhcp, RouterAdvertisement, WellKnown, Other]), StackSafety::Clear);
        assert_eq!(stack_reset_safety(&[Dhcp, Manual, Manual]), StackSafety::Static(2));
        assert_eq!(stack_reset_safety(&[Dhcp, Unknown]), StackSafety::Unknown);
        assert_eq!(stack_reset_safety(&[]), StackSafety::Unknown);
        assert_eq!(AddrOrigin::from_windows(3), Dhcp);
    }

    #[test]
    fn lists_connected_devices_with_their_connection() {
        let out = "enp3s0:ethernet:connected:3f2a9c1e-5b7d-4e8a-9c0b-1a2b3c4d5e6f\n\
                   wlp2s0:wifi:connected (externally):\n\
                   wlan1:wifi:disconnected:--\n\
                   lo:loopback:connected (externally):aa\n\
                   tun0:tun:connected:11111111-2222-3333-4444-555555555555\n";
        assert_eq!(
            nmcli_connected(out),
            vec![
                ("enp3s0".to_string(), Some("3f2a9c1e-5b7d-4e8a-9c0b-1a2b3c4d5e6f".to_string())),
                ("wlp2s0".to_string(), None),
            ],
            "wired and Wi-Fi only; no UUID means reconnect by device"
        );
        // Older nmcli without the fourth field still lists the devices.
        assert_eq!(nmcli_connected("eth0:ethernet:connected\n"), vec![("eth0".to_string(), None)]);
    }

    #[test]
    fn parses_nmcli_terse_output() {
        assert_eq!(nmcli_fields(r"no:Guest\:Free:40"), vec!["no", "Guest:Free", "40"]);
        let out = "yes:Hospital-Secure:72:WPA2 802.1X:540 Mbit/s:wlp2s0\nno:Guest\\:Free:40:--:130 Mbit/s:wlp2s0\n";
        let links = nmcli_active_wifi(out);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].ssid, "Hospital-Secure");
        assert_eq!(links[0].signal, Some(72));
        assert_eq!(links[0].security, "WPA2 802.1X");
        assert_eq!(links[0].device, "wlp2s0");
    }
}
