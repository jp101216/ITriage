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
