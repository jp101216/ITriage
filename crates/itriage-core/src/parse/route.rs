//! Linux network configuration from iproute2's JSON output (`ip -j …`),
//! `/etc/resolv.conf` and `resolvectl dns`.

use serde_json::Value;
use std::net::IpAddr;

/// One address on a link.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkAddr {
    pub ip: IpAddr,
    pub prefix: u8,
    /// Leased (DHCP) or autoconfigured (SLAAC), as opposed to set by hand.
    pub dynamic: bool,
    /// "global", "link", "host".
    pub scope: String,
}

/// One network interface from `ip -j addr show`.
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub up: bool,
    pub loopback: bool,
    pub addrs: Vec<LinkAddr>,
}

/// One route from `ip -j route show …` or `ip -j route get …`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RouteEntry {
    pub dev: Option<String>,
    pub gateway: Option<IpAddr>,
    pub source: Option<IpAddr>,
    pub metric: Option<u64>,
}

/// An address as tools print it: strips a `%zone`, a DoT `#name`, brackets
/// and an IPv4 `:port`.
pub fn parse_ip(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    let s = s.split('#').next().unwrap_or(s);
    let s = s.trim_start_matches('[');
    let s = s.split(']').next().unwrap_or(s);
    let s = s.split('%').next().unwrap_or(s);
    if let Ok(ip) = s.parse() {
        return Some(ip);
    }
    // 192.0.2.1:53
    let (host, port) = s.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    host.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

fn array(text: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(a)) => a,
        _ => Vec::new(),
    }
}

fn has_flag(v: &Value, flag: &str) -> bool {
    v.get("flags")
        .and_then(Value::as_array)
        .is_some_and(|f| f.iter().any(|x| x.as_str() == Some(flag)))
}

/// Interfaces and their addresses from `ip -j addr show`.
pub fn ip_addr_json(text: &str) -> Vec<Link> {
    array(text)
        .iter()
        .filter_map(|l| {
            let name = l.get("ifname")?.as_str()?.to_string();
            let state = l.get("operstate").and_then(Value::as_str).unwrap_or("");
            let up = state == "UP" || (state == "UNKNOWN" && has_flag(l, "UP") && has_flag(l, "LOWER_UP"));
            let addrs = l
                .get("addr_info")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|a| {
                            Some(LinkAddr {
                                ip: parse_ip(a.get("local")?.as_str()?)?,
                                prefix: a.get("prefixlen").and_then(Value::as_u64).unwrap_or(0) as u8,
                                dynamic: a.get("dynamic").and_then(Value::as_bool).unwrap_or(false),
                                scope: a.get("scope").and_then(Value::as_str).unwrap_or("").to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(Link {
                index: l.get("ifindex").and_then(Value::as_u64).unwrap_or(0) as u32,
                name,
                up,
                loopback: has_flag(l, "LOOPBACK"),
                addrs,
            })
        })
        .collect()
}

/// Routes from `ip -j route show default` or `ip -j route get <address>`.
pub fn ip_route_json(text: &str) -> Vec<RouteEntry> {
    array(text)
        .iter()
        .map(|r| RouteEntry {
            dev: r.get("dev").and_then(Value::as_str).map(str::to_string),
            gateway: r.get("gateway").and_then(Value::as_str).and_then(parse_ip),
            source: r.get("prefsrc").and_then(Value::as_str).and_then(parse_ip),
            metric: r.get("metric").and_then(Value::as_u64),
        })
        .collect()
}

/// `nameserver` lines from resolv.conf.
pub fn resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            (parts.next()? == "nameserver").then(|| parts.next().and_then(parse_ip))?
        })
        .collect()
}

/// `resolvectl dns`: "Global: …" and "Link 3 (wlp2s0): …" lines. Returns
/// the link name (`None` for Global) and its servers.
pub fn resolvectl_dns(text: &str) -> Vec<(Option<String>, Vec<IpAddr>)> {
    text.lines()
        .filter_map(|l| {
            let (head, _) = l.split_once(':').filter(|(h, _)| h.starts_with("Global") || h.starts_with("Link"))?;
            let link = head
                .split_once('(')
                .and_then(|(_, rest)| rest.split_once(')'))
                .map(|(name, _)| name.to_string());
            // The server list itself can contain colons (IPv6), so take it all.
            let servers: Vec<IpAddr> = l[head.len() + 1..]
                .split_whitespace()
                .filter_map(parse_ip)
                .collect();
            Some((link, servers))
        })
        .collect()
}

/// IPv4 default routes from `/proc/net/route` (interface, gateway, metric),
/// for machines without iproute2. Addresses there are little-endian hex.
pub fn proc_net_route(text: &str) -> Vec<(String, std::net::Ipv4Addr, u32)> {
    let mut out: Vec<(String, std::net::Ipv4Addr, u32)> = text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
                return None;
            }
            let gw = u32::from_str_radix(f[2], 16).ok()?;
            let flags = u32::from_str_radix(f[3], 16).ok()?;
            // RTF_UP and RTF_GATEWAY.
            if flags & 0x1 == 0 || flags & 0x2 == 0 {
                return None;
            }
            Some((f[0].to_string(), std::net::Ipv4Addr::from(gw.to_le_bytes()), f[6].parse().unwrap_or(0)))
        })
        .collect();
    out.sort_by_key(|r| r.2);
    out
}

/// Does `ip` sit in the same subnet as `addr`/`prefix`?
pub fn same_subnet(addr: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (addr, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = u32::from(prefix.min(32));
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = u32::from(prefix.min(128));
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// `loginctl list-sessions --no-legend`: the user on the local seat.
pub fn loginctl_seat_user(text: &str) -> Option<String> {
    let rows: Vec<Vec<&str>> = text.lines().map(|l| l.split_whitespace().collect()).collect();
    rows.iter()
        .find(|r| r.len() >= 4 && r[3] == "seat0")
        .or_else(|| rows.iter().find(|r| r.len() >= 3 && r[1].parse::<u32>().is_ok_and(|uid| uid >= 1000)))
        .map(|r| r[2].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = r#"[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"operstate":"UNKNOWN",
      "addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]},
      {"ifindex":2,"ifname":"wlp2s0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP",
      "addr_info":[{"family":"inet","local":"192.168.1.23","prefixlen":24,"scope":"global","dynamic":true},
                   {"family":"inet6","local":"fe80::1a2b:3c4d","prefixlen":64,"scope":"link"}]},
      {"ifindex":3,"ifname":"enp3s0","flags":["NO-CARRIER","BROADCAST","UP"],"operstate":"DOWN","addr_info":[]},
      {"ifindex":4,"ifname":"wg0","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"operstate":"UNKNOWN",
      "addr_info":[{"family":"inet","local":"10.8.0.2","prefixlen":32,"scope":"global"}]}]"#;

    #[test]
    fn parses_links_and_addresses() {
        let links = ip_addr_json(ADDR);
        assert_eq!(links.len(), 4);
        assert!(links[0].loopback && links[0].up);
        let wifi = &links[1];
        assert_eq!((wifi.index, wifi.name.as_str(), wifi.up), (2, "wlp2s0", true));
        assert_eq!(wifi.addrs[0].ip.to_string(), "192.168.1.23");
        assert!(wifi.addrs[0].dynamic && !wifi.addrs[1].dynamic);
        assert!(!links[2].up, "no carrier");
        assert!(links[3].up, "tunnels report UNKNOWN while carrying traffic");
        assert!(ip_addr_json("not json").is_empty());
    }

    #[test]
    fn parses_routes() {
        let get = r#"[{"dst":"8.8.8.8","gateway":"192.168.1.1","dev":"wlp2s0","prefsrc":"192.168.1.23","flags":[],"uid":1000,"cache":[]}]"#;
        let r = &ip_route_json(get)[0];
        assert_eq!(r.dev.as_deref(), Some("wlp2s0"));
        assert_eq!(r.gateway.unwrap().to_string(), "192.168.1.1");
        assert_eq!(r.source.unwrap().to_string(), "192.168.1.23");
        let onlink = r#"[{"dst":"192.168.1.40","dev":"wlp2s0","prefsrc":"192.168.1.23","flags":[]}]"#;
        assert_eq!(ip_route_json(onlink)[0].gateway, None);
        let default = r#"[{"dst":"default","gateway":"fe80::1","dev":"wlp2s0","protocol":"ra","metric":600,"flags":[]}]"#;
        assert_eq!(ip_route_json(default)[0].metric, Some(600));
    }

    #[test]
    fn parses_dns_configuration() {
        let conf = "# generated\nnameserver 127.0.0.53\noptions edns0\nnameserver fe80::1%wlp2s0\nsearch corp.example.org\n";
        let servers: Vec<String> = resolv_conf(conf).iter().map(|s| s.to_string()).collect();
        assert_eq!(servers, ["127.0.0.53", "fe80::1"]);
        let rc = "Global: 1.1.1.1#cloudflare-dns.com\nLink 2 (enp0s3):\nLink 3 (wlp2s0): 192.168.1.1 fe80::1%3\n";
        let parsed = resolvectl_dns(rc);
        assert_eq!(parsed[0], (None, vec!["1.1.1.1".parse().unwrap()]));
        assert_eq!(parsed[1], (Some("enp0s3".into()), vec![]));
        assert_eq!(parsed[2].0.as_deref(), Some("wlp2s0"));
        assert_eq!(parsed[2].1.len(), 2);
        assert_eq!(parse_ip("192.0.2.1:53").unwrap().to_string(), "192.0.2.1");
        assert_eq!(parse_ip("[2001:db8::1]").unwrap().to_string(), "2001:db8::1");
        assert!(parse_ip("nonsense").is_none());
    }

    #[test]
    fn reads_proc_net_route() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    wlp2s0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                    eth0\t00000000\t010010AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                    eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let routes = proc_net_route(text);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0], ("eth0".to_string(), "172.16.0.1".parse().unwrap(), 100), "lowest metric first");
        assert_eq!(routes[1].1.to_string(), "192.168.2.1");
        let a: IpAddr = "192.168.1.23".parse().unwrap();
        assert!(same_subnet(a, 24, "192.168.1.200".parse().unwrap()));
        assert!(!same_subnet(a, 24, "192.168.2.1".parse().unwrap()));
        assert!(same_subnet("2001:db8::5".parse().unwrap(), 64, "2001:db8::99".parse().unwrap()));
    }

    #[test]
    fn finds_the_seat_user() {
        let out = "     3 1001 kiosk -     -\n     2 1000 jess  seat0 tty2\n";
        assert_eq!(loginctl_seat_user(out).as_deref(), Some("jess"));
        assert_eq!(loginctl_seat_user("     5 1002 sam\n").as_deref(), Some("sam"));
        assert_eq!(loginctl_seat_user("     1 0 root\n"), None);
    }
}
