//! Network plumbing shared by the network checks: interfaces and their
//! addresses, the route to a destination, timed DNS (through the system
//! resolver and straight to each DNS server), TCP probes with a time budget,
//! ICMP ping, and the public-IP lookup.
//!
//! The behaviour follows Invoke-NetTriage: the "selected route" is the one
//! Windows (or Linux) would actually use, the gateway and DNS servers come
//! from that route's interface, and a TCP check tries every address a name
//! resolves to within one time budget.
//!
//! Windows goes through IP Helper (GetAdaptersAddresses, GetBestRoute2,
//! IcmpSendEcho) and WinHTTP; Linux through iproute2's JSON output,
//! systemd-resolved, `ping` and `curl`.

pub mod latency;
pub mod proxy;
pub mod target;

use crate::parse::dns;
use crate::parse::net::AddrOrigin;
use crate::parse::ping::PingStats;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// One network interface.
#[derive(Debug, Clone)]
pub struct Interface {
    pub index: u32,
    /// "Wi-Fi", "Ethernet 2" (Windows); "wlp2s0" (Linux).
    pub name: String,
    /// The adapter's driver description (Windows only).
    pub description: String,
    pub up: bool,
    pub loopback: bool,
    pub addresses: Vec<IfAddr>,
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct IfAddr {
    pub ip: IpAddr,
    pub prefix: u8,
    pub origin: AddrOrigin,
}

impl Interface {
    /// Addresses other machines can reach: not loopback, link-local or APIPA.
    pub fn usable_addresses(&self) -> impl Iterator<Item = &IfAddr> {
        self.addresses.iter().filter(|a| is_usable(a.ip))
    }

    /// "10.20.33.118/22, fe80::1a2b/64".
    pub fn address_list(&self) -> String {
        self.addresses
            .iter()
            .map(|a| format!("{}/{}", a.ip, a.prefix))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Not loopback, unspecified, IPv4 link-local (169.254/16, APIPA) or IPv6
/// link-local (fe80::/10).
pub fn is_usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified() && !v4.is_link_local(),
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified() && (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// An APIPA address: DHCP failed and Windows picked one itself.
pub fn is_apipa(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.is_link_local())
}

/// The route the OS would use to reach a destination.
#[derive(Debug, Clone, Default)]
pub struct Route {
    pub interface: Option<String>,
    pub index: Option<u32>,
    /// The local address packets would leave from.
    pub source: Option<IpAddr>,
    /// The gateway; `None` when the destination is on the local network.
    pub next_hop: Option<IpAddr>,
    /// The DNS servers configured on that interface.
    pub dns_servers: Vec<IpAddr>,
}

impl Route {
    /// "via 10.20.32.1 on Wi-Fi (from 10.20.33.118)" / "direct on Ethernet".
    pub fn describe(&self) -> String {
        let on = self
            .interface
            .as_deref()
            .map(|i| format!(" on {i}"))
            .unwrap_or_default();
        let from = self.source.map(|s| format!(" (from {s})")).unwrap_or_default();
        match self.next_hop {
            Some(gw) => format!("via {gw}{on}{from}"),
            None => format!("direct{on}{from}"),
        }
    }
}

pub fn interfaces() -> Result<Vec<Interface>, String> {
    imp::interfaces()
}

pub fn route_to(dest: IpAddr) -> Result<Route, String> {
    imp::route_to(dest)
}

/// Well-known public addresses used only to ask the OS which route it would
/// pick; no packet is sent.
const ROUTE_PROBE_V4: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const ROUTE_PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

/// The default route: IPv4 first, the way NetTriage picks it.
pub fn default_route() -> Result<Route, String> {
    route_to(IpAddr::V4(ROUTE_PROBE_V4)).or_else(|v4| route_to(IpAddr::V6(ROUTE_PROBE_V6)).map_err(|_| v4))
}

/// ICMP echo `count` times. `scope` is the interface index, needed for IPv6
/// link-local targets.
pub fn ping(addr: IpAddr, scope: Option<u32>, count: u32, timeout: Duration) -> Result<PingStats, String> {
    imp::ping(addr, scope, count.clamp(1, 20), timeout)
}

/// A name resolved through the system resolver (hosts file, cache, DNS).
#[derive(Debug, Clone)]
pub struct Resolution {
    pub addresses: Vec<IpAddr>,
    pub elapsed: Duration,
}

/// Resolve `host`. An IP address resolves to itself without a lookup.
pub fn resolve(host: &str) -> Result<Resolution, String> {
    let started = Instant::now();
    if let Some(ip) = crate::parse::route::parse_ip(host).filter(|_| !host.contains('#')) {
        return Ok(Resolution {
            addresses: vec![ip],
            elapsed: Duration::ZERO,
        });
    }
    let found = (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("{host} doesn't resolve ({})", resolve_error(&e)))?;
    let mut addresses: Vec<IpAddr> = Vec::new();
    for a in found {
        if !addresses.contains(&a.ip()) {
            addresses.push(a.ip());
        }
    }
    if addresses.is_empty() {
        return Err(format!("{host} resolved to no addresses"));
    }
    Ok(Resolution {
        addresses,
        elapsed: started.elapsed(),
    })
}

fn resolve_error(e: &std::io::Error) -> String {
    let text = e.to_string();
    if text.contains("not known") || text.contains("No such host") || text.contains("11001") {
        "no such name".into()
    } else if text.contains("Temporary failure") || text.contains("11002") {
        "DNS server didn't answer".into()
    } else {
        text
    }
}

/// One connection attempt.
#[derive(Debug, Clone)]
pub struct TcpAttempt {
    pub address: IpAddr,
    pub result: Result<Duration, String>,
}

/// Invoke-NetTriage's `Test-ResolvedTcpPort`: try each resolved address in
/// turn, sharing one time budget, until one connects.
#[derive(Debug, Clone)]
pub struct TcpCheck {
    pub port: u16,
    pub attempts: Vec<TcpAttempt>,
    /// The budget ran out before every address was tried.
    pub budget_exhausted: bool,
}

impl TcpCheck {
    pub fn connected(&self) -> Option<(IpAddr, Duration)> {
        self.attempts
            .iter()
            .find_map(|a| a.result.as_ref().ok().map(|d| (a.address, *d)))
    }

    /// "10.1.2.3 refused · 10.1.2.4 timed out".
    pub fn error(&self) -> String {
        let mut parts: Vec<String> = self
            .attempts
            .iter()
            .filter_map(|a| a.result.as_ref().err().map(|e| format!("{} {e}", a.address)))
            .collect();
        if self.budget_exhausted {
            parts.push("time budget used up".into());
        }
        if parts.is_empty() {
            "not tried".into()
        } else {
            parts.join(" · ")
        }
    }
}

pub fn tcp_check(addresses: &[IpAddr], port: u16, budget: Duration) -> TcpCheck {
    let started = Instant::now();
    let mut attempts = Vec::new();
    let mut budget_exhausted = false;
    for (i, address) in addresses.iter().enumerate() {
        let Some(remaining) = budget.checked_sub(started.elapsed()).filter(|r| !r.is_zero()) else {
            budget_exhausted = true;
            break;
        };
        // Split what's left between the addresses still to try.
        let share = (remaining / (addresses.len() - i) as u32).max(Duration::from_millis(1));
        let t0 = Instant::now();
        let result = TcpStream::connect_timeout(&SocketAddr::new(*address, port), share)
            .map(|_| t0.elapsed())
            .map_err(|e| connect_error(&e));
        let ok = result.is_ok();
        attempts.push(TcpAttempt { address: *address, result });
        if ok {
            break;
        }
    }
    TcpCheck {
        port,
        attempts,
        budget_exhausted,
    }
}

/// A connect error as people say it.
pub fn connect_error(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        TimedOut | WouldBlock => "timed out".into(),
        ConnectionRefused => "refused".into(),
        ConnectionReset => "reset".into(),
        HostUnreachable => "host unreachable".into(),
        NetworkUnreachable => "network unreachable".into(),
        AddrNotAvailable => "address not available".into(),
        _ => e.to_string(),
    }
}

/// Ask one DNS server for `name` directly over UDP, bypassing the resolver
/// cache. Returns the reply and the round trip.
pub fn dns_query(server: IpAddr, name: &str, timeout: Duration) -> Result<(dns::Reply, Duration), String> {
    dns_query_at(SocketAddr::new(server, 53), name, timeout)
}

fn dns_query_at(server: SocketAddr, name: &str, timeout: Duration) -> Result<(dns::Reply, Duration), String> {
    let id = (std::process::id() as u16) ^ (crate::util::now_epoch() as u16).rotate_left(5);
    let packet = dns::query(id, name).ok_or_else(|| format!("`{name}` isn't a valid DNS name"))?;
    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().expect("literal");
    let socket = UdpSocket::bind(bind).map_err(|e| format!("no socket: {e}"))?;
    let started = Instant::now();
    socket.send_to(&packet, server).map_err(|e| connect_error(&e))?;
    let mut buf = [0u8; 1500];
    loop {
        let left = timeout.checked_sub(started.elapsed()).filter(|d| !d.is_zero()).ok_or("timed out")?;
        socket.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        let (n, from) = socket.recv_from(&mut buf).map_err(|e| connect_error(&e))?;
        if from.ip() != server.ip() {
            continue;
        }
        if let Ok(reply) = dns::parse_reply(id, &buf[..n]) {
            return Ok((reply, started.elapsed()));
        }
    }
}

/// This machine's public (egress) IP, from a service that answers with the
/// address as plain text. A captive portal or proxy that answers with a web
/// page instead is reported as such.
pub fn egress_ip(urls: &[String], timeout: Duration) -> Result<IpAddr, String> {
    let mut last = String::from("no lookup service configured");
    for url in urls.iter().filter(|u| u.starts_with("https://")) {
        match imp::http_get(url, timeout) {
            Ok(body) => {
                let text = body.trim();
                match text.parse::<IpAddr>() {
                    Ok(ip) => return Ok(ip),
                    Err(_) => {
                        last = format!(
                            "{url} answered with something other than an address (a captive portal or proxy page?)"
                        )
                    }
                }
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The lookup services to try: the configured one, then api.ipify.org as
/// NetTriage does when the default is in use. Empty disables the lookup.
pub fn egress_urls(configured: &str) -> Vec<String> {
    let configured = configured.trim();
    if configured.is_empty() {
        return Vec::new();
    }
    let mut urls = vec![configured.to_string()];
    if configured == crate::profile::DEFAULT_EGRESS_URL {
        urls.push("https://api.ipify.org".to_string());
    }
    urls
}

/// Run `f` for each item on its own thread and collect the results in order.
pub fn parallel<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    std::thread::scope(|scope| {
        let f = &f;
        let handles: Vec<_> = items.iter().map(|item| scope.spawn(move || f(item))).collect();
        handles.into_iter().map(|h| h.join().expect("network probe thread panicked")).collect()
    })
}

#[cfg(windows)]
mod imp {
    pub use crate::win::net::{http_get, interfaces, ping, route_to};
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::ping::linux_summary;
    use crate::parse::route::{self, Link};
    use crate::util::{capture, cmd, command_exists};

    fn ip_json(args: &[&str]) -> Option<String> {
        if !command_exists("ip") {
            return None;
        }
        let mut c = cmd("ip");
        c.arg("-j").args(args).env("LC_ALL", "C");
        capture(c).ok().filter(|o| o.success()).map(|o| o.stdout)
    }

    /// Per-link DNS servers from systemd-resolved, falling back to
    /// resolv.conf (skipping resolved's 127.0.0.53 stub for the real
    /// upstream list).
    fn dns_config() -> (Vec<IpAddr>, Vec<(String, Vec<IpAddr>)>) {
        let mut global = Vec::new();
        let mut links = Vec::new();
        if command_exists("resolvectl") {
            let mut c = cmd("resolvectl");
            c.arg("dns").env("LC_ALL", "C");
            if let Ok(out) = capture(c) {
                if out.success() {
                    for (link, servers) in route::resolvectl_dns(&out.stdout) {
                        match link {
                            Some(name) => links.push((name, servers)),
                            None => global.extend(servers),
                        }
                    }
                }
            }
        }
        if global.is_empty() && links.iter().all(|(_, s)| s.is_empty()) {
            for file in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
                let servers: Vec<IpAddr> = std::fs::read_to_string(file)
                    .map(|t| route::resolv_conf(&t))
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|ip| !ip.is_loopback())
                    .collect();
                if !servers.is_empty() {
                    global = servers;
                    break;
                }
            }
        }
        (global, links)
    }

    fn dns_for(link: &str, global: &[IpAddr], links: &[(String, Vec<IpAddr>)]) -> Vec<IpAddr> {
        links
            .iter()
            .find(|(name, servers)| name == link && !servers.is_empty())
            .map(|(_, s)| s.clone())
            .unwrap_or_else(|| global.to_vec())
    }

    pub fn interfaces() -> Result<Vec<Interface>, String> {
        let links: Vec<Link> = match ip_json(&["addr", "show"]) {
            Some(text) => route::ip_addr_json(&text),
            None => return fallback_interfaces(),
        };
        let mut defaults = Vec::new();
        for family in [&["route", "show", "default"][..], &["-6", "route", "show", "default"][..]] {
            if let Some(text) = ip_json(family) {
                defaults.extend(route::ip_route_json(&text));
            }
        }
        let (global, per_link) = dns_config();
        Ok(links
            .into_iter()
            .map(|l| Interface {
                index: l.index,
                description: String::new(),
                up: l.up,
                loopback: l.loopback,
                addresses: l
                    .addrs
                    .iter()
                    .map(|a| IfAddr {
                        ip: a.ip,
                        prefix: a.prefix,
                        origin: if a.dynamic {
                            if a.ip.is_ipv4() { AddrOrigin::Dhcp } else { AddrOrigin::RouterAdvertisement }
                        } else if a.scope == "link" || a.scope == "host" {
                            AddrOrigin::WellKnown
                        } else {
                            AddrOrigin::Manual
                        },
                    })
                    .collect(),
                gateways: defaults
                    .iter()
                    .filter(|r| r.dev.as_deref() == Some(l.name.as_str()))
                    .filter_map(|r| r.gateway)
                    .collect(),
                dns_servers: if l.loopback { Vec::new() } else { dns_for(&l.name, &global, &per_link) },
                name: l.name,
            })
            .collect())
    }

    /// Without iproute2: addresses from sysinfo, IPv4 gateways from
    /// /proc/net/route.
    fn fallback_interfaces() -> Result<Vec<Interface>, String> {
        let networks = sysinfo::Networks::new_with_refreshed_list();
        let (global, per_link) = dns_config();
        let defaults = std::fs::read_to_string("/proc/net/route").map(|t| route::proc_net_route(&t)).unwrap_or_default();
        Ok(networks
            .iter()
            .map(|(name, data)| Interface {
                index: ifindex(name).unwrap_or(0),
                name: name.clone(),
                description: String::new(),
                up: !data.ip_networks().is_empty(),
                loopback: name == "lo",
                addresses: data
                    .ip_networks()
                    .iter()
                    .map(|n| IfAddr { ip: n.addr, prefix: n.prefix, origin: AddrOrigin::Unknown })
                    .collect(),
                gateways: defaults.iter().filter(|(i, _, _)| i == name).map(|(_, g, _)| IpAddr::V4(*g)).collect(),
                dns_servers: dns_for(name, &global, &per_link),
            })
            .collect())
    }

    fn ifindex(dev: &str) -> Option<u32> {
        std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    pub fn route_to(dest: IpAddr) -> Result<Route, String> {
        let Some(text) = ip_json(&["route", "get", &dest.to_string()]) else {
            return fallback_route(dest);
        };
        let r = route::ip_route_json(&text)
            .into_iter()
            .next()
            .ok_or_else(|| format!("no route to {dest}"))?;
        let (global, per_link) = dns_config();
        Ok(Route {
            dns_servers: r.dev.as_deref().map(|d| dns_for(d, &global, &per_link)).unwrap_or(global),
            index: r.dev.as_deref().and_then(ifindex),
            interface: r.dev,
            source: r.source,
            next_hop: r.gateway,
        })
    }

    /// Without iproute2: let the kernel pick a source address for a UDP
    /// "connection" (nothing is sent), find the interface that owns it, and
    /// take that interface's default gateway unless the destination is on
    /// its own subnet.
    fn fallback_route(dest: IpAddr) -> Result<Route, String> {
        let bind = if dest.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
        socket
            .connect(SocketAddr::new(dest, 9))
            .map_err(|e| format!("no route to {dest} ({})", connect_error(&e)))?;
        let source = socket.local_addr().map_err(|e| e.to_string())?.ip();
        let interfaces = fallback_interfaces()?;
        let owner = interfaces
            .iter()
            .find_map(|i| i.addresses.iter().find(|a| a.ip == source).map(|a| (i, a)));
        let (interface, index, next_hop, dns_servers) = match owner {
            Some((i, a)) => {
                let on_link = route::same_subnet(a.ip, a.prefix, dest);
                let gw = if on_link { None } else { i.gateways.first().copied() };
                (Some(i.name.clone()), ifindex(&i.name), gw, i.dns_servers.clone())
            }
            None => (None, None, None, dns_config().0),
        };
        Ok(Route { interface, index, source: Some(source), next_hop, dns_servers })
    }

    pub fn ping(addr: IpAddr, scope: Option<u32>, count: u32, timeout: Duration) -> Result<PingStats, String> {
        if !command_exists("ping") {
            return Err("ping isn't installed".into());
        }
        let target = match (addr, scope) {
            (IpAddr::V6(v6), Some(s)) if (v6.segments()[0] & 0xffc0) == 0xfe80 => format!("{addr}%{s}"),
            _ => addr.to_string(),
        };
        let wait = timeout.as_secs().max(1).to_string();
        let count = count.to_string();
        let run = |fast: bool| {
            let mut c = cmd("ping");
            c.args(["-n", "-c", &count, "-W", &wait]);
            if fast {
                c.args(["-i", "0.2"]);
            }
            c.arg(&target).env("LC_ALL", "C");
            capture(c)
        };
        // -i 0.2 keeps four echoes under a second; BusyBox ping lacks it.
        let mut out = run(true)?;
        if linux_summary(&out.stdout).is_none() {
            out = run(false)?;
        }
        linux_summary(&out.stdout).ok_or_else(|| {
            let said = out.combined();
            let said = crate::parse::text::first_line(&said);
            if said.is_empty() { "ping gave no result".to_string() } else { said.to_string() }
        })
    }

    pub fn http_get(url: &str, timeout: Duration) -> Result<String, String> {
        if !command_exists("curl") {
            return Err("curl isn't installed".into());
        }
        let mut c = cmd("curl");
        c.args(["-sS", "--fail", "--max-time", &timeout.as_secs().max(1).to_string(), "-A", "itriage", url]);
        let out = capture(c)?;
        if out.success() {
            Ok(out.stdout)
        } else {
            Err(format!("{url}: {}", crate::parse::text::first_line(out.stderr.trim())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_addresses_skip_link_local() {
        for no in ["127.0.0.1", "169.254.10.20", "fe80::1", "::1", "0.0.0.0"] {
            assert!(!is_usable(no.parse().unwrap()), "{no}");
        }
        for yes in ["10.20.33.118", "2001:db8::5"] {
            assert!(is_usable(yes.parse().unwrap()), "{yes}");
        }
        assert!(is_apipa("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn tcp_checks_try_every_address_within_the_budget() {
        let open = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = open.local_addr().unwrap().port();
        let check = tcp_check(&["127.0.0.1".parse().unwrap()], port, Duration::from_millis(1500));
        let (addr, _) = check.connected().expect("connects");
        assert_eq!(addr.to_string(), "127.0.0.1");

        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let both: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        let check = tcp_check(&both, closed, Duration::from_millis(1500));
        assert!(check.connected().is_none());
        #[cfg(not(windows))]
        assert_eq!(check.attempts.len(), 2, "{check:?}");
        assert!(check.error().contains("127.0.0.1"), "{}", check.error());
        let none = tcp_check(&both, closed, Duration::ZERO);
        assert!(none.budget_exhausted && none.attempts.is_empty());
    }

    #[test]
    fn literals_resolve_without_dns() {
        let r = resolve("10.1.2.3").unwrap();
        assert_eq!(r.addresses, vec!["10.1.2.3".parse::<IpAddr>().unwrap()]);
        assert!(resolve("no-such-host.invalid").is_err());
        let localhost = resolve("localhost").unwrap();
        assert!(localhost.addresses.iter().all(|a| a.is_loopback()));
    }

    #[test]
    fn dns_queries_time_a_server_directly() {
        // A one-shot fake DNS server on localhost.
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let answer = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let mut reply = buf[..n].to_vec();
            reply[2] |= 0x80; // a response
            reply[7] = 1; // one answer
            server.send_to(&reply, from).unwrap();
        });
        let (reply, rtt) = dns_query_at(addr, "www.example.org", Duration::from_secs(2)).unwrap();
        answer.join().unwrap();
        assert!(reply.answered() && reply.answers == 1);
        assert!(rtt < Duration::from_secs(2));

        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = dns_query_at(silent.local_addr().unwrap(), "example.org", Duration::from_millis(150)).unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert!(dns_query("127.0.0.1".parse().unwrap(), "bad..name", Duration::from_millis(50)).is_err());
    }

    #[test]
    fn egress_urls_fall_back_only_for_the_default() {
        assert_eq!(egress_urls(""), Vec::<String>::new());
        assert_eq!(egress_urls("https://ip.example.org").len(), 1);
        assert_eq!(egress_urls(crate::profile::DEFAULT_EGRESS_URL).len(), 2);
        let none = egress_ip(&["http://insecure.example".into()], Duration::from_millis(10));
        assert!(none.is_err(), "plain http is never used");
    }

    #[test]
    fn routes_read_like_sentences() {
        let r = Route {
            interface: Some("Wi-Fi".into()),
            next_hop: Some("10.20.32.1".parse().unwrap()),
            source: Some("10.20.33.118".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(r.describe(), "via 10.20.32.1 on Wi-Fi (from 10.20.33.118)");
        let direct = Route { interface: Some("Ethernet".into()), ..Default::default() };
        assert_eq!(direct.describe(), "direct on Ethernet");
    }
}
