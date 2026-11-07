//! Network configuration and reachability. Read-only. The network sections of
//! Invoke-NetTriage: adapters and their addresses, the route the OS would
//! actually use (with its gateway and that interface's DNS servers), a timed
//! DNS lookup plus a direct query to each DNS server, an outbound TCP probe,
//! and the public (egress) IP.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::net::{self, Interface};
use crate::parse::dns::rcode_name;
use crate::parse::ping::ms;
use std::net::IpAddr;
use std::time::Duration;

pub struct Connectivity;

impl TriageModule for Connectivity {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "net.connectivity",
            "Network connectivity",
            Category::Network,
            "Adapters and addresses, the route in use with its gateway and DNS servers, a timed DNS lookup, an outbound TCP test and the public IP.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let profile = ctx.profile();
        let (settings, th) = (&profile.network, &profile.thresholds);
        let mut findings = Vec::new();
        let mut problems: Vec<&str> = Vec::new();

        // --- Adapters ---
        ctx.log("Reading network adapters…");
        let interfaces = net::interfaces().unwrap_or_else(|e| {
            findings.push(Finding::warn("Adapters", e));
            Vec::new()
        });
        let active: Vec<&Interface> = interfaces
            .iter()
            .filter(|i| i.up && !i.loopback && !i.addresses.is_empty())
            .collect();
        if active.is_empty() && !interfaces.is_empty() {
            findings.push(Finding::crit("Adapters", "no connected adapter has an address"));
            problems.push("no network connection");
        }
        for i in &active {
            let apipa = i.addresses.iter().any(|a| net::is_apipa(a.ip))
                && !i.usable_addresses().any(|a| a.ip.is_ipv4());
            let label = format!("Interface {}", i.name);
            findings.push(if apipa {
                problems.push("DHCP not answering");
                Finding::warn(label, i.address_list())
                    .with_detail("Self-assigned 169.254 address: DHCP didn't answer on this adapter.")
            } else {
                Finding::info(label, i.address_list()).with_detail(i.description.clone())
            });
        }

        // --- The route in use, its gateway and DNS servers ---
        let all_dns = || {
            let mut list: Vec<IpAddr> = Vec::new();
            for i in &active {
                for s in &i.dns_servers {
                    if !list.contains(s) {
                        list.push(*s);
                    }
                }
            }
            list
        };
        let dns_servers = match net::default_route() {
            Ok(r) => {
                findings.push(Finding::ok("Default route", r.describe()));
                if r.dns_servers.is_empty() { all_dns() } else { r.dns_servers.clone() }
            }
            Err(e) => {
                findings.push(Finding::crit("Default route", "none: this PC can't reach other networks").with_detail(e));
                problems.push("no default route");
                all_dns()
            }
        };
        findings.push(if dns_servers.is_empty() {
            Finding::warn("DNS servers", "none configured")
        } else {
            Finding::info("DNS servers", join(&dns_servers))
        });

        // --- Timed DNS: the system resolver, then each server directly ---
        match settings.dns_probe_name() {
            Some(name) => {
                ctx.log(format!("Resolving {name}…"));
                let label = format!("DNS lookup ({name})");
                match net::resolve(&name) {
                    Ok(r) => {
                        let t = r.elapsed.as_secs_f64() * 1000.0;
                        let severity = th.dns_ms.high(t);
                        if severity.rank() >= Severity::Warning.rank() {
                            problems.push("slow DNS");
                        }
                        let n = r.addresses.len();
                        findings.push(
                            Finding::new(label, format!("resolved in {} · {n} address{}", ms(t), if n == 1 { "" } else { "es" }), severity)
                                .with_metric(t, "ms", true),
                        );
                    }
                    Err(e) => {
                        problems.push("DNS failing");
                        findings.push(Finding::crit(label, e).with_action(crate::actions::offer("flush-dns", None)));
                    }
                }
                let servers: Vec<IpAddr> = dns_servers.iter().take(3).copied().collect();
                if !servers.is_empty() {
                    ctx.log(format!("Asking {} DNS server(s) directly…", servers.len()));
                }
                let replies = net::parallel(&servers, |s| net::dns_query(*s, &name, Duration::from_secs(2)));
                let answered = replies.iter().filter(|r| matches!(r, Ok((reply, _)) if reply.answered())).count();
                for (server, reply) in servers.iter().zip(replies) {
                    let label = format!("DNS server {server}");
                    findings.push(match reply {
                        Ok((reply, rtt)) if reply.answered() => {
                            let t = rtt.as_secs_f64() * 1000.0;
                            Finding::new(label, format!("answers in {}", ms(t)), th.dns_ms.high(t)).with_metric(t, "ms", true)
                        }
                        Ok((reply, _)) => Finding::warn(label, rcode_name(reply.rcode)),
                        Err(e) => {
                            let severity = if answered == 0 { Severity::Critical } else { Severity::Warning };
                            Finding::new(label, format!("not answering ({e})"), severity)
                        }
                    });
                }
            }
            None => findings.push(Finding::info(
                "DNS lookup",
                "skipped: public probes are off and the site profile names no DNS probe",
            )),
        }

        // --- Outbound TCP ---
        if let Some((host, port)) = settings.tcp_probe_target() {
            ctx.log(format!("Connecting to {host}:{port}…"));
            let label = format!("Outbound TCP ({host}:{port})");
            findings.push(match net::resolve(&host) {
                Ok(r) => {
                    let check = net::tcp_check(&r.addresses, port, settings.tcp_timeout());
                    match check.connected() {
                        Some((_, d)) => {
                            let t = d.as_secs_f64() * 1000.0;
                            Finding::new(label, format!("connected in {}", ms(t)), th.network_rtt_ms.high(t))
                                .with_metric(t, "ms", true)
                        }
                        None => {
                            problems.push("no outbound connections");
                            Finding::crit(label, format!("failed: {}", check.error()))
                        }
                    }
                }
                Err(e) => Finding::crit(label, e),
            });
        }

        // --- Public IP ---
        let urls = settings.egress_urls();
        if urls.is_empty() {
            findings.push(Finding::info("Public IP", "lookup off (site profile)"));
        } else {
            ctx.log("Looking up the public IP…");
            findings.push(match net::egress_ip(&urls, Duration::from_secs(5)) {
                Ok(ip) => Finding::info("Public IP", ip.to_string()),
                Err(e) => Finding::info("Public IP", format!("couldn't look it up: {e}")),
            });
        }

        let summary = if problems.is_empty() {
            "Connectivity OK".to_string()
        } else {
            capitalize(&problems.join(", "))
        };
        Ok(Output::new(summary, findings))
    }
}

fn join(ips: &[IpAddr]) -> String {
    ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
}

pub(crate) fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}
