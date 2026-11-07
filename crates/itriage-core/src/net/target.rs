//! Destination test: Invoke-NetTriage's single-target diagnostic for "I can't
//! reach X". Resolves the name, tries a TCP connect on each port across every
//! address it resolves to, then shows the route the OS picks for it (which
//! interface, which gateway: the quickest way to spot traffic going around a
//! VPN, or into one) and pings it. Read-only.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::net;
use crate::parse::ping::ms;
use std::net::IpAddr;

pub struct DestinationTest;

impl TriageModule for DestinationTest {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "net.target",
            "Destination test",
            Category::Network,
            "DNS, a TCP connect on each port, the route the PC picks, and ping, for one host you type in (ports default to 443, 80, 445, 3389).",
        )
        .takes_target()
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let Some(target) = ctx.target() else {
            return Ok(Output::new(
                "Skipped: no destination given",
                vec![Finding::info(
                    "Destination",
                    "none given: type a host name or address, with ports if they aren't 443, 80, 445 and 3389",
                )],
            ));
        };
        let profile = ctx.profile();
        let (settings, th) = (&profile.network, &profile.thresholds);
        let host = target.host.as_str();
        let ports = if target.ports.is_empty() { settings.target_ports.clone() } else { target.ports.clone() };
        let mut findings = Vec::new();

        // --- DNS ---
        ctx.log(format!("Resolving {host}…"));
        let addresses: Vec<IpAddr> = match net::resolve(host) {
            Ok(r) => {
                let list = r.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
                findings.push(if r.elapsed.is_zero() {
                    Finding::info(format!("DNS {host}"), "an address; no lookup needed")
                } else {
                    let t = r.elapsed.as_secs_f64() * 1000.0;
                    Finding::new(format!("DNS {host}"), format!("{list} · resolved in {}", ms(t)), th.dns_ms.high(t))
                        .with_metric(t, "ms", true)
                });
                r.addresses
            }
            Err(e) => {
                findings.push(Finding::crit(format!("DNS {host}"), e).with_action(crate::actions::offer("flush-dns", None)));
                for port in &ports {
                    findings.push(Finding::crit(format!("{host}:{port}"), "not tried: the name doesn't resolve"));
                }
                return Ok(Output::new(format!("{host} doesn't resolve"), findings));
            }
        };

        // --- TCP, every port at once ---
        ctx.log(format!("Connecting to {host} on port{} {}…", if ports.len() == 1 { "" } else { "s" },
            ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")));
        let checks = net::parallel(&ports, |p| net::tcp_check(&addresses, *p, settings.tcp_timeout()));
        let mut open = 0;
        for check in &checks {
            let label = format!("{host}:{}", check.port);
            findings.push(match check.connected() {
                Some((addr, d)) => {
                    open += 1;
                    let t = d.as_secs_f64() * 1000.0;
                    let via = if addresses.len() > 1 || addr.to_string() != host { format!(" ({addr})") } else { String::new() };
                    Finding::new(label, format!("open · connected in {}{via}", ms(t)), th.network_rtt_ms.high(t))
                        .with_metric(t, "ms", true)
                }
                None => Finding::crit(label, format!("no connection: {}", check.error())),
            });
        }

        // NetTriage's "selected address": the first one that connected.
        let selected = checks
            .iter()
            .find_map(|c| c.connected().map(|(a, _)| a))
            .unwrap_or(addresses[0]);

        // --- Route ---
        let route = net::route_to(selected);
        let scope = route.as_ref().ok().and_then(|r| r.index);
        match &route {
            Ok(r) => {
                let vpn = r.interface.as_deref().is_some_and(|i| {
                    net::interfaces()
                        .ok()
                        .and_then(|list| list.into_iter().find(|x| x.name == i))
                        .is_some_and(|x| {
                            crate::parse::net::is_vpn_adapter(&x.description) || crate::parse::net::is_tunnel_interface(&x.name)
                        })
                });
                let mut f = Finding::info(format!("Route to {host}"), r.describe());
                let mut notes = Vec::new();
                if vpn {
                    notes.push("through the VPN tunnel".to_string());
                }
                if !r.dns_servers.is_empty() {
                    notes.push(format!(
                        "DNS servers on that interface: {}",
                        r.dns_servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")
                    ));
                }
                f = f.with_detail(notes.join(" · "));
                findings.push(f);
            }
            Err(e) => findings.push(Finding::warn(format!("Route to {host}"), e.clone())),
        }

        // --- Ping ---
        ctx.log(format!("Pinging {selected}…"));
        let ping_text = match net::ping(selected, scope, settings.ping_count, settings.ping_timeout()) {
            Ok(stats) => {
                let loss = stats.loss_pct();
                match stats.avg_ms {
                    Some(avg) => {
                        let severity = worst(th.network_rtt_ms.high(avg), th.packet_loss_pct.high(loss));
                        findings.push(Finding::new(format!("Ping {host}"), stats.describe(), severity).with_metric(avg, "ms", true));
                        Some(format!("ping {}", ms(avg)))
                    }
                    None => {
                        findings.push(
                            Finding::warn(format!("Ping {host}"), "no reply · 100% loss")
                                .with_detail("Many servers and firewalls drop ping; the port results above are the better test."),
                        );
                        Some("no ping reply".into())
                    }
                }
            }
            Err(e) => {
                findings.push(Finding::info(format!("Ping {host}"), format!("couldn't ping: {e}")));
                None
            }
        };

        let mut summary = format!("{host}: {open} of {} port{} open", ports.len(), if ports.len() == 1 { "" } else { "s" });
        if let Some(p) = ping_text {
            summary.push_str(&format!(" · {p}"));
        }
        Ok(Output::new(summary, findings))
    }
}

fn worst(a: Severity, b: Severity) -> Severity {
    if a.rank() >= b.rank() {
        a
    } else {
        b
    }
}
