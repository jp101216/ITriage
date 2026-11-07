//! Latency and packet loss to the gateway and the first DNS server, over
//! ICMP, as Invoke-NetTriage measures them (4 echoes, 1 s timeout each, set
//! by the site profile). Read-only.
//!
//! Round trip and loss are separate rows with their own measurements, so a
//! before/after comparison shows each one moving.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::net;
use crate::parse::ping::ms;
use crate::profile::Band;
use std::net::IpAddr;

pub struct Latency;

struct Target {
    kind: &'static str,
    ip: IpAddr,
    scope: Option<u32>,
    rtt: Band,
    /// Gateways are expected to answer ping; DNS servers often filter it.
    must_answer: bool,
}

impl TriageModule for Latency {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "net.latency",
            "Latency & packet loss",
            Category::Network,
            "Round trip and packet loss to the gateway and the first DNS server over ICMP. Warns at 20 ms or 1% loss to the gateway.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let profile = ctx.profile();
        let (settings, th) = (&profile.network, &profile.thresholds);
        let route = match net::default_route() {
            Ok(r) => r,
            Err(e) => {
                return Ok(Output::new(
                    "No default route, so nothing to measure",
                    vec![Finding::crit("Gateway", "no default route").with_detail(e)],
                ))
            }
        };
        let mut targets = Vec::new();
        if let Some(gw) = route.next_hop {
            targets.push(Target { kind: "Gateway", ip: gw, scope: route.index, rtt: th.gateway_rtt_ms, must_answer: true });
        }
        let dns = route.dns_servers.first().copied().or_else(|| {
            net::interfaces().ok()?.into_iter().filter(|i| i.up).flat_map(|i| i.dns_servers).next()
        });
        if let Some(dns) = dns.filter(|d| Some(*d) != route.next_hop) {
            targets.push(Target { kind: "DNS server", ip: dns, scope: route.index, rtt: th.network_rtt_ms, must_answer: false });
        }
        if targets.is_empty() {
            return Ok(Output::new(
                "Nothing to measure: the route has no gateway and no DNS server",
                vec![Finding::info("Gateway", format!("none ({})", route.describe()))],
            ));
        }

        let count = settings.ping_count;
        ctx.log(format!(
            "Pinging {} ({count} echoes each)…",
            targets.iter().map(|t| t.ip.to_string()).collect::<Vec<_>>().join(" and ")
        ));
        let results = net::parallel(&targets, |t| net::ping(t.ip, t.scope, count, settings.ping_timeout()));

        let mut findings = Vec::new();
        let mut parts = Vec::new();
        for (t, result) in targets.iter().zip(results) {
            let name = format!("{} {}", t.kind, t.ip);
            let stats = match result {
                Ok(s) => s,
                Err(e) => {
                    findings.push(Finding::warn(name, format!("couldn't ping: {e}")));
                    continue;
                }
            };
            let loss = stats.loss_pct();
            let silent = stats.received == 0;
            match stats.avg_ms {
                Some(avg) => {
                    findings.push(
                        Finding::new(
                            format!("{name} round trip"),
                            format!(
                                "avg {} (min {} / max {})",
                                ms(avg),
                                ms(stats.min_ms.unwrap_or(avg)),
                                ms(stats.max_ms.unwrap_or(avg))
                            ),
                            t.rtt.high(avg),
                        )
                        .with_metric(avg, "ms", true),
                    );
                    parts.push(format!("{} {}, {loss}% loss", t.kind.to_lowercase(), ms(avg)));
                }
                None => {
                    findings.push(Finding::new(
                        format!("{name} round trip"),
                        "no reply",
                        if t.must_answer { Severity::Critical } else { Severity::Info },
                    ));
                    parts.push(format!("{} not answering", t.kind.to_lowercase()));
                }
            }
            let severity = if silent && !t.must_answer { Severity::Info } else { th.packet_loss_pct.high(loss) };
            let mut f = Finding::new(
                format!("{name} packet loss"),
                format!("{loss}% ({} of {} replies)", stats.received, stats.sent),
                severity,
            )
            .with_metric(loss, "%", true);
            if silent && !t.must_answer {
                f = f.with_detail("Many DNS servers filter ping; the DNS checks in Network connectivity show whether it answers queries.");
            } else if silent {
                f = f.with_detail("Gateways normally answer ping: check the cable or Wi-Fi link, and the switch port.");
            }
            findings.push(f);
        }

        let summary = if parts.is_empty() {
            "Couldn't ping the gateway or DNS server".to_string()
        } else {
            crate::triage::network::capitalize(&parts.join(" · "))
        };
        Ok(Output::new(summary, findings))
    }
}
