//! Network connectivity: interface IPs, DNS resolution, and an outbound TCP
//! reachability probe. Read-only.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use sysinfo::Networks;

pub struct Connectivity;

impl TriageModule for Connectivity {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "net.connectivity",
            "Network connectivity",
            Category::Network,
            "Interface IPs, DNS resolution, and an outbound TCP reachability test.",
        )
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let mut findings = Vec::new();

        // --- Interfaces with addresses ---
        let networks = Networks::new_with_refreshed_list();
        let mut active = 0;
        for (name, data) in &networks {
            let ips: Vec<String> = data
                .ip_networks()
                .iter()
                .map(|n| format!("{}/{}", n.addr, n.prefix))
                .collect();
            if ips.is_empty() {
                continue;
            }
            active += 1;
            findings.push(Finding::info(format!("Interface {name}"), ips.join(", ")));
        }
        if active == 0 {
            findings.push(Finding::warn("Interfaces", "no interfaces report an IP address"));
        }

        // --- DNS resolution ---
        let dns_ok = "example.com:443"
            .to_socket_addrs()
            .map(|mut addrs| addrs.next().is_some())
            .unwrap_or(false);
        findings.push(Finding::new(
            "DNS resolution (example.com)",
            if dns_ok { "resolved" } else { "failed" },
            if dns_ok { Severity::Ok } else { Severity::Critical },
        ));

        // --- Outbound TCP reachability ---
        let target: SocketAddr = "1.1.1.1:443".parse().expect("valid literal socket address");
        let tcp_ok = TcpStream::connect_timeout(&target, Duration::from_secs(3)).is_ok();
        findings.push(Finding::new(
            "Outbound TCP (1.1.1.1:443)",
            if tcp_ok { "reachable" } else { "unreachable" },
            if tcp_ok { Severity::Ok } else { Severity::Critical },
        ));

        let summary = match (dns_ok, tcp_ok) {
            (true, true) => "Connectivity OK.",
            (false, _) => "DNS resolution is failing.",
            (_, false) => "No outbound connectivity.",
        };
        Ok(Output::new(summary, findings))
    }
}
