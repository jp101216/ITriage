//! Site requirements: the services and network endpoints the site profile
//! says this machine needs. Read-only.
//!
//! Endpoints are Invoke-NetTriage's "core infrastructure": each is resolved,
//! then every address it resolves to is tried within one TCP time budget
//! (1.5 s by default), and the connect time is kept for before/after
//! comparison. They're checked in parallel, so a profile with a dozen of
//! them still finishes in seconds.

use crate::actions::offer;
use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::profile::{Band, EndpointReq};
use std::time::Duration;

pub struct SiteChecks;

impl TriageModule for SiteChecks {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "site.checks",
            "Site services & endpoints",
            Category::Site,
            "Services the site profile requires are running, and the servers it lists (EHR, file, print, license) answer.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let profile = ctx.profile();
        let req = &profile.require;
        if req.service.is_empty() && req.endpoint.is_empty() {
            return Ok(Output::new(
                "No site requirements to check",
                vec![Finding::info(
                    "Site profile",
                    format!(
                        "{} lists no required services or endpoints",
                        if profile.name.is_empty() { "The default profile" } else { profile.name.as_str() }
                    ),
                )],
            ));
        }

        let mut findings = Vec::new();
        for s in &req.service {
            let label = s.label.clone().unwrap_or_else(|| s.name.clone());
            findings.push(match imp::service_state(&s.name) {
                Ok(State::Running) => Finding::ok(label, "running"),
                Ok(State::Missing) => Finding::warn(label, format!("{} isn't installed", s.name)),
                Ok(State::Stopped(state, startable)) => {
                    let mut f = Finding::warn(label, state);
                    if startable && crate::actions::valid_service_name(&s.name) {
                        f = f.with_action(offer("start-service", Some(&s.name)));
                    } else if !startable {
                        f = f.with_detail("It's disabled, so it has to be re-enabled (usually by policy) before it can start.");
                    }
                    f
                }
                Err(e) => Finding::warn(label, e),
            });
        }

        if !req.endpoint.is_empty() {
            ctx.log(format!("Checking {} endpoint(s)…", req.endpoint.len()));
            findings.extend(check_endpoints(
                &req.endpoint,
                profile.network.tcp_timeout(),
                profile.thresholds.network_rtt_ms,
            ));
        }

        let total = findings.len();
        let met = findings.iter().filter(|f| f.severity == Severity::Ok).count();
        let summary = if met == total {
            format!("All {total} site requirements met")
        } else {
            format!("{met} of {total} site requirements met")
        };
        Ok(Output::new(summary, findings))
    }
}

pub(crate) enum State {
    Running,
    /// Stopped; whether starting it can work (it can't while disabled).
    Stopped(String, bool),
    Missing,
}

/// DNS then TCP for every endpoint, all at once.
fn check_endpoints(endpoints: &[EndpointReq], budget: Duration, rtt: Band) -> Vec<Finding> {
    crate::net::parallel(endpoints, |e| probe(e, budget, rtt))
}

fn probe(e: &EndpointReq, budget: Duration, rtt: Band) -> Finding {
    let target = format!("{}:{}", e.host, e.port);
    let addresses = match crate::net::resolve(&e.host) {
        Ok(r) => r.addresses,
        Err(_) => return Finding::crit(e.label.clone(), format!("{} doesn't resolve (DNS)", e.host)),
    };
    let check = crate::net::tcp_check(&addresses, e.port, budget);
    match check.connected() {
        Some((addr, d)) => {
            let t = d.as_secs_f64() * 1000.0;
            let mut f = Finding::new(e.label.clone(), format!("{target} reachable · {}", crate::parse::ping::ms(t)), rtt.high(t))
                .with_metric(t, "ms", true);
            if addr.to_string() != e.host {
                f = f.with_detail(format!("connected to {addr}"));
            }
            f
        }
        None => Finding::crit(e.label.clone(), format!("{target} unreachable ({})", check.error())),
    }
}

#[cfg(windows)]
mod imp {
    use super::State;

    pub fn service_state(name: &str) -> Result<State, String> {
        use crate::win::scm::StartMode;
        Ok(match crate::win::scm::query(name)? {
            None => State::Missing,
            Some(s) if s.running => State::Running,
            Some(s) => {
                let mode = match s.start {
                    StartMode::Auto => "Automatic",
                    StartMode::AutoDelayed => "Automatic (delayed)",
                    StartMode::Manual => "Manual",
                    StartMode::Disabled => "Disabled",
                    StartMode::Unknown => "start type unknown",
                };
                State::Stopped(format!("{} · {mode}", s.state), s.start != StartMode::Disabled)
            }
        })
    }
}

#[cfg(not(windows))]
mod imp {
    use super::State;
    use crate::parse::text::key_values;
    use crate::util::{capture, cmd, command_exists};

    pub fn service_state(name: &str) -> Result<State, String> {
        if !command_exists("systemctl") {
            return Err("systemd not found".into());
        }
        if !crate::actions::valid_service_name(name) {
            return Err(format!("`{name}` isn't a valid unit name"));
        }
        let mut c = cmd("systemctl");
        c.args(["show", "--property=LoadState,ActiveState,SubState", "--", name])
            .env("LC_ALL", "C");
        let out = capture(c)?;
        let kv = key_values(&out.stdout);
        let get = |k: &str| kv.get(k).map(String::as_str).unwrap_or("");
        Ok(match (get("LoadState"), get("ActiveState")) {
            ("not-found", _) => State::Missing,
            (_, "active") => State::Running,
            (_, "") => return Err(format!("systemctl couldn't read {name}")),
            ("masked", active) => State::Stopped(format!("{active} · masked"), false),
            (_, active) => State::Stopped(format!("{active} ({})", get("SubState")), true),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_endpoints_in_parallel() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        }; // dropped, so nothing listens there
        let eps = vec![
            EndpointReq { label: "Open".into(), host: "127.0.0.1".into(), port: open },
            EndpointReq { label: "Closed".into(), host: "127.0.0.1".into(), port: closed },
            EndpointReq { label: "Bogus".into(), host: "no-such-host.invalid".into(), port: 443 },
        ];
        let f = check_endpoints(&eps, Duration::from_millis(1500), crate::profile::Thresholds::default().network_rtt_ms);
        assert_eq!(f[0].severity, Severity::Ok, "{:?}", f[0]);
        assert_eq!(f[1].severity, Severity::Critical);
        // Windows retries SYNs to a closed local port, so it may time out instead.
        #[cfg(not(windows))]
        assert!(f[1].value.contains("refused"), "{}", f[1].value);
        assert!(f[0].metric.is_some(), "connect time is kept for compare");
        assert!(f[2].value.contains("resolve"), "{}", f[2].value);
    }
}
