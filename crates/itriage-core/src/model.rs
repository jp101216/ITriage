//! Shared result types. Everything here is `serde`-serializable so the Tauri
//! command layer can hand it straight to the frontend as JSON, and the JSON /
//! ticket-text exports fall out of the same structs.

use serde::{Deserialize, Serialize};

/// How alarming a single finding is. Drives the colour chip in the UI and the
/// worst-of roll-up on a module card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Critical,
}

impl Severity {
    /// Higher = worse. Used to roll a module's findings up to one status.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Ok => 0,
            Severity::Info => 1,
            Severity::Warning => 2,
            Severity::Critical => 3,
        }
    }
}

/// Which bucket a module lives in. The frontend groups the checklist by this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    System,
    Network,
    Processes,
    Eventlog,
    /// Service-desk workstation checks: time, domain, printers, devices, Wi-Fi, certs, battery.
    Workstation,
    /// Site-profile driven checks: required apps, services and endpoints.
    Site,
    /// Network-stack repair (the Endpoint Tune-Up network phase).
    Repair,
    /// Cleanup and maintenance: temp files, image repair, drives, policy.
    Fixes,
    Updates,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::System => "System",
            Category::Network => "Network",
            Category::Processes => "Processes & services",
            Category::Eventlog => "Event log",
            Category::Workstation => "Workstation",
            Category::Site => "Site & clinical",
            Category::Repair => "Network repair",
            Category::Fixes => "Cleanup & maintenance",
            Category::Updates => "Updates",
        }
    }
}

/// A one-click fix offered on a finding ("Restart Print Spooler"). The core
/// strips actions the active site policy doesn't allow before results leave
/// the engine, and re-checks the policy when the fix actually runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixRef {
    /// Built-in fix id, e.g. `restart-spooler`, `start-service`.
    pub id: String,
    /// Button text.
    pub label: String,
    /// What the fix acts on, e.g. a service name for `start-service`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub requires_admin: bool,
}

/// A knowledge-base article linked to a finding by the site profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KbLink {
    pub title: String,
    pub url: String,
}

/// A measured number behind a finding (connect time, packet loss, signal),
/// kept so two runs can be compared value by value, not just by severity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    pub value: f64,
    /// "ms", "%", "s", "days"…
    pub unit: String,
    /// `true` for latency, loss and "% used"; `false` for signal, free space
    /// and battery health, where a lower number is the worse one.
    pub higher_is_worse: bool,
}

/// One line of a report: a labelled value with a severity, plus an optional
/// second line of detail (an event's message, a package's description…).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub label: String,
    pub value: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<FixRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kb: Option<KbLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<Metric>,
}

impl Finding {
    pub fn new(label: impl Into<String>, value: impl Into<String>, severity: Severity) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            severity,
            detail: None,
            action: None,
            kb: None,
            metric: None,
        }
    }
    pub fn ok(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(label, value, Severity::Ok)
    }
    pub fn info(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(label, value, Severity::Info)
    }
    pub fn warn(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(label, value, Severity::Warning)
    }
    pub fn crit(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(label, value, Severity::Critical)
    }
    /// Attach a muted second line, shown under the row in the UI and indented
    /// under it in the ticket-text export.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if !detail.trim().is_empty() {
            self.detail = Some(detail);
        }
        self
    }
    /// Offer a one-click fix on this finding (see `crate::actions`).
    pub fn with_action(mut self, action: FixRef) -> Self {
        self.action = Some(action);
        self
    }
    /// Record the measured number behind this finding, for run-to-run compare.
    pub fn with_metric(mut self, value: f64, unit: &str, higher_is_worse: bool) -> Self {
        if value.is_finite() {
            self.metric = Some(Metric {
                value,
                unit: unit.to_string(),
                higher_is_worse,
            });
        }
        self
    }
}

/// A destination the user asked to test: the NetTriage single-target
/// diagnostic (DNS, route, ping, and a TCP connect per port).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

impl Target {
    /// Parse what someone typed: `host`, `host:443`, `host 443,445`,
    /// `[2001:db8::1]:443` or a bare IPv6 address. No ports means `default_ports`.
    pub fn parse(input: &str, default_ports: &[u16]) -> Result<Target, String> {
        let input = input.trim();
        let (host_part, ports_part) = match input.split_once(char::is_whitespace) {
            Some((h, p)) => (h, Some(p.trim())),
            None => (input, None),
        };
        let (host, inline_ports) = if let Some(rest) = host_part.strip_prefix('[') {
            let (h, after) = rest.split_once(']').ok_or("An IPv6 address in brackets needs its closing ']'.")?;
            (h, after.strip_prefix(':'))
        } else if host_part.matches(':').count() == 1 {
            let (h, p) = host_part.split_once(':').unwrap_or((host_part, ""));
            (h, Some(p))
        } else {
            (host_part, None)
        };
        let ports = match ports_part.or(inline_ports).filter(|p| !p.trim().is_empty()) {
            Some(text) => parse_ports(text)?,
            None => default_ports.to_vec(),
        };
        let host = host.trim();
        let valid = !host.is_empty()
            && host.len() <= 253
            && !host.starts_with('-')
            && host.chars().all(|c| c.is_ascii_alphanumeric() || "-._:%".contains(c));
        if !valid {
            return Err(format!("`{host}` isn't a host name or IP address."));
        }
        Ok(Target { host: host.to_string(), ports })
    }
}

fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in text.split([',', ' ', ';']).map(str::trim).filter(|p| !p.is_empty()) {
        match part.parse::<u16>() {
            Ok(p) if p > 0 => {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
            _ => {
                return Err(format!(
                    "`{part}` isn't a port number (1–65535). Ports go after the host, like fileserver01:445,3389."
                ))
            }
        }
    }
    if ports.len() > 16 {
        return Err("Up to 16 ports at a time.".into());
    }
    Ok(ports)
}

/// What a module produces on a successful run, before timing/error wrapping.
pub struct Output {
    pub findings: Vec<Finding>,
    pub summary: String,
    /// The change this module made needs a restart to finish.
    pub restart_required: bool,
}

impl Output {
    pub fn new(summary: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self {
            findings,
            summary: summary.into(),
            restart_required: false,
        }
    }
    pub fn restart_required(mut self, required: bool) -> Self {
        self.restart_required = required;
        self
    }
}

/// Static description of a module, shown in the checklist before anything runs.
/// Serialize-only: it's sent out to the frontend but never read back into Rust,
/// which lets `platforms` stay `&'static str` without a `Deserialize` lifetime.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: Category,
    /// `true` for anything that changes the box (fixes, installing updates).
    /// The UI asks for confirmation before running any mutating module.
    pub mutating: bool,
    /// Needs administrator/root. On Windows the module fails fast unless the
    /// app is elevated; on Linux it asks for a password through pkexec.
    pub requires_admin: bool,
    /// What to tell the user in the confirmation dialog before it runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// Which OSes this module actually does something useful on.
    pub platforms: Vec<&'static str>,
    /// Set when the active site policy blocks this module; the UI shows it
    /// locked with this reason, and the engine refuses to run it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<String>,
    /// Briefly drops network connectivity (adapter restarts, DHCP renew, policy
    /// refresh) or restarts the machine, so remote-safe mode locks it.
    pub disruptive: bool,
    /// Works on a destination the user types in (host and ports).
    pub takes_target: bool,
}

impl ModuleInfo {
    /// A read-only, cross-platform module. Chain `.mutating()`, `.admin()` and
    /// `.warning(..)` for anything stronger.
    pub fn new(id: &str, title: &str, category: Category, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            category,
            mutating: false,
            requires_admin: false,
            warning: None,
            platforms: vec!["windows", "linux"],
            locked: None,
            disruptive: false,
            takes_target: false,
        }
    }
    /// Restrict to one platform (for checks that only make sense there).
    pub fn only(mut self, platform: &'static str) -> Self {
        self.platforms = vec![platform];
        self
    }
    pub fn mutating(mut self) -> Self {
        self.mutating = true;
        self
    }
    pub fn admin(mut self) -> Self {
        self.requires_admin = true;
        self
    }
    pub fn warning(mut self, text: impl Into<String>) -> Self {
        self.warning = Some(text.into());
        self
    }
    pub fn disruptive(mut self) -> Self {
        self.disruptive = true;
        self
    }
    pub fn takes_target(mut self) -> Self {
        self.takes_target = true;
        self
    }
}

/// The outcome of running one module: findings plus timing and any error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub module_id: String,
    pub title: String,
    pub category: Category,
    pub findings: Vec<Finding>,
    pub summary: String,
    pub error: Option<String>,
    pub duration_ms: u128,
    /// The module's progress lines (the run transcript), so saved and opened
    /// reports keep them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<String>,
    /// A change it made needs a restart to finish.
    #[serde(default, skip_serializing_if = "is_false")]
    pub restart_required: bool,
    /// Produced by a preview (what-if) run: nothing was changed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub preview: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl ModuleResult {
    /// A result for a module that didn't run (blocked, or failed to start).
    pub fn failed(info: &ModuleInfo, error: impl Into<String>) -> Self {
        Self {
            module_id: info.id.clone(),
            title: info.title.clone(),
            category: info.category,
            findings: Vec::new(),
            summary: String::new(),
            error: Some(error.into()),
            duration_ms: 0,
            log: Vec::new(),
            restart_required: false,
            preview: false,
        }
    }

    /// Worst severity across findings, or `Critical` if the module errored.
    /// This is what the frontend turns into the card's status chip.
    pub fn status(&self) -> Severity {
        if self.error.is_some() {
            return Severity::Critical;
        }
        self.findings
            .iter()
            .map(|f| f.severity)
            .max_by_key(|s| s.rank())
            .unwrap_or(Severity::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULTS: [u16; 4] = [443, 80, 445, 3389];

    #[test]
    fn parses_typed_destinations() {
        let t = |s: &str| Target::parse(s, &DEFAULTS).unwrap();
        assert_eq!(t("intranet.example.com"), Target { host: "intranet.example.com".into(), ports: DEFAULTS.to_vec() });
        assert_eq!(t("fileserver01:445").ports, vec![445]);
        assert_eq!(t("fileserver01 445, 139 3389").ports, vec![445, 139, 3389]);
        assert_eq!(t("[2001:db8::1]:443"), Target { host: "2001:db8::1".into(), ports: vec![443] });
        assert_eq!(t("2001:db8::1").ports, DEFAULTS.to_vec(), "a bare IPv6 address keeps the defaults");
        assert_eq!(t("10.0.0.5:80,443").ports, vec![80, 443]);
    }

    #[test]
    fn rejects_bad_destinations() {
        for bad in ["", "-oProxyCommand=x", "host;reboot", "host:0", "host:99999", "a b,c"] {
            assert!(Target::parse(bad, &DEFAULTS).is_err(), "{bad}");
        }
    }

    #[test]
    fn findings_keep_metrics_and_skip_nonsense() {
        let f = Finding::ok("Gateway", "4 ms").with_metric(4.2, "ms", true);
        assert_eq!(f.metric.as_ref().unwrap().value, 4.2);
        assert!(Finding::ok("x", "y").with_metric(f64::NAN, "ms", true).metric.is_none());
    }
}

