//! "Likely cause": the one or two lines a technician would write at the top
//! of the ticket after reading the whole report.
//!
//! It's a fixed list of rules over the findings, not a guess: each rule
//! names the findings it rests on, so the reader can check it, and says what
//! to do next. When several fire, the ones that explain the most come
//! first (a failing drive before a full one, no network before slow DNS).
//! Rules only read results of checks that really ran; a preview or a module
//! that failed proves nothing.

use crate::model::{Finding, ModuleResult, Severity};
use serde::{Deserialize, Serialize};

/// The most that are shown; past this it's a list, not a diagnosis.
pub const MAX: usize = 3;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Insight {
    pub severity: Severity,
    /// What is most likely wrong, in one or two sentences.
    pub cause: String,
    /// The findings it rests on: "Wi-Fi & VPN: Signal: 42% · weak".
    #[serde(default)]
    pub evidence: Vec<String>,
    /// What to do about it.
    pub next: String,
}

struct View<'a> {
    results: &'a [ModuleResult],
}

type Hit<'a> = (&'a ModuleResult, &'a Finding);

fn bad(f: &Finding) -> bool {
    f.severity.rank() >= Severity::Warning.rank()
}

fn cite((r, f): Hit) -> String {
    format!("{}: {}: {}", r.title, f.label, f.value)
}

/// The part of a value before its first " · ".
fn head(value: &str) -> &str {
    value.split(" · ").next().unwrap_or(value)
}

impl<'a> View<'a> {
    fn module(&self, id: &str) -> Option<&'a ModuleResult> {
        self.results.iter().find(|r| r.module_id == id && r.error.is_none() && !r.preview)
    }

    /// The first finding of a module that passes `test`.
    fn find(&self, id: &str, test: impl Fn(&Finding) -> bool) -> Option<Hit<'a>> {
        let r = self.module(id)?;
        r.findings.iter().find(|f| test(f)).map(|f| (r, f))
    }

    /// A finding by label, only when it's a problem.
    fn problem(&self, id: &str, label: &str) -> Option<Hit<'a>> {
        self.find(id, |f| f.label == label && bad(f))
    }

    fn problems(&self, id: &str, test: impl Fn(&Finding) -> bool) -> Vec<Hit<'a>> {
        match self.module(id) {
            Some(r) => r.findings.iter().filter(|f| bad(f) && test(f)).map(|f| (r, f)).collect(),
            None => Vec::new(),
        }
    }
}

fn insight(rank: u8, severity: Severity, cause: impl Into<String>, evidence: Vec<String>, next: &str) -> (u8, Insight) {
    (rank, Insight { severity, cause: cause.into(), evidence, next: next.to_string() })
}

fn worst(hits: &[Hit]) -> Severity {
    hits.iter().map(|(_, f)| f.severity).max_by_key(|s| s.rank()).unwrap_or(Severity::Warning)
}

/// The rules, each with a rank: the higher it is, the more of the rest it
/// would explain.
fn rules(v: &View) -> Vec<(u8, Insight)> {
    let mut out = Vec::new();

    // --- A drive on its way out explains slowness, freezes and crashes.
    let failing = v.problems("system.reliability", |f| {
        f.label.starts_with("Failure predicted") || (f.label.starts_with("Drive (") && f.severity == Severity::Critical) || (f.label.starts_with("Disk errors") && f.severity == Severity::Critical)
    });
    if !failing.is_empty() {
        out.push(insight(
            100,
            Severity::Critical,
            "A drive is failing. Slowness, freezes and crashes all follow from that.",
            failing.iter().map(|h| cite(*h)).collect(),
            "Back up this PC's data first, then replace the drive.",
        ));
    } else if let Some(h) = v.find("system.reliability", |f| f.label.starts_with("Disk errors") && bad(f)) {
        out.push(insight(
            72,
            Severity::Warning,
            "The drive has been reporting errors, which shows up as pauses and slow file access.",
            vec![cite(h)],
            "Back up the data, then check the drive's health and its cable. Replace it if the errors continue.",
        ));
    }

    // --- The account itself.
    if let Some(h) = v.find("desk.account", |f| f.label == "Account status" && f.severity == Severity::Critical) {
        let locked = h.1.value.starts_with("locked");
        let mut evidence = vec![cite(h)];
        evidence.extend(v.find("desk.account", |f| f.label == "Lockout sources on this PC" && f.severity != Severity::Ok).map(cite));
        out.push(if locked {
            insight(
                96,
                Severity::Critical,
                "The account is locked out, so sign-in, mapped drives and mail all fail.",
                evidence,
                "Clear the lockout sources listed under Sign-in & account lockouts, then unlock the account. Unlocking alone doesn't last.",
            )
        } else {
            insight(96, Severity::Critical, "The account is disabled, so nothing that signs in with it works.", evidence, "Have the account enabled again in the directory.")
        });
    } else if let Some(h) = v.find("desk.account", |f| f.label == "Password" && f.severity == Severity::Critical) {
        let expired = h.1.value.starts_with("expired");
        out.push(insight(
            if expired { 94 } else { 50 },
            Severity::Critical,
            if expired {
                "The password has expired. Sign-in to network resources fails until it's changed."
            } else {
                "The password is about to expire, and sign-in to network resources fails the moment it does."
            },
            vec![cite(h)],
            "Change it with Ctrl+Alt+Del, Change a password, while on the office network or VPN.",
        ));
    } else if let Some(h) = v.find("desk.account", |f| f.label == "Lockout sources on this PC" && f.severity == Severity::Warning) {
        out.push(insight(
            60,
            Severity::Warning,
            "Something on this PC is still using an old password, which is what locks the account.",
            vec![cite(h)],
            "Clear the sources listed under Sign-in & account lockouts.",
        ));
    }

    // --- A destination the technician asked about.
    if let Some(r) = v.module("net.target") {
        let dns = r.findings.iter().find(|f| f.label.starts_with("DNS ") && f.severity == Severity::Critical);
        let closed: Vec<&Finding> = r.findings.iter().filter(|f| f.severity == Severity::Critical && f.value.starts_with("no connection")).collect();
        let none = r.findings.iter().find(|f| f.label.ends_with(" ports") && bad(f));
        if let Some(f) = dns {
            out.push(insight(
                93,
                Severity::Critical,
                format!("{} can't be found: its name doesn't resolve, so nothing was tried beyond DNS.", f.label.trim_start_matches("DNS ")),
                vec![cite((r, f))],
                "Check the name's spelling and the DNS servers this PC uses. If other PCs resolve it, flush the DNS cache here.",
            ));
        } else if !closed.is_empty() {
            let ports: Vec<&str> = closed.iter().map(|f| f.label.as_str()).collect();
            out.push(insight(
                93,
                Severity::Critical,
                format!("This PC reaches the network but {} doesn't accept the connection: the service is down, or a firewall between them blocks it.", ports.join(" and ")),
                closed.iter().map(|f| cite((r, f))).collect(),
                "Try it from another PC. If it fails there too, it's the server or a firewall rule, not this PC.",
            ));
        } else if let Some(f) = none {
            out.push(insight(70, Severity::Warning, format!("{}: {}.", f.label.trim_end_matches(" ports"), f.value), vec![cite((r, f))], "Name the port the service really uses and test again."));
        }
    }

    // --- No network at all.
    let no_net = v.problems("net.connectivity", |f| f.severity == Severity::Critical && (f.label == "Default route" || f.label == "Adapters"));
    if !no_net.is_empty() {
        out.push(insight(
            92,
            Severity::Critical,
            "This PC has no working network connection.",
            no_net.iter().map(|h| cite(*h)).collect(),
            "Check the cable or Wi-Fi first. If the adapter shows connected, restart adapters and renew DHCP.",
        ));
    } else {
        let dns_down = v.problems("net.connectivity", |f| f.severity == Severity::Critical && f.label.starts_with("DNS"));
        let tcp_ok = v.find("net.connectivity", |f| f.label.starts_with("Outbound TCP") && !bad(f)).is_some();
        if !dns_down.is_empty() {
            out.push(insight(
                88,
                Severity::Critical,
                if tcp_ok {
                    "Name lookups are failing while the connection itself works: DNS is the problem, not the network."
                } else {
                    "Name lookups are failing, so sites and servers can't be found by name."
                },
                dns_down.iter().map(|h| cite(*h)).collect(),
                "Flush the DNS cache. If that doesn't help, the DNS servers this PC was given aren't answering.",
            ));
        }
    }

    // --- The clock.
    if let Some(h) = v.find("desk.time", |f| f.label.starts_with("Offset vs") && bad(f)) {
        out.push(insight(
            if h.1.severity == Severity::Critical { 90 } else { 45 },
            h.1.severity,
            "The clock is wrong. Past five minutes of drift, domain sign-in, Wi-Fi (802.1X) and secure sites fail.",
            vec![cite(h)],
            "Resync the clock, then check where it gets its time from.",
        ));
    }

    // --- Crashes.
    if let Some(h) = v.find("system.reliability", |f| f.label.starts_with("Blue screens") && bad(f)) {
        let cause = h.1.detail.as_deref().and_then(|d| d.split("(usually ").nth(1)).and_then(|d| d.split(')').next());
        let pointing = cause.map(|c| format!(" The most common stop code usually means {c}.")).unwrap_or_default();
        out.push(insight(
            86,
            h.1.severity,
            format!("Windows has crashed with a blue screen {} in the last 30 days.{pointing}", times(head(&h.1.value))),
            vec![cite(h)],
            "Update drivers, BIOS and firmware. If the stop code names hardware, run the manufacturer's diagnostics.",
        ));
    }
    if let Some(h) = v.find("system.reliability", |f| f.label.starts_with("Unexpected shutdowns") && bad(f)) {
        out.push(insight(
            58,
            h.1.severity,
            format!("The PC has stopped without shutting down {} in the last 30 days: lost power, or froze so hard it was switched off.", times(head(&h.1.value))),
            vec![cite(h)],
            "On a laptop, check the battery and charger. On a desktop, check the power cable and supply, and that it isn't overheating.",
        ));
    }

    // --- Signed in without a domain controller.
    if let Some(h) = v.find("desk.domain", |f| f.label == "Signed in via" && bad(f)) {
        out.push(insight(
            64,
            Severity::Warning,
            "This PC signed in with cached credentials: no domain controller answered. Password changes, mapped drives and policy don't work until it reaches one.",
            vec![cite(h)],
            "Connect to the office network or VPN, then lock and unlock the PC.",
        ));
    }

    // --- Wi-Fi and the local network.
    let gateway = v.problems("net.latency", |f| f.label.starts_with("Gateway"));
    if let Some(h) = v.problem("desk.wifi", "Signal") {
        let mut evidence = vec![cite(h)];
        evidence.extend(gateway.iter().map(|g| cite(*g)));
        out.push(insight(
            if gateway.is_empty() { 62 } else { 78 },
            h.1.severity,
            format!("Weak Wi-Fi ({}) is the most likely reason for a slow or dropping connection.", head(&h.1.value)),
            evidence,
            "Move closer to the access point or use a wired connection, then run the triage again.",
        ));
    } else if !gateway.is_empty() {
        out.push(insight(
            74,
            worst(&gateway),
            "The connection to the local network is slow or dropping packets, before anything leaves the building.",
            gateway.iter().map(|g| cite(*g)).collect(),
            "On a cable, try another cable and wall port. On Wi-Fi, check the signal. If neighbours have it too, it's the switch or access point.",
        ));
    }

    // --- The site's own servers.
    let down = v.problems("site.checks", |f| f.severity == Severity::Critical);
    if !down.is_empty() {
        let names: Vec<&str> = down.iter().map(|(_, f)| f.label.as_str()).collect();
        out.push(insight(
            80,
            Severity::Critical,
            format!("{} of the site's systems {} answer from this PC: {}.", down.len(), if down.len() == 1 { "doesn't" } else { "don't" }, names.join(", ")),
            down.iter().take(4).map(|h| cite(*h)).collect(),
            "Check from another PC. If it fails there too, it's the server or the network, not this PC.",
        ));
    }

    // --- Running out of room.
    let full = v.problems("system.disk", |f| f.metric.as_ref().is_some_and(|m| m.unit == "% free"));
    if !full.is_empty() {
        let (_, f) = full[0];
        out.push(insight(
            if worst(&full) == Severity::Critical { 82 } else { 56 },
            worst(&full),
            format!("{} is nearly full ({}). The PC slows down, and updates and saves start failing, when it runs out of space.", f.label, head(&f.value)),
            full.iter().map(|h| cite(*h)).collect(),
            "Clear temp files and empty the Recycle Bin, then move or remove large files.",
        ));
    }
    if let Some(h) = v.problem("system.disk", "Disk latency") {
        out.push(insight(
            54,
            h.1.severity,
            "The disk is slow to respond, so everything that reads or writes waits on it.",
            vec![cite(h)],
            "See what's using the disk under Top processes. If nothing is, check Drive health & reliability.",
        ));
    }

    // --- Memory and processor.
    if let Some(h) = v.problem("system.memory", "RAM") {
        let mut evidence = vec![cite(h)];
        evidence.extend(v.find("proc.top", |f| f.label.contains("(pid ") && bad(f)).map(cite));
        out.push(insight(
            if h.1.severity == Severity::Critical { 76 } else { 52 },
            h.1.severity,
            "Memory is nearly full, so the PC is swapping to disk and everything waits.",
            evidence,
            "Close the heaviest apps (Top processes names them). If this is the normal workload, the PC needs more memory.",
        ));
    }
    if let Some(h) = v.problem("proc.top", "CPU load") {
        let busiest = h.1.detail.as_deref().map(|d| format!(" {d}.")).unwrap_or_default();
        out.push(insight(
            if h.1.severity == Severity::Critical { 75 } else { 51 },
            h.1.severity,
            format!("The processor is busy ({}).{busiest}", h.1.value),
            vec![cite(h)],
            "If one process is using it and shouldn't be, restart that app. A scan or an update finishing explains it too.",
        ));
    }

    // --- Printing.
    if let Some(h) = v.find("desk.printers", |f| (f.label == "Print Spooler" || f.label == "CUPS scheduler") && f.severity == Severity::Critical) {
        out.push(insight(84, Severity::Critical, "Nothing can print because the print service isn't running.", vec![cite(h)], "Restart the Print Spooler."));
    }

    // --- One app that keeps failing.
    if let Some(h) = v.find("system.reliability", |f| f.label.starts_with("App crashes") && bad(f)) {
        let app = h.1.detail.as_deref().and_then(|d| d.split(';').next()).unwrap_or("").to_string();
        out.push(insight(
            48,
            Severity::Warning,
            format!("One app keeps failing: {app}."),
            vec![cite(h)],
            "Update or repair that app. If it started after a change, undo the change.",
        ));
    }

    // --- Overdue for a restart.
    let uptime = v.problem("system.info", "Uptime");
    let pending = v.problem("system.info", "Restart pending");
    if uptime.is_some() || pending.is_some() {
        let cause = match (uptime, pending) {
            (Some(u), Some(_)) => format!("This PC has been up for {} with a restart pending. A restart finishes the waiting updates and clears most slow-downs.", u.1.value),
            (Some(u), None) => format!("This PC has been up for {}. A restart clears most slow-downs that build up over time.", u.1.value),
            _ => "A restart is pending: updates or changes are waiting for it to finish.".to_string(),
        };
        out.push(insight(40, Severity::Warning, cause, uptime.into_iter().chain(pending).map(cite).collect(), "Restart the PC at a time that suits the person using it."));
    }

    out
}

/// "3" → "3 times", "1" → "once".
fn times(count: &str) -> String {
    match count.trim() {
        "1" => "once".to_string(),
        "2" => "twice".to_string(),
        n => format!("{n} times"),
    }
}

/// The likeliest causes behind what a run found, most explanatory first.
/// Empty when nothing the rules know about is wrong.
pub fn likely_causes(results: &[ModuleResult]) -> Vec<Insight> {
    let mut found = rules(&View { results });
    found.sort_by_key(|(rank, _)| std::cmp::Reverse(*rank));
    found.into_iter().take(MAX).map(|(_, i)| i).collect()
}

/// The section of the ticket text, or nothing.
pub fn render(insights: &[Insight]) -> Vec<String> {
    let mut out = Vec::new();
    if insights.is_empty() {
        return out;
    }
    out.push("LIKELY CAUSE".to_string());
    for i in insights {
        out.push(format!("- {}", i.cause));
        if !i.evidence.is_empty() {
            out.push(format!("    Because: {}", i.evidence.join("; ")));
        }
        out.push(format!("    Next: {}", i.next));
    }
    out.push(String::new());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Category;

    fn result(id: &str, title: &str, findings: Vec<Finding>) -> ModuleResult {
        ModuleResult {
            module_id: id.into(),
            title: title.into(),
            category: Category::System,
            findings,
            summary: String::new(),
            error: None,
            duration_ms: 1,
            log: Vec::new(),
            restart_required: false,
            preview: false,
        }
    }

    #[test]
    fn a_clean_run_has_no_likely_cause() {
        let results = vec![
            result("system.memory", "Memory usage", vec![Finding::ok("RAM", "6 GB used of 16 GB (38%)")]),
            result("desk.wifi", "Wi-Fi & VPN", vec![Finding::ok("Signal", "88% · strong")]),
        ];
        assert!(likely_causes(&results).is_empty());
        assert!(render(&[]).is_empty());
    }

    #[test]
    fn weak_wifi_explains_a_slow_gateway() {
        let results = vec![
            result("desk.wifi", "Wi-Fi & VPN", vec![Finding::warn("Signal", "42% · weak")]),
            result(
                "net.latency",
                "Latency & packet loss",
                vec![Finding::warn("Gateway (10.20.4.1) round trip", "avg 38 ms (min 4 ms / max 210 ms)"), Finding::warn("Gateway (10.20.4.1) packet loss", "4% (24 of 25 replies)")],
            ),
            result("system.info", "System information", vec![Finding::warn("Uptime", "15d 4h 12m"), Finding::warn("Restart pending", "yes: Windows Update")]),
        ];
        let found = likely_causes(&results);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].cause, "Weak Wi-Fi (42%) is the most likely reason for a slow or dropping connection.");
        assert_eq!(found[0].evidence.len(), 3, "the signal and both gateway measurements: {:?}", found[0].evidence);
        assert_eq!(found[0].evidence[0], "Wi-Fi & VPN: Signal: 42% · weak");
        assert!(found[1].cause.starts_with("This PC has been up for 15d 4h 12m with a restart pending."));
        let text = render(&found).join("\n");
        assert!(text.starts_with("LIKELY CAUSE\n- Weak Wi-Fi (42%)") && text.contains("    Because: Wi-Fi & VPN: Signal: 42% · weak; ") && text.contains("    Next: Move closer"), "{text}");
    }

    #[test]
    fn the_cause_that_explains_the_most_comes_first_and_only_three_are_shown() {
        let results = vec![
            result("system.disk", "Disk space & latency", vec![Finding::crit("C:\\", "4.1 GB free of 237 GB (98% used) · NTFS").with_metric(2.0, "% free", false)]),
            result("system.memory", "Memory usage", vec![Finding::warn("RAM", "13.4 GB used of 16 GB (84%)")]),
            result("proc.top", "Top processes", vec![Finding::warn("CPU load", "81%").with_detail("Busiest: MsMpEng.exe 44%")]),
            result(
                "system.reliability",
                "Drive health & reliability",
                vec![
                    Finding::crit("Drive (KINGSTON SA400S37240G)", "unhealthy · SSD · SATA · 223.6 GB"),
                    Finding::crit("Blue screens (30 days)", "3 · last 1d ago").with_detail("0x0000007A KERNEL_DATA_INPAGE_ERROR ×3 (usually the drive or its cable)"),
                ],
            ),
        ];
        let found = likely_causes(&results);
        assert_eq!(found.len(), MAX);
        assert!(found[0].cause.starts_with("A drive is failing."));
        assert_eq!(found[1].cause, "Windows has crashed with a blue screen 3 times in the last 30 days. The most common stop code usually means the drive or its cable.");
        assert!(found[2].cause.starts_with("C:\\ is nearly full (4.1 GB free of 237 GB (98% used))"), "{}", found[2].cause);
    }

    #[test]
    fn a_locked_account_points_at_its_sources() {
        let results = vec![result(
            "desk.account",
            "Sign-in & account lockouts",
            vec![
                Finding::crit("Account status", "locked out"),
                Finding::warn("Lockout sources on this PC", "2 possible: 2 saved credentials, 1 disconnected session"),
            ],
        )];
        let found = likely_causes(&results);
        assert_eq!(found.len(), 1);
        assert!(found[0].cause.starts_with("The account is locked out"));
        assert_eq!(found[0].evidence.len(), 2);
        assert!(found[0].next.contains("Unlocking alone doesn't last."));

        // Not locked right now, but something here would lock it.
        let warned = vec![result("desk.account", "Sign-in & account lockouts", vec![Finding::info("Account status", "active · 3 wrong passwords since the last good one"), Finding::warn("Lockout sources on this PC", "1 possible: 1 service")])];
        assert!(likely_causes(&warned)[0].cause.starts_with("Something on this PC is still using an old password"));
    }

    #[test]
    fn tells_dns_from_the_network_and_a_server_from_this_pc() {
        let dns = vec![result(
            "net.connectivity",
            "Network connectivity",
            vec![Finding::ok("Default route", "10.20.4.1 via Wi-Fi"), Finding::crit("DNS lookup (www.microsoft.com)", "no such name"), Finding::ok("Outbound TCP (8.8.8.8:53)", "connected in 14 ms")],
        )];
        assert!(likely_causes(&dns)[0].cause.contains("DNS is the problem, not the network"));
        let offline = vec![result("net.connectivity", "Network connectivity", vec![Finding::crit("Default route", "none: this PC can't reach other networks"), Finding::crit("DNS lookup (www.microsoft.com)", "no such name")])];
        let found = likely_causes(&offline);
        assert_eq!(found.len(), 1, "with no route, failing DNS is a symptom");
        assert_eq!(found[0].cause, "This PC has no working network connection.");

        let server = vec![result("net.target", "Destination test", vec![Finding::ok("DNS ehr.example.org", "10.1.2.3 · resolved in 4 ms"), Finding::crit("ehr.example.org:443", "no connection: 10.1.2.3 refused")])];
        assert!(likely_causes(&server)[0].cause.starts_with("This PC reaches the network but ehr.example.org:443 doesn't accept the connection"));
        let name = vec![result("net.target", "Destination test", vec![Finding::crit("DNS ehr.example.org", "ehr.example.org doesn't resolve (no such name)")])];
        assert!(likely_causes(&name)[0].cause.starts_with("ehr.example.org can't be found"));
    }

    #[test]
    fn previews_and_failed_modules_prove_nothing() {
        let mut preview = result("system.memory", "Memory usage", vec![Finding::crit("RAM", "15.5 GB used of 16 GB (97%)")]);
        preview.preview = true;
        let mut failed = result("desk.wifi", "Wi-Fi & VPN", vec![Finding::warn("Signal", "30% · weak")]);
        failed.error = Some("couldn't run".into());
        assert!(likely_causes(&[preview, failed]).is_empty());
        assert_eq!(times("1"), "once");
        assert_eq!(times("14"), "14 times");
    }
}
