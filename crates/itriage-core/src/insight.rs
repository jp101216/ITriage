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

    // --- Certificates that can't be checked for revocation. Whatever checks
    // them (the 802.1X RADIUS server, a VPN gateway) then refuses them.
    let revocation = v.problems("desk.certs", |f| f.label.starts_with("Revocation: "));
    if !revocation.is_empty() {
        let auth = v
            .find("net.wifi-auth", |f| f.label.starts_with("Wireless session history") && bad(f))
            .or_else(|| v.find("net.wired-auth", |f| f.label == "Wired 802.1X" && bad(f)));
        let mut evidence: Vec<String> = revocation.iter().map(|h| cite(*h)).collect();
        evidence.extend(auth.map(cite));
        let expired = revocation.iter().any(|(_, f)| f.value.contains("EXPIRED") || f.value.contains("REVOKED"));
        let (rank, cause) = match (auth.is_some(), expired) {
            (true, _) => (89, "Network sign-in with this PC's certificate is failing, and the certificate can't be checked for revocation: the RADIUS server refuses a certificate it can't check."),
            (false, true) => (81, "The certificate authority's revocation list has expired or the certificate is revoked: 802.1X, VPN and smart-card sign-in fail for every PC with a certificate from it."),
            (false, false) => (49, "This PC's certificate can't be checked for revocation right now. If the list stays out of reach, network sign-in with it will start failing."),
        };
        out.push(insight(
            rank,
            if auth.is_some() || expired { Severity::Critical } else { worst(&revocation) },
            cause,
            evidence,
            "Have the PKI team publish a fresh CRL (certutil -CRL on the CA) and check the distribution point answers from the RADIUS server's network.",
        ));
    }

    // --- Wired 802.1X and NAC.
    if let Some(h) = v.problem("net.wired-auth", "NAC quarantine") {
        out.push(insight(
            92,
            Severity::Critical,
            "NAC put this PC in its remediation VLAN: the network works, but the systems it needs can't be reached from there.",
            vec![cite(h)],
            "Look up this PC in ISE or ClearPass to see which posture check failed (agent, antivirus, patches), fix that, then reconnect the cable.",
        ));
    }
    if revocation.is_empty() {
        if let Some(h) = v.find("net.wired-auth", |f| f.label == "Wired 802.1X" && f.severity == Severity::Critical) {
            let cert = h.1.value.to_ascii_lowercase().contains("certificate") || h.1.value.contains("revocation");
            out.push(insight(
                86,
                Severity::Critical,
                "Wired 802.1X is failing, so the switch port won't let this PC on (or puts it in a guest VLAN).",
                vec![cite(h)],
                if cert {
                    "The failure names a certificate: check Machine certificates on this PC, then the RADIUS server's log for why it rejected it."
                } else {
                    "Check the RADIUS (NPS, ISE, ClearPass) log for this PC's identity at that time; it says why it refused."
                },
            ));
        }
    }
    if let Some(h) = v.problem("net.wired-auth", "Wired AutoConfig service") {
        out.push(insight(61, Severity::Warning, "Wired AutoConfig is stopped although this PC uses wired 802.1X, so it can't authenticate on the port.", vec![cite(h)], "Start the Wired AutoConfig service and check the policy that should set it to Automatic."));
    }

    // --- Linux domain join.
    if let Some(h) = v.problem("desk.domain", "SSSD configuration") {
        out.push(insight(83, Severity::Critical, "SSSD won't start because sssd.conf has the wrong owner or permissions, so domain sign-in fails.", vec![cite(h)], "chmod 600 /etc/sssd/sssd.conf, chown root:root, then systemctl restart sssd."));
    } else if let Some(h) = v.find("desk.domain", |f| f.label == "Machine account" && f.severity == Severity::Critical) {
        out.push(insight(82, Severity::Critical, "This PC's domain machine account no longer works, so domain sign-in and Kerberos fail.", vec![cite(h)], "Rejoin the domain: realm leave, then realm join (with an account allowed to join computers)."));
    } else if let Some(h) = v.find("desk.domain", |f| f.label.starts_with("Domain ") && f.value.starts_with("offline")) {
        out.push(insight(64, Severity::Warning, "SSSD can't reach the domain, so only people with cached credentials can sign in.", vec![cite(h)], "Check DNS for the domain's SRV records and that a domain controller answers from this network; then sssctl domain-status again."));
    }

    // --- A server rejecting tickets, or tickets that are about to stop working.
    let rejected = v.problems("desk.identity", |f| f.label.starts_with("Kerberos ticket rejected by "));
    if !rejected.is_empty() {
        let names: Vec<&str> = rejected.iter().map(|(_, f)| f.label.trim_start_matches("Kerberos ticket rejected by ")).collect();
        out.push(insight(
            83,
            Severity::Critical,
            format!("{} can't read this PC's Kerberos tickets (KRB_AP_ERR_MODIFIED), so its shares and sites keep asking for a password.", names.join(" and ")),
            rejected.iter().map(|h| cite(*h)).collect(),
            "Find the duplicate SPN (setspn -X) or reset the server's computer account password, then clear the cached tickets here.",
        ));
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
    // Only what was measured. A ping that couldn't be sent says nothing about
    // the network, and neither does a gateway that answers no pings at all
    // while traffic gets through it: plenty of routers are set not to reply.
    let reaches_out = v.find("net.connectivity", |f| f.label.starts_with("Outbound TCP") && !bad(f)).is_some();
    let gateway: Vec<Hit> = v
        .problems("net.latency", |f| f.label.starts_with("Gateway") && (f.label.ends_with("round trip") || f.label.ends_with("packet loss")))
        .into_iter()
        .filter(|(_, f)| !(reaches_out && (f.value == "no reply" || f.value.starts_with("100%"))))
        .collect();
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
        // When the space check ran too, it says where the space went: what
        // it flagged as clearable, or failing that its biggest folder.
        let mut evidence: Vec<String> = full.iter().map(|h| cite(*h)).collect();
        let clearable = v.problems("system.storage", |_| true);
        let measured = v.module("system.storage").is_some();
        let bin = if cfg!(windows) { "Recycle Bin" } else { "Trash" };
        let next = if !clearable.is_empty() {
            evidence.extend(clearable.iter().take(3).map(|h| cite(*h)));
            format!("Start with what the space check flagged. Clear temp files and empty the {bin} (in the Tune-up checks), then move or remove large files.")
        } else if measured {
            evidence.extend(v.find("system.storage", |f| !f.label.ends_with(" in use") && !f.label.ends_with("(whole profile)")).map(cite));
            "Nothing that can simply be cleared stands out: go through the biggest folders with the person whose PC it is.".to_string()
        } else {
            format!("Run What's using the space to see where it went. Clearing temp files and emptying the {bin} (in the Tune-up checks) is the quick win.")
        };
        out.push(insight(
            if worst(&full) == Severity::Critical { 82 } else { 56 },
            worst(&full),
            format!("{} is nearly full ({}). The PC slows down, and updates and saves start failing, when it runs out of space.", f.label, head(&f.value)),
            evidence,
            &next,
        ));
    }

    // --- Slow to start.
    if let Some(h) = v.problem("system.startup", "Last start") {
        let mut evidence = vec![cite(h)];
        let held_up = v.problems("system.startup", |f| f.label.starts_with("Slowed startup: "));
        evidence.extend(held_up.iter().take(2).map(|h| cite(*h)));
        evidence.extend(v.problem("system.startup", "Startup apps").map(cite));
        let next = if let Some((_, f)) = held_up.first() {
            format!(
                "{} has slowed startup more than once: update it, or stop it starting with the PC. Then switch off the startup apps nobody needs.",
                f.label.trim_start_matches("Slowed startup: ")
            )
        } else {
            "Switch off the startup apps nobody needs. If it's still slow, look at the drive: a failing or nearly full one slows every start.".to_string()
        };
        out.push(insight(
            if h.1.severity == Severity::Critical { 50 } else { 42 },
            h.1.severity,
            format!("This PC is slow to start: {}.", head(&h.1.value)),
            evidence,
            &next,
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

    // --- A processor held back by firmware or heat. It shows as a busy
    // CPU, and would otherwise be blamed on whichever program is busiest.
    let held_back: Vec<Hit> = v
        .problems("system.hardware", |f| f.label == "Processor clock" || f.label == "Firmware speed limits (7 days)" || f.label == "Thermal throttling since start")
        .into_iter()
        .filter(|(_, f)| f.severity.rank() >= Severity::Warning.rank())
        .collect();
    let busy = v.problem("proc.top", "CPU load");
    if !held_back.is_empty() {
        let mut evidence: Vec<String> = held_back.iter().map(|h| cite(*h)).collect();
        evidence.extend(busy.map(cite));
        out.push(insight(
            if busy.is_some() { 77 } else { 60 },
            Severity::Warning,
            if busy.is_some() {
                "The processor is being held back by firmware or heat while it's busy, so everything is slow. It isn't one program's fault, even though one shows as busiest."
            } else {
                "The processor is running below its rated speed: firmware or heat is limiting it."
            },
            evidence,
            "Check the charger's wattage and the dock, then the vents and fan. On a laptop, try it on mains power without the dock.",
        ));
    }
    let hardware: Vec<Hit> = v.problems("system.hardware", |f| f.label.contains("processor errors") || f.label.contains("memory errors") || f.label.starts_with("Memory errors"));
    if !hardware.is_empty() {
        out.push(insight(
            if worst(&hardware) == Severity::Critical { 87 } else { 68 },
            worst(&hardware),
            "The hardware is reporting errors: processor or memory faults explain freezes, crashes and corrupted files.",
            hardware.iter().map(|h| cite(*h)).collect(),
            "Run the manufacturer's diagnostics (memory and processor). If errors continue, the part needs replacing.",
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
    if let Some(h) = busy.filter(|_| held_back.is_empty()) {
        let busiest = h.1.detail.as_deref().map(|d| format!(" {d}.")).unwrap_or_default();
        out.push(insight(
            if h.1.severity == Severity::Critical { 75 } else { 51 },
            h.1.severity,
            format!("The processor is busy ({}).{busiest}", h.1.value),
            vec![cite(h)],
            "If one process is using it and shouldn't be, restart that app. A scan or an update finishing explains it too.",
        ));
    }

    // --- A security rule stopping an app (it looks like the app is broken).
    let blocks = v.problems("sec.blocks", |f| f.value.starts_with("blocked") && (f.severity == Severity::Critical || !f.value.ends_with("d ago")));
    if let Some((_, f)) = blocks.first() {
        let (source, rest) = f.label.split_once(": ").unwrap_or(("A security rule", f.label.as_str()));
        let (rule, file) = rest.rsplit_once(" · ").unwrap_or((rest, "a program"));
        let count = f.metric.as_ref().map(|m| m.value as usize).unwrap_or(1);
        out.push(insight(
            if f.severity == Severity::Critical { 85 } else { 66 },
            f.severity,
            format!(
                "{file} is being blocked by security policy, not failing on its own: {source} \"{rule}\" stopped it {}.",
                match count { 1 => "once".to_string(), 2 => "twice".to_string(), n => format!("{n} times") }
            ),
            blocks.iter().take(3).map(|h| cite(*h)).collect(),
            "If it's legitimate, ask security for an exclusion or an allow rule for it. Don't turn the rule off.",
        ));
    }

    // --- A slow sign-in, and the step that took the time.
    if let Some(total) = v.problem("desk.logon", "Last sign-in (profile + Group Policy)") {
        let step = v.find("desk.logon", |f| f.label.starts_with("Policy step: ") && f.severity == Severity::Warning);
        let failed = v.find("desk.logon", |f| f.label.starts_with("Policy step failed: "));
        let dc = v.find("desk.logon", |f| f.label == "Domain controller during policy processing" && f.severity == Severity::Critical);
        let seconds = head(&total.1.value).to_string();
        let mut evidence = vec![cite(total)];
        evidence.extend(step.into_iter().chain(failed).chain(dc).map(cite));
        let (cause, next) = if dc.is_some() {
            (format!("Sign-in took {seconds} because no domain controller answered while policy was applied."), "Check the network connection at sign-in (Wi-Fi that connects only after sign-in, or a VPN that starts later), then DNS for the domain.")
        } else if let Some((_, s)) = step {
            (
                format!("{} took {} of a {seconds} sign-in.", s.label.trim_start_matches("Policy step: "), head(&s.value)),
                "Look at what that policy step does for this user (a large redirected folder, a slow logon script, an unreachable mapped drive) in gpresult /h.",
            )
        } else {
            (format!("Sign-in is slow ({seconds} of profile and policy processing)."), "Compare the policy steps listed under Sign-in speed with a quick PC's, and check the profile's size.")
        };
        out.push(insight(if dc.is_some() { 63 } else { 57 }, total.1.severity, cause, evidence, next));
    }

    // --- Printing.
    if let Some(h) = v.find("desk.printers", |f| (f.label == "Print Spooler" || f.label == "CUPS scheduler") && f.severity == Severity::Critical) {
        out.push(insight(84, Severity::Critical, "Nothing can print because the print service isn't running.", vec![cite(h)], "Restart the Print Spooler."));
    }

    // --- Point and Print: a print server users can't take drivers from.
    if let Some(h) = v.find("desk.printers", |f| f.label.starts_with("Print server ") && bad(f)) {
        let server = h.1.label.trim_start_matches("Print server ");
        out.push(insight(
            58,
            Severity::Warning,
            format!("Adding a printer from {server} asks for an administrator: that server isn't on the approved Point and Print list."),
            vec![cite(h)],
            "Add the server to the approved list in Group Policy, or install its drivers for users ahead of time. Don't open driver installs to everyone.",
        ));
    } else if let Some(h) = v.find("desk.printers", |f| f.label.ends_with(": driver") && bad(f)) {
        out.push(insight(52, Severity::Warning, format!("{}: {}.", h.1.label.trim_end_matches(": driver"), h.1.value), vec![cite(h)], "Switch that printer to a package-aware (v4) driver or Microsoft's IPP class driver."));
    }

    // --- Microsoft 365.
    if let Some(h) = v.find("desk.m365", |f| f.label.starts_with("Outlook data file: ") && bad(f)) {
        let file = h.1.label.trim_start_matches("Outlook data file: ");
        let full = h.1.severity == Severity::Critical;
        out.push(insight(
            if full { 80 } else { 50 },
            h.1.severity,
            if full { format!("Outlook's data file {file} is full, so new mail stops arriving in it.") } else { format!("Outlook's data file {file} is nearly full.") },
            vec![cite(h)],
            "Archive or delete old mail, or for a mailbox cache (.ost) set a shorter \"mail to keep offline\" window. A policy can raise the limit, but a file this size makes Outlook slow.",
        ));
    }
    if let Some(h) = v.problem("desk.m365", "Entra sign-in broker") {
        out.push(insight(78, Severity::Critical, "Microsoft 365 apps can't sign in with the Windows account: the Entra sign-in broker is missing.", vec![cite(h)], "Follow Microsoft's primary refresh token troubleshooting article; the broker comes back with Windows repair, not a script."));
    } else if let Some(h) = v.problem("desk.m365", "Entra sign-in errors (24 h)") {
        out.push(insight(
            55,
            Severity::Warning,
            "Entra sign-in keeps failing on this PC, the usual cause of Outlook and Teams asking for the password again and again.",
            vec![cite(h)],
            "Run dsregcmd /status as the user and check AzureAdPrt, then follow the linked Microsoft article.",
        ));
    }
    if let Some(h) = v.problem("desk.m365", "OneDrive folder backup") {
        out.push(insight(
            62,
            Severity::Warning,
            format!("{} OneDrive isn't running, so files saved there aren't syncing or backed up.", head(&h.1.value).replace(", but OneDrive isn't running", ", but")),
            vec![cite(h)],
            "Start OneDrive from the Start menu and sign in. If it won't stay running, reset it (onedrive.exe /reset) and sign in again.",
        ));
    }
    if let Some(h) = v.problem("desk.m365", "Microsoft 365 Apps") {
        out.push(insight(45, Severity::Warning, "Microsoft 365 Apps are older than the site requires.", vec![cite(h)], "Check its update channel and whether Office updates are reaching this PC; Update Now in any Office app's Account page starts one."));
    }

    // --- Edge IE mode.
    if let Some(h) = v.problem("desk.browser", "Enterprise site list") {
        out.push(insight(
            60,
            Severity::Warning,
            format!("Edge's IE mode site list {}, so older web apps may open in the wrong mode.", h.1.value),
            vec![cite(h)],
            "Open the list's address from this PC; if it fails, check the server or share hosting it and the proxy. edge://compat/enterprise shows what Edge last downloaded.",
        ));
    } else if let Some(h) = v.problem("desk.browser", "IE integration") {
        out.push(insight(40, Severity::Warning, format!("Edge's IE integration is set to {}.", h.1.value), vec![cite(h)], "Set InternetExplorerIntegrationLevel to IE mode (1)."));
    }

    // --- A required device that drops out.
    let drops = v.problems("capture.recording", |f| f.label.starts_with("Peripheral dropped: "));
    if let Some(first) = drops.first() {
        let device = first.1.label.trim_start_matches("Peripheral dropped: ");
        let suspend = v.find("desk.devices", |f| f.label == "USB selective suspend" && f.value.contains("on "));
        let mut evidence: Vec<String> = drops.iter().take(3).map(|h| cite(*h)).collect();
        evidence.extend(suspend.map(cite));
        out.push(insight(
            70,
            Severity::Warning,
            format!("The {} {} during the recording.", device.to_lowercase(), head(&first.1.value)),
            evidence,
            if suspend.is_some() {
                "USB selective suspend is on. If the drops follow idle time, keep USB devices awake (a site opt-in fix); if they happen mid-use, try another port, cable or dock."
            } else {
                "Try another USB port, cable or the dock's port; check Device Manager for the device's own power setting."
            },
        ));
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
    fn a_full_disk_says_where_the_space_went_when_that_was_measured() {
        let disk = || result("system.disk", "Disk space & latency", vec![Finding::crit("C:\\", "4.1 GB free of 237 GB (98% used)").with_metric(2.0, "% free", false)]);
        // Not measured: the advice is to measure.
        let alone = likely_causes(&[disk()]);
        assert!(alone[0].next.starts_with("Run What's using the space"), "{}", alone[0].next);
        // Measured, with something that can simply be cleared.
        let flagged = likely_causes(&[
            disk(),
            result(
                "system.storage",
                "What's using the space",
                vec![
                    Finding::info("C:\\ in use", "233 GB of 237 GB (98%)"),
                    Finding::info("C:\\Users\\jparker (whole profile)", "120.0 GB"),
                    Finding::warn("C:\\Windows.old", "24.0 GB · 10% of what's in use"),
                ],
            ),
        ]);
        assert!(flagged[0].next.starts_with("Start with what the space check flagged"));
        assert!(flagged[0].evidence.iter().any(|e| e.contains("Windows.old: 24.0 GB")), "{:?}", flagged[0].evidence);
        // Measured, and nothing clearable: the biggest folder, not the whole profile.
        let nothing = likely_causes(&[
            disk(),
            result(
                "system.storage",
                "What's using the space",
                vec![
                    Finding::info("C:\\ in use", "233 GB of 237 GB (98%)"),
                    Finding::info("C:\\Users\\jparker (whole profile)", "190.0 GB"),
                    Finding::info("C:\\Users\\jparker\\Videos", "150.0 GB"),
                ],
            ),
        ]);
        assert!(nothing[0].next.starts_with("Nothing that can simply be cleared"));
        assert!(nothing[0].evidence.last().unwrap().contains("Videos: 150.0 GB"), "{:?}", nothing[0].evidence);
    }

    #[test]
    fn a_slow_start_names_what_held_it_up() {
        let found = likely_causes(&[result(
            "system.startup",
            "Startup & sign-in speed",
            vec![
                Finding::warn("Last start", "94.0 s to the desktop · 2h ago · usually 41.0 s"),
                Finding::warn("Slowed startup: Contoso Sync", "Application · 4 times in 30 days · about 21.0 s extra each time"),
                Finding::info("Startup apps", "9 start with the PC: a, b"),
            ],
        )]);
        assert_eq!(found[0].cause, "This PC is slow to start: 94.0 s to the desktop.");
        assert!(found[0].next.starts_with("Contoso Sync has slowed startup more than once"));
        assert_eq!(found[0].evidence.len(), 2, "an ordinary list of startup apps isn't evidence");
        // A quick start is nothing to explain.
        assert!(likely_causes(&[result("system.startup", "Startup & sign-in speed", vec![Finding::ok("Last start", "24.0 s to the desktop · 2h ago")])]).is_empty());
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
    fn a_check_that_couldnt_measure_isnt_a_cause() {
        // Seen on a PC without ping: the latency check warns that it couldn't
        // measure, which is not evidence of a slow network.
        let unmeasured = vec![result("net.latency", "Latency & packet loss", vec![Finding::warn("Gateway 192.0.2.1", "couldn't ping: ping isn't installed")])];
        assert!(likely_causes(&unmeasured).is_empty());
        let silent = result("net.latency", "Latency & packet loss", vec![Finding::crit("Gateway 10.20.32.1 round trip", "no reply"), Finding::crit("Gateway 10.20.32.1 packet loss", "100% (0 of 4 replies)")]);
        assert!(likely_causes(std::slice::from_ref(&silent))[0].cause.starts_with("The connection to the local network is slow or dropping packets"));
        // Seen on a cloud PC: the gateway ignores pings, and traffic flows through it.
        let working = result("net.connectivity", "Network connectivity", vec![Finding::ok("Outbound TCP (8.8.8.8:53)", "connected in 12 ms")]);
        assert!(likely_causes(&[silent.clone(), working.clone()]).is_empty(), "a router that doesn't answer pings isn't a fault");
        // Some replies lost is a fault, whatever else works.
        let lossy = result("net.latency", "Latency & packet loss", vec![Finding::warn("Gateway 10.20.32.1 packet loss", "25% (3 of 4 replies)")]);
        assert_eq!(likely_causes(&[lossy, working]).len(), 1);
    }

    #[test]
    fn a_held_back_processor_is_the_cause_not_the_busiest_program() {
        let results = vec![
            result("proc.top", "Top processes", vec![Finding::crit("CPU load", "97%").with_detail("Busiest: EHRClient.exe 61%")]),
            result("system.hardware", "Throttling & hardware errors", vec![
                Finding::warn("Processor clock", "38% of its maximum · processor 97% busy"),
                Finding::warn("Firmware speed limits (7 days)", "26 reports · limited for 3h 10m in total · last 4m ago"),
            ]),
        ];
        let found = likely_causes(&results);
        assert!(found[0].cause.starts_with("The processor is being held back by firmware or heat"), "{found:#?}");
        assert_eq!(found[0].evidence.len(), 3);
        assert!(!found.iter().any(|i| i.cause.starts_with("The processor is busy")), "the busy CPU is the symptom here");
        // Without the hardware check, a busy CPU is still a busy CPU.
        assert!(likely_causes(&results[..1])[0].cause.starts_with("The processor is busy"));
    }

    #[test]
    fn a_blocked_app_is_named_with_the_rule_that_blocked_it() {
        let results = vec![result("sec.blocks", "Policy blocks", vec![
            Finding::crit("ASR rule: Block all Office applications from creating child processes · natspeak.exe", "blocked 3 times · last 1h ago").with_metric(3.0, "blocks", true),
            Finding::warn("AppLocker: EXE rules: no rule allows it · tool.exe", "blocked once · last 4d ago").with_metric(1.0, "blocks", true),
        ])];
        let found = likely_causes(&results);
        assert_eq!(found.len(), 1, "last week's block isn't today's cause");
        assert_eq!(found[0].cause, "natspeak.exe is being blocked by security policy, not failing on its own: ASR rule \"Block all Office applications from creating child processes\" stopped it 3 times.");
        assert_eq!(found[0].severity, Severity::Critical);
    }

    #[test]
    fn a_slow_sign_in_names_its_slowest_step() {
        let results = vec![result("desk.logon", "Sign-in speed (Group Policy)", vec![
            Finding::warn("Last sign-in (profile + Group Policy)", "63.0 s · 1h ago"),
            Finding::warn("Policy step: Folder Redirection", "41.0 s · 65% of the sign-in"),
            Finding::info("Policy step: Scripts", "5.0 s · 8% of the sign-in"),
        ])];
        assert_eq!(likely_causes(&results)[0].cause, "Folder Redirection took 41.0 s of a 63.0 s sign-in.");
        let mut lost = results.clone();
        lost[0].findings.push(Finding::crit("Domain controller during policy processing", "no domain controller reachable once in 7 days · last 1h ago"));
        assert!(likely_causes(&lost)[0].cause.contains("no domain controller answered"));
    }

    #[test]
    fn an_expired_crl_with_failing_8021x_is_the_cause() {
        let certs = result("desk.certs", "Machine certificates", vec![Finding::crit("Revocation: WS-07.corp.example.org", "CRL EXPIRED 3h ago (next update was due 2026-11-12T12:00 UTC) · chain check: passed")]);
        let wifi = result("net.wifi-auth", "Wi-Fi roaming & network authentication", vec![Finding::warn("Wireless session history (collected events)", "0 successful association(s), 2 disconnect(s), 3 failure(s)")]);
        let both = likely_causes(&[certs.clone(), wifi]);
        assert!(both[0].cause.starts_with("Network sign-in with this PC's certificate is failing"), "{both:#?}");
        assert_eq!(both[0].evidence.len(), 2);
        assert!(likely_causes(&[certs])[0].cause.starts_with("The certificate authority's revocation list has expired"));
    }

    #[test]
    fn microsoft_365_problems_are_named() {
        let r = vec![result("desk.m365", "Outlook, Teams & OneDrive", vec![
            Finding::crit("Outlook data file: jparker@corp.example.org.ost", "50.0 GB · 100% of the 50.0 GB limit: full, Outlook stops adding mail to it"),
            Finding::warn("OneDrive folder backup", "Desktop, Documents are in OneDrive, but OneDrive isn't running"),
            Finding::warn("Entra sign-in errors (24 h)", "12 errors · last 1m ago"),
        ])];
        let found = likely_causes(&r);
        assert_eq!(found[0].cause, "Outlook's data file jparker@corp.example.org.ost is full, so new mail stops arriving in it.");
        assert!(found.iter().any(|i| i.cause == "Desktop, Documents are in OneDrive, but OneDrive isn't running, so files saved there aren't syncing or backed up."), "{found:#?}");
        assert!(found.iter().any(|i| i.cause.starts_with("Entra sign-in keeps failing")));
    }

    #[test]
    fn edge_print_servers_and_device_drops_are_named() {
        let r = vec![
            result("desk.browser", "Edge IE mode site list", vec![Finding::warn("Enterprise site list", "can't be fetched: intranet.example.org answered HTTP 404")]),
            result("desk.printers", "Printers & print queues", vec![Finding::warn("Print server PRN09", "not on the approved list")]),
            result("capture.recording", "Intermittent problem recording", vec![Finding::warn("Peripheral dropped: Scanner", "dropped 2 times · came back")]),
            result("desk.devices", "Devices & peripherals", vec![Finding::info("USB selective suspend", "on plugged in · on on battery")]),
        ];
        let found = likely_causes(&r);
        let causes: Vec<&str> = found.iter().map(|i| i.cause.as_str()).collect();
        assert_eq!(causes[0], "The scanner dropped 2 times during the recording.");
        assert!(found[0].next.starts_with("USB selective suspend is on"));
        assert_eq!(found[0].evidence.len(), 2);
        assert!(causes.contains(&"Edge's IE mode site list can't be fetched: intranet.example.org answered HTTP 404, so older web apps may open in the wrong mode."));
        assert!(causes.iter().any(|c| c.starts_with("Adding a printer from PRN09 asks for an administrator")));
    }

    #[test]
    fn nac_quarantine_and_wired_failures_are_named() {
        let r = vec![result("net.wired-auth", "Wired 802.1X & NAC", vec![
            Finding::crit("NAC quarantine", "Ethernet has 10.250.4.17, in the quarantine subnet 10.250.0.0/16"),
            Finding::crit("Wired 802.1X", "failing: The authenticator is no longer present · 3 times in a row, last 5m ago"),
        ])];
        let found = likely_causes(&r);
        assert!(found[0].cause.starts_with("NAC put this PC in its remediation VLAN"));
        assert!(found[1].cause.starts_with("Wired 802.1X is failing"));
        let with_crl = vec![r[0].clone(), result("desk.certs", "Machine certificates", vec![Finding::crit("Revocation: WS-07", "CRL EXPIRED 3h ago · chain check: passed")])];
        let found = likely_causes(&with_crl);
        assert!(found.iter().any(|i| i.cause.starts_with("Network sign-in with this PC's certificate is failing")));
        assert!(!found.iter().any(|i| i.cause.starts_with("Wired 802.1X is failing")), "the revocation rule already covers it");
    }

    #[test]
    fn linux_domain_problems_are_named() {
        let conf = vec![result("desk.domain", "Domain & Group Policy", vec![Finding::crit("SSSD configuration", "/etc/sssd/sssd.conf is 0644, owned by uid 0")])];
        assert!(likely_causes(&conf)[0].cause.starts_with("SSSD won't start"));
        let offline = vec![result("desk.domain", "Domain & Group Policy", vec![Finding::warn("Domain corp.example.org", "offline: sign-ins use cached credentials")])];
        assert!(likely_causes(&offline)[0].cause.starts_with("SSSD can't reach the domain"));
    }

    #[test]
    fn a_server_rejecting_tickets_is_named() {
        let r = vec![result("desk.identity", "Entra, Kerberos & SSO sign-in", vec![Finding::crit("Kerberos ticket rejected by fs01$", "KRB_AP_ERR_MODIFIED twice in 7 days · last 20m ago")])];
        assert!(likely_causes(&r)[0].cause.starts_with("fs01$ can't read this PC's Kerberos tickets"));
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
