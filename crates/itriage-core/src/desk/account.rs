//! Sign-in and account: is the account locked, disabled or about to need a
//! new password, and what on this PC keeps locking it. Read-only; the fixes
//! it offers live in [`crate::actions`].
//!
//! # Why accounts keep locking
//!
//! After a password change, anything still holding the old password keeps
//! trying it, and each try counts toward the lockout. On the PC itself the
//! usual holders are:
//!
//! * credentials saved in Credential Manager (a file server, a Remote
//!   Desktop host, an Office sign-in);
//! * another session of the same person, left disconnected;
//! * a service or a scheduled task set up to run as the person;
//! * someone or something signing in *to* this PC with the old password,
//!   which the Security log records (event 4625).
//!
//! This check lists each of them. What it can't see is the same thing on
//! another device (a phone's mail app, a second PC), so when nothing here
//! explains a lockout it says where to look next.
//!
//! The account's own state comes from a domain controller (or from this PC,
//! for a local account) through the same calls `net user` makes. The
//! grading is plain functions, tested on any OS.

use crate::actions::offer;
use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::profile::Band;
use crate::util::{ago, plural};

pub struct SignInAccount;

impl TriageModule for SignInAccount {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.account",
            "Sign-in & account lockouts",
            Category::Workstation,
            "Whether the signed-in account is locked, disabled or about to need a new password, mapped drives, and what on this PC keeps locking it: saved credentials, stale sessions, services, scheduled tasks and failed sign-ins.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::check(ctx)
    }
}

// ------------------------------------------------------------------ facts

/// What a domain controller (or this PC, for a local account) says about a user.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UserInfo {
    pub locked: bool,
    pub disabled: bool,
    pub password_never_expires: bool,
    pub password_expired: bool,
    pub cannot_change_password: bool,
    pub smartcard_required: bool,
    pub password_age_secs: u64,
    /// Wrong passwords since the last good one, as that server counted them.
    pub bad_password_count: u32,
}

/// The password and lockout rules of a domain (or of this PC).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Policy {
    /// `None`: passwords never expire.
    pub max_password_age_secs: Option<u64>,
    /// Wrong passwords before the account locks; 0 means it never does.
    pub lockout_threshold: u32,
    /// `None`: locked until an administrator unlocks it.
    pub lockout_duration_secs: Option<u64>,
    /// How long wrong passwords are remembered.
    pub lockout_window_secs: u64,
}

/// One entry in the Credential Manager: where it's for and whose it is.
/// Never the secret.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedCredential {
    pub target: String,
    pub user: String,
    /// 1 generic, 2 Windows (domain) password, 4 visible domain password.
    pub kind: u32,
    /// Unix seconds it was last saved.
    pub saved: Option<u64>,
}

/// A sign-in session on this PC.
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: u32,
    /// `DOMAIN\user`; empty for the services session and the sign-in screen.
    pub account: String,
    /// 0 active, 1 connected, 4 disconnected.
    pub state: i32,
    pub station: String,
}

pub const SESSION_DISCONNECTED: i32 = 4;

/// One failed sign-in from the Security log (event 4625).
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub time: u64,
    pub user: String,
    pub domain: String,
    pub logon_type: u32,
    pub process: String,
    pub source: String,
    /// The NTSTATUS that says why: `0xC000006A` is a wrong password.
    pub reason: String,
}

/// A drive letter mapped to a network share.
#[derive(Debug, Clone, PartialEq)]
pub struct MappedDrive {
    pub letter: String,
    pub path: String,
    /// The other account it connects as, when it isn't the signed-in user.
    pub connects_as: Option<String>,
    /// Whether its server answers, in words either way.
    pub reach: Result<String, String>,
}

/// The account being checked, taken apart.
#[derive(Debug, Clone, PartialEq)]
pub struct Who {
    /// As Windows shows it: `CORP\jparker`.
    pub account: String,
    pub domain: String,
    pub user: String,
    /// An account of this PC, not of a domain.
    pub local: bool,
    /// A cloud identity (Microsoft Entra ID, or a personal Microsoft
    /// account), by name. No domain controller knows it.
    pub cloud: Option<&'static str>,
}

impl Who {
    pub fn new(account: &str, hostname: &str) -> Self {
        let (domain, user) = split_account(account);
        let local = domain.is_empty() || domain == "." || domain.eq_ignore_ascii_case(hostname);
        // The "domains" Windows shows for accounts that live in the cloud.
        let cloud = if domain.eq_ignore_ascii_case("AzureAD") {
            Some("Microsoft Entra ID account")
        } else if domain.eq_ignore_ascii_case("MicrosoftAccount") {
            Some("Microsoft account")
        } else {
            None
        };
        Self { account: account.to_string(), domain, user, local, cloud }
    }
}

/// Why a cloud account's state isn't in the report.
pub const CLOUD_STATE: &str = "its sign-in state and password are kept in the cloud, not on a domain controller, so they can't be read from the PC";

/// `CORP\jparker` → (CORP, jparker); `jparker@corp.example.org` →
/// (corp.example.org, jparker); `jparker` → ("", jparker).
pub fn split_account(account: &str) -> (String, String) {
    let account = account.trim();
    if let Some((domain, user)) = account.split_once('\\') {
        (domain.to_string(), user.to_string())
    } else if let Some((user, realm)) = account.rsplit_once('@') {
        (realm.to_string(), user.to_string())
    } else {
        (String::new(), account.to_string())
    }
}

/// Is `candidate` (the name on a saved credential, a service or a task)
/// this account? Deliberately strict about the domain: `jparker@gmail.com`
/// is somebody's mail password, not the CORP account.
pub fn same_account(candidate: &str, who: &Who, hostname: &str, bare_name_counts: bool) -> bool {
    let (domain, user) = split_account(candidate);
    if user.is_empty() || !user.eq_ignore_ascii_case(&who.user) {
        return false;
    }
    if domain.is_empty() {
        return bare_name_counts;
    }
    let first_label = domain.split('.').next().unwrap_or("");
    if who.local {
        domain == "." || domain.eq_ignore_ascii_case(hostname)
    } else {
        domain.eq_ignore_ascii_case(&who.domain)
            || first_label.eq_ignore_ascii_case(&who.domain)
            || who.domain.split('.').next().is_some_and(|d| d.eq_ignore_ascii_case(first_label))
    }
}

/// Account names a fix will act on: no control characters, nothing that
/// could be read as an option.
pub fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_alphanumeric() || "._-$@\\ ".contains(c))
        && name.chars().any(|c| c.is_alphanumeric())
}

// ---------------------------------------------------------------- grading

fn days(secs: u64) -> u64 {
    secs / 86_400
}

fn span(secs: u64) -> String {
    match secs {
        0..=119 => format!("{secs} seconds"),
        120..=7_199 => format!("{} minutes", secs / 60),
        7_200..=172_799 => format!("{} hours", secs / 3_600),
        _ => format!("{} days", secs / 86_400),
    }
}

pub fn who_finding(who: &Who, server: Option<&str>, running_as: Option<&str>) -> Finding {
    let kind = who.cloud.unwrap_or(if who.local { "local account" } else { "domain account" });
    let mut notes = Vec::new();
    if let Some(dc) = server {
        notes.push(format!("Checked on {}.", dc.trim_start_matches('\\')));
    }
    if let Some(me) = running_as.filter(|m| !m.eq_ignore_ascii_case(&who.account)) {
        notes.push(format!("ITriage is running as {me}."));
    }
    Finding::info("Account", format!("{} · {kind}", who.account)).with_detail(notes.join(" "))
}

/// Locked, disabled or fine, with how close it is to locking.
pub fn status_finding(info: &Result<UserInfo, String>, rules: Option<&Policy>, who: &Who, offer_unlock: bool) -> Finding {
    const LABEL: &str = "Account status";
    let info = match info {
        Ok(i) => i,
        Err(why) => return Finding::info(LABEL, format!("couldn't be read: {why}")),
    };
    let threshold = rules.map_or(0, |r| r.lockout_threshold);
    if info.disabled {
        return Finding::crit(LABEL, "disabled").with_detail("Sign-in is refused everywhere until the account is enabled again.");
    }
    if info.locked {
        let unlocks = match rules.and_then(|r| r.lockout_duration_secs) {
            Some(0) | None if rules.is_some() => "It stays locked until someone unlocks it.".to_string(),
            Some(secs) => format!("It unlocks by itself {} after the last wrong password.", span(secs)),
            None => String::new(),
        };
        let mut f = Finding::crit(LABEL, "locked out").with_detail(
            format!("Unlocking it doesn't stop whatever is using the old password: clear the sources below first, or it locks again. {unlocks}")
                .trim()
                .to_string(),
        );
        if offer_unlock {
            f = f.with_action(offer("unlock-account", Some(&who.account)));
        }
        return f;
    }
    match info.bad_password_count {
        0 => Finding::ok(LABEL, "active"),
        n if threshold > 0 && n + 1 >= threshold => {
            Finding::warn(LABEL, format!("active, but one wrong password from locking ({n} of {threshold} used)"))
        }
        n => {
            let of = if threshold > 0 { format!(" (it locks at {threshold})") } else { String::new() };
            Finding::info(LABEL, format!("active · {n} wrong password{} since the last good one{of}", plural(n as usize)))
        }
    }
}

pub fn password_finding(info: &Result<UserInfo, String>, rules: Option<&Policy>, band: Band) -> Option<Finding> {
    const LABEL: &str = "Password";
    const HOW: &str = "Change it with Ctrl+Alt+Del, Change a password, while on the office network or VPN. Then lock and unlock the PC so it uses the new one.";
    let info = info.as_ref().ok()?;
    let changed = match days(info.password_age_secs) {
        0 => "changed today".to_string(),
        1 => "changed yesterday".to_string(),
        n => format!("changed {n} days ago"),
    };
    if info.smartcard_required {
        return Some(Finding::info(LABEL, "smart card sign-in: there's no password to expire"));
    }
    if info.password_expired {
        return Some(Finding::crit(LABEL, format!("expired · {changed}")).with_detail(HOW));
    }
    if info.password_never_expires {
        return Some(Finding::info(LABEL, format!("never expires · {changed}")));
    }
    let Some(max) = rules.and_then(|r| r.max_password_age_secs) else {
        return Some(Finding::info(LABEL, format!("{changed} · no expiry {}", if rules.is_some() { "by policy" } else { "date known" })));
    };
    if info.password_age_secs >= max {
        return Some(Finding::crit(LABEL, format!("expired · {changed}")).with_detail(HOW));
    }
    let left = days(max - info.password_age_secs);
    let severity = band.low(left as f64);
    let when = match left {
        0 => "expires today".to_string(),
        1 => "expires tomorrow".to_string(),
        n => format!("expires in {n} days"),
    };
    let mut f = Finding::new(LABEL, format!("{when} · {changed}"), severity).with_metric(left as f64, "days", false);
    if severity != Severity::Ok {
        f = f.with_detail(HOW);
    }
    Some(f)
}

pub fn policy_finding(rules: Option<&Policy>) -> Option<Finding> {
    const LABEL: &str = "Lockout policy";
    let r = rules?;
    if r.lockout_threshold == 0 {
        return Some(Finding::info(LABEL, "accounts never lock out here"));
    }
    let window = if r.lockout_window_secs > 0 { format!(" within {}", span(r.lockout_window_secs)) } else { String::new() };
    let then = match r.lockout_duration_secs {
        Some(secs) if secs > 0 => format!("unlocks by itself after {}", span(secs)),
        _ => "stays locked until someone unlocks it".to_string(),
    };
    Some(Finding::info(LABEL, format!("locks after {} wrong passwords{window}; {then}", r.lockout_threshold)))
}

fn credential_kind(kind: u32) -> &'static str {
    match kind {
        2 | 4 => "Windows credential",
        _ => "app credential",
    }
}

/// The credentials saved under this account's name. `listed` is an error
/// when they couldn't be read (ITriage runs as someone else).
pub fn saved_finding(listed: &Result<Vec<SavedCredential>, String>, trouble: bool, now: u64) -> Finding {
    const LABEL: &str = "Saved credentials";
    let saved = match listed {
        Ok(s) => s,
        Err(why) => return Finding::info(LABEL, format!("not checked: {why}")),
    };
    if saved.is_empty() {
        return Finding::ok(LABEL, "none saved under this account");
    }
    let names: Vec<String> = saved
        .iter()
        .take(8)
        .map(|c| {
            let when = c.saved.map(|t| format!(", saved {}", ago(now.saturating_sub(t)))).unwrap_or_default();
            format!("{} ({}{when})", c.target, credential_kind(c.kind))
        })
        .collect();
    let more = if saved.len() > 8 { format!("; and {} more", saved.len() - 8) } else { String::new() };
    let value = format!("{} saved under this account", saved.len());
    let detail = format!(
        "{}{more}. Each holds a copy of the password and keeps using it after the password changes.",
        names.join("; ")
    );
    Finding::new(LABEL, value, if trouble { Severity::Warning } else { Severity::Info })
        .with_detail(detail)
        .with_action(offer("clear-saved-credentials", None))
}

/// The account's other, disconnected sessions on this PC.
pub fn session_findings(stale: &[Session]) -> Vec<Finding> {
    stale
        .iter()
        .map(|s| {
            let station = if s.station.is_empty() { String::new() } else { format!(" ({})", s.station) };
            Finding::warn(format!("Disconnected session {}", s.id), format!("{} is still signed in{station}", s.account))
                .with_detail(
                    "A session left behind keeps the password it signed in with. After a password change, everything in it \
                     that reaches the network uses the old one. Signing it out closes its programs; unsaved work in it is lost.",
                )
                .with_action(offer("logoff-session", Some(&s.id.to_string())))
        })
        .collect()
}

pub fn service_finding(services: &[(String, String)]) -> Option<Finding> {
    if services.is_empty() {
        return None;
    }
    let names: Vec<String> = services.iter().map(|(name, display)| if display.is_empty() || display == name { name.clone() } else { format!("{display} ({name})") }).collect();
    Some(
        Finding::warn("Services signing in as this account", format!("{}: {}", services.len(), names.join(", "))).with_detail(
            "A service stores the password it was given. After a password change it fails to start and each try counts \
             toward the lockout. Enter the new password on the service's Log On tab, or better, give it an account of its own.",
        ),
    )
}

pub fn task_finding(tasks: &Result<Vec<String>, String>) -> Option<Finding> {
    const LABEL: &str = "Scheduled tasks with a stored password";
    match tasks {
        Ok(t) if t.is_empty() => None,
        Ok(t) => Some(Finding::warn(LABEL, format!("{}: {}", t.len(), t.join(", "))).with_detail(
            "Each task runs with the password it was saved with. After a password change it fails every time it's due. \
             Re-enter the password in Task Scheduler (the task's Properties, then OK).",
        )),
        Err(why) => Some(Finding::info(LABEL, format!("not checked: {why}"))),
    }
}

fn logon_type(n: u32) -> &'static str {
    match n {
        2 => "at the keyboard",
        3 => "over the network",
        4 => "by a scheduled task",
        5 => "by a service",
        7 => "unlocking the screen",
        8 => "over the network (clear text)",
        9 => "with Run as",
        10 => "over Remote Desktop",
        11 => "with cached credentials",
        _ => "in an unusual way",
    }
}

fn failure_reason(status: &str) -> &'static str {
    match status.to_ascii_lowercase().as_str() {
        "0xc000006a" => "wrong password",
        "0xc0000064" => "no such user",
        "0xc0000234" => "account locked",
        "0xc0000072" => "account disabled",
        "0xc0000071" => "password expired",
        "0xc0000224" => "password must be changed",
        "0xc0000133" => "clock out of sync",
        "0xc000015b" => "not allowed to sign in this way",
        _ => "",
    }
}

/// One 4625 event's XML as a failure.
pub fn failure_from(xml: &str) -> Option<Failure> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    if system.event_id != 4625 {
        return None;
    }
    let data = crate::parse::evtxml::event_data(xml);
    let get = |key: &str| data.iter().find(|(k, _)| k == key).map(|(_, v)| v.trim().to_string()).filter(|v| v != "-").unwrap_or_default();
    let source = [get("WorkstationName"), get("IpAddress")].into_iter().find(|s| !s.is_empty() && s != "::1" && s != "127.0.0.1").unwrap_or_default();
    Some(Failure {
        time: system.time_created.as_deref().and_then(crate::parse::time::iso8601_utc_to_epoch).unwrap_or(0),
        user: get("TargetUserName"),
        domain: get("TargetDomainName"),
        logon_type: get("LogonType").parse().unwrap_or(0),
        process: get("ProcessName"),
        source,
        reason: Some(get("SubStatus")).filter(|s| !s.is_empty() && s != "0x0").unwrap_or_else(|| get("Status")),
    })
}

/// The account's failed sign-ins on this PC in the last day.
pub fn failures_finding(listed: &Result<Vec<Failure>, String>, hostname: &str, now: u64) -> Finding {
    const LABEL: &str = "Failed sign-ins on this PC (24 h)";
    let failures = match listed {
        Ok(f) => f,
        Err(why) => return Finding::info(LABEL, format!("not checked: {why}")),
    };
    if failures.is_empty() {
        return Finding::ok(LABEL, "none");
    }
    let mut groups: Vec<(String, usize)> = Vec::new();
    for f in failures {
        let mut how = logon_type(f.logon_type).to_string();
        let program = f.process.rsplit(['\\', '/']).next().unwrap_or("").to_string();
        if !program.is_empty() && matches!(f.logon_type, 4 | 5 | 9) {
            how.push_str(&format!(" ({program})"));
        }
        if matches!(f.logon_type, 3 | 8 | 10) && !f.source.is_empty() && !f.source.eq_ignore_ascii_case(hostname) {
            how.push_str(&format!(" from {}", f.source));
        }
        let why = failure_reason(&f.reason);
        if !why.is_empty() {
            how.push_str(&format!(": {why}"));
        }
        match groups.iter_mut().find(|(g, _)| *g == how) {
            Some((_, n)) => *n += 1,
            None => groups.push((how, 1)),
        }
    }
    groups.sort_by_key(|g| std::cmp::Reverse(g.1));
    let last = failures.iter().map(|f| f.time).max().unwrap_or(0);
    let described: Vec<String> = groups.iter().take(5).map(|(how, n)| format!("{n} {how}")).collect();
    Finding::new(
        LABEL,
        format!("{} · last {}", failures.len(), ago(now.saturating_sub(last))),
        if failures.len() >= 20 { Severity::Critical } else { Severity::Warning },
    )
    .with_detail(described.join("; "))
    .with_metric(failures.len() as f64, "", true)
}

/// The summary line of the lockout section: what on this PC could be
/// behind a lockout, or where to look when nothing here is.
pub fn sources_finding(suspects: &[String], info: &Result<UserInfo, String>, failures: usize, server: Option<&str>) -> Finding {
    const LABEL: &str = "Lockout sources on this PC";
    const ELSEWHERE: &str = "Look at what else holds this password: the mail app on a phone or tablet, Wi-Fi or VPN profiles, \
                             and other PCs where the person is still signed in.";
    let trouble = failures > 0 || info.as_ref().is_ok_and(|i| i.locked || i.bad_password_count > 0);
    let list = suspects.join(", ");
    match (trouble, suspects.is_empty(), info.is_ok()) {
        (true, false, _) => Finding::warn(LABEL, format!("{} possible: {list}", suspects.len())).with_detail(
            "Each one can hold the old password and keep trying it. Clear them before unlocking the account, or it locks again.",
        ),
        (true, true, _) => {
            let dc = server.map(|s| format!(" On the domain controller ({}), event 4740 in the Security log names the computer each lockout came from.", s.trim_start_matches('\\'))).unwrap_or_default();
            Finding::info(LABEL, "nothing here explains it").with_detail(format!("{ELSEWHERE}{dc}"))
        }
        (false, false, true) => Finding::info(LABEL, format!("nothing is failing now; these hold the password and would after a change: {list}")),
        (false, false, false) => Finding::info(LABEL, format!("these hold the password and would fail after a change: {list}")),
        (false, true, _) => Finding::ok(LABEL, "none found"),
    }
}

/// A mapped drive and whether its server answers.
pub fn drive_finding(letter: &str, path: &str, connects_as: Option<&str>, reach: &Result<String, String>) -> Finding {
    let label = format!("Mapped drive {}:", letter.trim_end_matches(':').to_ascii_uppercase());
    let detail = connects_as.map(|u| format!("Connects as {u}, not as the signed-in user: that password is stored, and goes stale when it changes.")).unwrap_or_default();
    match reach {
        Ok(how) => Finding::ok(label, format!("{path} · {how}")).with_detail(detail),
        Err(why) => Finding::warn(label, format!("{path} · {why}")).with_detail(detail),
    }
}

/// `\\fs01\home$` → fs01.
pub fn unc_server(path: &str) -> Option<&str> {
    path.trim().strip_prefix(r"\\").or_else(|| path.trim().strip_prefix("//"))?.split(['\\', '/']).next().filter(|s| !s.is_empty())
}

pub fn summary(findings: &[Finding]) -> String {
    let get = |label: &str| findings.iter().find(|f| f.label == label);
    let mut bits = Vec::new();
    if let Some(s) = get("Account status") {
        bits.push(match s.severity {
            Severity::Critical => s.value.clone(),
            _ if s.value.starts_with("couldn't") => "account state not readable".to_string(),
            _ => s.value.split(" · ").next().unwrap_or("").split(',').next().unwrap_or("").to_string(),
        });
    }
    if let Some(p) = get("Password").filter(|p| p.severity.rank() >= Severity::Warning.rank()) {
        bits.push(format!("password {}", p.value.split(" · ").next().unwrap_or("")));
    }
    if let Some(s) = get("Lockout sources on this PC").filter(|s| s.severity == Severity::Warning) {
        bits.push(format!("{} on this PC", s.value.split(':').next().unwrap_or("").replace(" possible", " possible lockout source(s)")));
    }
    let down = findings.iter().filter(|f| f.label.starts_with("Mapped drive") && f.severity == Severity::Warning).count();
    if down > 0 {
        bits.push(format!("{down} mapped drive{} unreachable", plural(down)));
    }
    let mut text = bits.join(" · ");
    if let Some(first) = text.get(..1) {
        text = format!("{}{}", first.to_uppercase(), &text[1..]);
    }
    if text.is_empty() {
        "Checked".to_string()
    } else {
        text
    }
}

/// Everything gathered about the account, ready to grade.
pub struct Facts {
    pub who: Who,
    /// The server that answered, `\\DC01`.
    pub server: Option<String>,
    pub running_as: Option<String>,
    pub info: Result<UserInfo, String>,
    pub rules: Option<Policy>,
    pub saved: Result<Vec<SavedCredential>, String>,
    pub stale_sessions: Vec<Session>,
    pub services: Vec<(String, String)>,
    pub tasks: Result<Vec<String>, String>,
    pub failures: Result<Vec<Failure>, String>,
    pub drives: Vec<MappedDrive>,
    pub hostname: String,
}

pub fn findings(facts: &Facts, band: Band, now: u64) -> Vec<Finding> {
    let rules = facts.rules.as_ref();
    let mut out = vec![who_finding(&facts.who, facts.server.as_deref(), facts.running_as.as_deref())];
    out.push(status_finding(&facts.info, rules, &facts.who, true));
    out.extend(password_finding(&facts.info, rules, band));
    out.extend(policy_finding(rules));

    let failed = facts.failures.as_ref().map_or(0, |f| f.len());
    let trouble = failed > 0 || facts.info.as_ref().is_ok_and(|i| i.locked || i.bad_password_count > 0);
    let mut suspects = Vec::new();
    if let Ok(saved) = &facts.saved {
        if !saved.is_empty() {
            suspects.push(format!("{} saved credential{}", saved.len(), plural(saved.len())));
        }
    }
    let n = facts.stale_sessions.len();
    if n > 0 {
        suspects.push(format!("{n} disconnected session{}", plural(n)));
    }
    let n = facts.services.len();
    if n > 0 {
        suspects.push(format!("{n} service{}", plural(n)));
    }
    if let Ok(tasks) = &facts.tasks {
        if !tasks.is_empty() {
            suspects.push(format!("{} scheduled task{}", tasks.len(), plural(tasks.len())));
        }
    }
    if failed > 0 {
        suspects.push(format!("{failed} failed sign-in{} to this PC", plural(failed)));
    }
    out.push(sources_finding(&suspects, &facts.info, failed, facts.server.as_deref()));
    out.push(saved_finding(&facts.saved, trouble, now));
    out.extend(session_findings(&facts.stale_sessions));
    out.extend(service_finding(&facts.services));
    out.extend(task_finding(&facts.tasks));
    out.push(failures_finding(&facts.failures, &facts.hostname, now));
    for d in &facts.drives {
        out.push(drive_finding(&d.letter, &d.path, d.connects_as.as_deref(), &d.reach));
    }
    out
}

/// Scheduled tasks that run with a stored password, with whose it is.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const STORED_PASSWORD_TASKS: &str = r#"
$ErrorActionPreference = 'Stop'
$tasks = @()
$failed = ''
try {
  $tasks = @(Get-ScheduledTask | Where-Object { @('Password', 'InteractiveOrPassword') -contains [string]$_.Principal.LogonType } | ForEach-Object {
    [ordered]@{ Name = ([string]$_.TaskPath + [string]$_.TaskName); User = [string]$_.Principal.UserId }
  })
} catch { $failed = [string]$_.Exception.Message }
Send-ITriage ([ordered]@{ Tasks = $tasks; Error = $failed })
"#;

/// Is a server reachable on `port`? In words either way.
fn reach(server: &str, port: u16, timeout: std::time::Duration) -> Result<String, String> {
    let found = crate::net::resolve(server).map_err(|_| format!("{server} doesn't resolve"))?;
    let check = crate::net::tcp_check(&found.addresses, port, timeout);
    match check.connected() {
        Some(_) => Ok(format!("{server} answers")),
        None => Err(format!("can't reach {server} ({})", check.error())),
    }
}

// ------------------------------------------------------------ the fixes

/// Remove the credentials saved under the signed-in account's name.
pub fn clear_saved_credentials() -> Result<String, String> {
    imp::clear_saved_credentials()
}

/// Sign out one disconnected session.
pub fn logoff_session(id: &str) -> Result<String, String> {
    imp::logoff_session(id)
}

/// Clear an account's lockout.
pub fn unlock_account(account: &str) -> Result<String, String> {
    imp::unlock_account(account)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::psjson::{list, or_default};
    use crate::win::{account, registry, session};
    use serde::Deserialize;
    use std::time::Duration;

    /// Failed sign-ins in the last 24 hours. Matched to the account afterwards.
    const FAILED_SIGN_INS: &str = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
    const DC_WAIT: Duration = Duration::from_secs(20);

    #[derive(Deserialize, Default)]
    #[serde(default, rename_all = "PascalCase")]
    struct TaskRow {
        #[serde(deserialize_with = "or_default")]
        name: String,
        #[serde(deserialize_with = "or_default")]
        user: String,
    }

    #[derive(Deserialize, Default)]
    #[serde(default, rename_all = "PascalCase")]
    struct TaskList {
        #[serde(deserialize_with = "list")]
        tasks: Vec<TaskRow>,
        #[serde(deserialize_with = "or_default")]
        error: String,
    }

    fn hostname() -> String {
        sysinfo::System::host_name().unwrap_or_default()
    }

    /// The account to check: whoever is at the PC, else whoever runs ITriage.
    fn subject() -> Result<(Who, Option<String>), String> {
        let me = session::current_account();
        let account = session::console_user().or_else(|| me.clone()).ok_or("Nobody is signed in, so there's no account to check.")?;
        Ok((Who::new(&account, &hostname()), me))
    }

    /// The account's state and rules, from a domain controller or this PC.
    /// A slow or missing controller gives up after a while, never hangs.
    fn state(who: &Who) -> (Option<String>, Result<UserInfo, String>, Option<Policy>) {
        if who.local {
            return (None, account::user_info(None, &who.user).map_err(account::net_error), account::policy(None).ok());
        }
        if who.cloud.is_some() {
            // Nothing to search for: there's no domain controller to ask.
            return (None, Err(CLOUD_STATE.to_string()), None);
        }
        let Some(dc) = account::domain_controller(&who.domain, DC_WAIT) else {
            return (None, Err(format!("no domain controller for {} answered. On the office network or VPN, try again", who.domain)), None);
        };
        let (server, user) = (dc.clone(), who.user.clone());
        let asked = crate::util::within(Duration::from_secs(30), move || {
            (account::user_info(Some(&server), &user).map_err(account::net_error), account::policy(Some(&server)).ok())
        });
        match asked {
            Some((info, rules)) => (Some(dc), info, rules),
            None => (Some(dc.clone()), Err(format!("{} stopped answering", dc.trim_start_matches('\\'))), None),
        }
    }

    pub fn check(ctx: &RunContext) -> Result<Output, String> {
        let (who, me) = subject()?;
        let host = hostname();
        let same_user = me.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(&who.account));
        ctx.log(format!("Checking {}…", who.account));
        let (server, info, rules) = state(&who);

        let saved = if same_user {
            account::saved_credentials().map(|all| mine(all, &who, &host))
        } else {
            Err(format!(
                "saved credentials belong to each user, and ITriage is running as {}. Run it as {} to see theirs",
                me.as_deref().unwrap_or("another account"),
                who.account
            ))
        };

        let here = session::current_session();
        let stale_sessions = account::sessions()
            .into_iter()
            .filter(|s| s.state == SESSION_DISCONNECTED && Some(s.id) != here && s.account.eq_ignore_ascii_case(&who.account))
            .collect();

        let services = crate::win::scm::logon_accounts()
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, _, account)| same_account(account, &who, &host, false))
            .map(|(name, display, _)| (name, display))
            .collect();

        let sid = session::sid_of(&who.account);
        let tasks = match crate::win::ps::run(STORED_PASSWORD_TASKS, ctx, Duration::from_secs(90)) {
            Ok(out) => crate::fixes::json::<TaskList>(&out.stdout).and_then(|t| {
                if !t.error.is_empty() && t.tasks.is_empty() {
                    return Err(t.error);
                }
                Ok(t.tasks
                    .into_iter()
                    .filter(|row| same_account(&row.user, &who, &host, true) || sid.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(&row.user)))
                    .map(|row| row.name)
                    .collect())
            }),
            Err(e) => Err(e),
        };

        let failures = if crate::host::is_elevated() {
            crate::win::eventlog::query_xml("Security", FAILED_SIGN_INS, 500).map(|events| {
                events
                    .iter()
                    .filter_map(|xml| failure_from(xml))
                    .filter(|f| f.user.eq_ignore_ascii_case(&who.user) && (f.domain.is_empty() || same_account(&format!("{}\\{}", f.domain, f.user), &who, &host, false)))
                    .collect()
            })
        } else {
            Err("reading the Security log needs administrator rights".to_string())
        };

        let facts = Facts {
            drives: drives(&who, same_user, ctx.profile().network.tcp_timeout()),
            who,
            server,
            running_as: me,
            info,
            rules,
            saved,
            stale_sessions,
            services,
            tasks,
            failures,
            hostname: host,
        };
        let findings = findings(&facts, ctx.profile().thresholds.password_expiry_days, crate::util::now_epoch());
        Ok(Output::new(summary(&findings), findings))
    }

    /// The saved credentials that hold this account's password.
    fn mine(all: Vec<SavedCredential>, who: &Who, host: &str) -> Vec<SavedCredential> {
        all.into_iter()
            .filter(|c| matches!(c.kind, 1 | 2 | 4) && same_account(&c.user, who, host, c.kind != 1))
            .collect()
    }

    /// The user's persistent drive mappings, each with whether its server
    /// answers on the file-sharing port.
    fn drives(who: &Who, same_user: bool, timeout: Duration) -> Vec<MappedDrive> {
        let (root, key) = if same_user {
            (registry::HKCU, "Network".to_string())
        } else {
            match session::sid_of(&who.account) {
                Some(sid) => (registry::HKU, format!(r"{sid}\Network")),
                None => return Vec::new(),
            }
        };
        let mapped: Vec<(String, String, Option<String>)> = registry::subkeys(root, &key)
            .into_iter()
            .filter_map(|letter| {
                let path = registry::read_string(root, &format!(r"{key}\{letter}"), "RemotePath")?;
                let user = registry::read_string(root, &format!(r"{key}\{letter}"), "UserName").filter(|u| !u.eq_ignore_ascii_case(&who.account));
                Some((letter, path, user))
            })
            .collect();
        let reached = crate::net::parallel(&mapped, |(_, path, _)| match unc_server(path) {
            Some(server) => reach(server, 445, timeout),
            None => Err("not a network path".to_string()),
        });
        mapped.into_iter().zip(reached).map(|((letter, path, connects_as), reach)| MappedDrive { letter, path, connects_as, reach }).collect()
    }

    pub fn clear_saved_credentials() -> Result<String, String> {
        let (who, me) = subject()?;
        if !me.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(&who.account)) {
            return Err(format!(
                "Saved credentials belong to each user, and ITriage is running as {}. Run it as {} (not relaunched as another administrator) to clear theirs.",
                me.as_deref().unwrap_or("another account"),
                who.account
            ));
        }
        let targets = mine(account::saved_credentials()?, &who, &hostname());
        if targets.is_empty() {
            return Ok("There was nothing to remove: no credentials are saved under this account.".into());
        }
        let mut removed = Vec::new();
        let mut failed = Vec::new();
        for c in &targets {
            match account::delete_credential(&c.target, c.kind) {
                Ok(()) => removed.push(c.target.clone()),
                Err(e) => failed.push(e),
            }
        }
        let done = format!(
            "Removed {} saved credential{}: {}. Windows asks for the password the next time each is used.",
            removed.len(),
            plural(removed.len()),
            removed.join(", ")
        );
        if failed.is_empty() {
            Ok(done)
        } else {
            Err(format!("{done} But {} couldn't be removed: {}", failed.len(), failed.join("; ")))
        }
    }

    pub fn logoff_session(id: &str) -> Result<String, String> {
        let id: u32 = id.parse().map_err(|_| format!("`{id}` isn't a session number."))?;
        if Some(id) == session::current_session() {
            return Err("That's the session ITriage is running in.".into());
        }
        let found = account::sessions().into_iter().find(|s| s.id == id).ok_or(format!("Session {id} has already gone."))?;
        // Only what the check offered: someone's session, left disconnected.
        if found.state != SESSION_DISCONNECTED || found.account.is_empty() {
            return Err(format!("Session {id} isn't a disconnected sign-in any more, so it was left alone."));
        }
        account::logoff(id)?;
        Ok(format!("Asked Windows to sign out {}'s disconnected session {id}.", found.account))
    }

    pub fn unlock_account(name: &str) -> Result<String, String> {
        let who = Who::new(name, &hostname());
        if let Some(kind) = who.cloud {
            return Err(format!("{} is a {kind}: it's unlocked in the cloud directory's admin centre, not from the PC.", who.account));
        }
        let server = if who.local {
            None
        } else {
            Some(account::domain_controller(&who.domain, DC_WAIT).ok_or(format!("No domain controller for {} answered.", who.domain))?)
        };
        let user = who.user.clone();
        let at = server.clone();
        let outcome = crate::util::within(Duration::from_secs(30), move || account::unlock(at.as_deref(), &user))
            .ok_or("The domain controller stopped answering.")?;
        match outcome {
            Ok(true) => Ok(format!(
                "{} is unlocked. If something is still using the old password, it will lock again: clear the sources the report lists.",
                who.account
            )),
            Ok(false) => Ok(format!("{} wasn't locked, so nothing was changed.", who.account)),
            Err(5) => Err(format!(
                "Access denied: the account ITriage is running as isn't allowed to unlock {}. Relaunch ITriage as an account that is (a help desk or domain admin account), or unlock it in Active Directory Users and Computers.",
                who.account
            )),
            Err(code) => Err(format!("Couldn't unlock {}: {}.", who.account, account::net_error(code))),
        }
    }
}

/// What `chage -l -i` says about a password: (last changed, expires), each
/// an ISO date or a word like "never".
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_chage(text: &str) -> (Option<String>, Option<String>) {
    let field = |name: &str| {
        text.lines().find_map(|l| {
            let (key, value) = l.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string()).filter(|v| !v.is_empty())
        })
    };
    (field("Last password change"), field("Password expires"))
}

/// Failed attempts `faillock --user NAME` lists as still counting.
#[cfg_attr(windows, allow(dead_code))]
pub fn faillock_failures(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            let fields: Vec<&str> = l.split_whitespace().collect();
            // "2026-11-08 09:14:02 RHOST 10.0.0.9 V": a date, and V for valid.
            fields.first().is_some_and(|d| d.len() == 10 && d.as_bytes()[4] == b'-') && fields.last() == Some(&"V")
        })
        .count()
}

/// Network file systems in `/proc/mounts`: (mount point, source, server, port).
#[cfg_attr(windows, allow(dead_code))]
pub fn network_mounts(mounts: &str) -> Vec<(String, String, String, u16)> {
    mounts
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (source, point, fs) = (*f.first()?, *f.get(1)?, *f.get(2)?);
            let (server, port) = match fs {
                "cifs" | "smb3" | "smbfs" => (unc_server(source)?.to_string(), 445),
                "nfs" | "nfs4" => (source.rsplit_once(":/").map(|(host, _)| host.trim_matches(['[', ']']).to_string())?, 2049),
                _ => return None,
            };
            Some((point.replace("\\040", " "), source.replace("\\040", " "), server, port))
        })
        .collect()
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::time::iso8601_utc_to_epoch;
    use crate::util::{capture_for, cmd, command_exists, exit_label, pkexec_error, privileged, PROMPTED};
    use std::time::Duration;

    const QUICK: Duration = Duration::from_secs(15);

    fn subject() -> String {
        std::env::var("SUDO_USER")
            .ok()
            .filter(|u| !u.is_empty())
            .or_else(|| std::env::var("PKEXEC_UID").ok().and_then(|uid| name_of(&uid)))
            .or_else(|| std::env::var("USER").ok().filter(|u| !u.is_empty()))
            .unwrap_or_else(|| "root".to_string())
    }

    fn name_of(uid: &str) -> Option<String> {
        std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.get(2) == Some(&uid)).then(|| f[0].to_string())
        })
    }

    fn run(program: &str, args: &[&str]) -> Option<String> {
        if !command_exists(program) {
            return None;
        }
        let mut c = cmd(program);
        c.args(args).env("LC_ALL", "C");
        capture_for(c, QUICK).ok().filter(|o| o.success()).map(|o| o.stdout)
    }

    /// Days from today to an ISO date (negative when it has passed).
    fn days_until(date: &str, now: u64) -> Option<i64> {
        let then = iso8601_utc_to_epoch(&format!("{date}T00:00:00Z"))?;
        Some((then as i64 - now as i64).div_euclid(86_400))
    }

    pub fn check(ctx: &RunContext) -> Result<Output, String> {
        let user = subject();
        let who = Who { account: user.clone(), domain: String::new(), user: user.clone(), local: true, cloud: None };
        let now = crate::util::now_epoch();
        let band = ctx.profile().thresholds.password_expiry_days;
        let mut out = vec![who_finding(&who, None, None)];

        // "jparker P 2026-09-01 0 99999 7 -1": L is locked, NP has no password.
        let state = run("passwd", &["-S", &user]);
        let locked = state.as_deref().and_then(|s| s.split_whitespace().nth(1).map(|f| f.starts_with('L')));
        let failed = run("faillock", &["--user", &user]).map(|t| faillock_failures(&t));
        out.push(match (locked, failed) {
            (Some(true), _) if user == "root" => Finding::info("Account status", "password sign-in is off, as usual for root"),
            (Some(true), _) => Finding::warn("Account status", "password locked")
                .with_detail("The password is locked (passwd -l), so password sign-in is refused. Keys and single sign-on still work."),
            (_, Some(n)) if n > 0 => Finding::warn("Account status", format!("{n} failed sign-in{} counting toward a lockout", plural(n)))
                .with_detail("pam_faillock refuses sign-in once its limit is reached. Resetting the count lets the person try again.")
                .with_action(offer("unlock-account", Some(&user))),
            (Some(false), _) => Finding::ok("Account status", "active"),
            (None, _) => Finding::info("Account status", "couldn't be read (accounts from a directory aren't in the local files)"),
        });

        if let Some(text) = run("chage", &["-l", "-i", &user]) {
            let (changed, expires) = parse_chage(&text);
            let changed = changed.map(|c| format!(" · last changed {c}")).unwrap_or_default();
            out.push(match expires.as_deref() {
                None => Finding::info("Password", format!("expiry not reported{changed}")),
                Some(date) => match days_until(date, now) {
                    Some(left) if left < 0 => Finding::crit("Password", format!("expired {date}{changed}")),
                    Some(left) => Finding::new("Password", format!("expires in {left} day{} ({date}){changed}", plural(left as usize)), band.low(left as f64))
                        .with_metric(left as f64, "days", false),
                    None => Finding::info("Password", format!("{}{changed}", if date.eq_ignore_ascii_case("never") { "never expires" } else { date })),
                },
            });
        }

        if command_exists("klist") {
            let mut c = cmd("klist");
            c.arg("-s");
            if let Ok(o) = capture_for(c, QUICK) {
                out.push(if o.success() {
                    Finding::ok("Kerberos ticket", "valid")
                } else {
                    Finding::info("Kerberos ticket", "none, or expired (kinit gets a new one)")
                });
            }
        }

        let mounts = network_mounts(&std::fs::read_to_string("/proc/mounts").unwrap_or_default());
        let timeout = ctx.profile().network.tcp_timeout();
        let reached = crate::net::parallel(&mounts, |(_, _, server, port)| reach(server, *port, timeout));
        for ((point, source, _, _), r) in mounts.iter().zip(reached) {
            let mut f = drive_finding("x", source, None, &r);
            f.label = format!("Network share {point}");
            out.push(f);
        }
        Ok(Output::new(summary(&out), out))
    }

    pub fn clear_saved_credentials() -> Result<String, String> {
        Err("Saved Windows credentials are a Windows feature. On Linux they're in the desktop keyring (Passwords and Keys).".into())
    }

    pub fn logoff_session(_id: &str) -> Result<String, String> {
        Err("Signing out a disconnected session is a Windows fix. On Linux: loginctl terminate-session.".into())
    }

    /// Reset pam_faillock's count for the account.
    pub fn unlock_account(account: &str) -> Result<String, String> {
        let (c, via_pkexec) = privileged("faillock", &["--user", account, "--reset"])?;
        let out = capture_for(c, PROMPTED)?;
        if via_pkexec {
            if let Some(why) = pkexec_error(out.code) {
                return Err(why.to_string());
            }
        }
        if out.success() {
            Ok(format!("Failed sign-in count reset for {account}."))
        } else {
            Err(format!("faillock failed ({}): {}", exit_label(out.code), crate::parse::text::first_line(&out.combined())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    fn corp() -> Who {
        Who::new(r"CORP\jparker", "WS-FLINT-07")
    }

    fn band() -> Band {
        crate::profile::Thresholds::default().password_expiry_days
    }

    fn rules() -> Policy {
        Policy { max_password_age_secs: Some(90 * DAY), lockout_threshold: 5, lockout_duration_secs: Some(1800), lockout_window_secs: 1800 }
    }

    fn quiet(who: Who) -> Facts {
        Facts {
            who,
            server: Some(r"\\DC01".into()),
            running_as: Some(r"CORP\jparker".into()),
            info: Ok(UserInfo { password_age_secs: 20 * DAY, ..UserInfo::default() }),
            rules: Some(rules()),
            saved: Ok(Vec::new()),
            stale_sessions: Vec::new(),
            services: Vec::new(),
            tasks: Ok(Vec::new()),
            failures: Ok(Vec::new()),
            drives: Vec::new(),
            hostname: "WS-FLINT-07".into(),
        }
    }

    fn by<'a>(findings: &'a [Finding], label: &str) -> &'a Finding {
        findings.iter().find(|f| f.label == label).unwrap_or_else(|| panic!("no {label} in {findings:#?}"))
    }

    #[test]
    fn takes_account_names_apart() {
        assert_eq!(split_account(r"CORP\jparker"), ("CORP".into(), "jparker".into()));
        assert_eq!(split_account("jparker@corp.example.org"), ("corp.example.org".into(), "jparker".into()));
        assert_eq!(split_account("jparker"), (String::new(), "jparker".into()));
        assert!(!corp().local);
        assert!(Who::new(r"ws-flint-07\kiosk", "WS-FLINT-07").local && Who::new("kiosk", "WS-FLINT-07").local);
    }

    #[test]
    fn a_cloud_account_is_not_looked_for_on_a_domain_controller() {
        let entra = Who::new(r"AzureAD\jparker", "WS-FLINT-07");
        assert_eq!(entra.cloud, Some("Microsoft Entra ID account"));
        assert!(!entra.local);
        assert_eq!(Who::new(r"MicrosoftAccount\someone@outlook.com", "PC").cloud, Some("Microsoft account"));
        assert_eq!(corp().cloud, None);
        assert_eq!(who_finding(&entra, None, None).value, r"AzureAD\jparker · Microsoft Entra ID account");
        // Its state can't be read, and the report says why without alarm.
        let mut facts = quiet(entra);
        facts.server = None;
        facts.info = Err(CLOUD_STATE.to_string());
        facts.rules = None;
        facts.saved = Ok(vec![SavedCredential { target: "fs01".into(), user: r"AzureAD\jparker".into(), kind: 2, saved: None }]);
        let f = findings(&facts, band(), NOW);
        let status = by(&f, "Account status");
        assert_eq!(status.severity, Severity::Info);
        assert!(status.value.starts_with("couldn't be read: its sign-in state and password are kept in the cloud"), "{}", status.value);
        assert!(f.iter().all(|x| x.label != "Password" && x.label != "Lockout policy"));
        // What's on the PC is still listed.
        assert!(by(&f, "Lockout sources on this PC").value.starts_with("these hold the password"));
        assert_eq!(summary(&f), "Account state not readable");
    }

    #[test]
    fn matches_only_this_accounts_names() {
        let who = corp();
        let is = |name: &str, bare| same_account(name, &who, "WS-FLINT-07", bare);
        assert!(is(r"corp\JParker", false) && is("jparker@corp.example.org", false) && is(r"CORP.EXAMPLE.ORG\jparker", false));
        assert!(!is("jparker@gmail.com", true), "somebody's mail password, not the CORP account");
        assert!(!is(r"CORP\jparker-admin", false) && !is(r"OTHER\jparker", false) && !is(r"WS-FLINT-07\jparker", false));
        assert!(is("jparker", true) && !is("jparker", false), "a bare name counts only where the caller says so");
        assert!(!is("", true));
        let local = Who::new(r"WS-FLINT-07\kiosk", "WS-FLINT-07");
        assert!(same_account(r".\kiosk", &local, "WS-FLINT-07", false) && same_account(r"ws-flint-07\kiosk", &local, "WS-FLINT-07", false));
        assert!(!same_account(r"CORP\kiosk", &local, "WS-FLINT-07", false));

        assert!(valid_account_name(r"CORP\jparker") && valid_account_name("jparker@corp.example.org") && valid_account_name("Jo Smith"));
        for bad in ["", "-rf", "a;b", "a\nb", "a/b", "a'b", "$(x)", "\\"] {
            assert!(!valid_account_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_healthy_account_has_nothing_to_report() {
        let f = findings(&quiet(corp()), band(), NOW);
        assert_eq!(by(&f, "Account").value, r"CORP\jparker · domain account");
        assert_eq!(by(&f, "Account").detail.as_deref(), Some("Checked on DC01."));
        assert_eq!(by(&f, "Account status").value, "active");
        assert_eq!(by(&f, "Password").value, "expires in 70 days · changed 20 days ago");
        assert_eq!(by(&f, "Lockout policy").value, "locks after 5 wrong passwords within 30 minutes; unlocks by itself after 30 minutes");
        assert_eq!(by(&f, "Lockout sources on this PC").severity, Severity::Ok);
        assert!(f.iter().all(|x| x.severity.rank() <= Severity::Info.rank()), "{f:#?}");
        assert_eq!(summary(&f), "Active");
    }

    #[test]
    fn a_locked_account_names_what_keeps_locking_it() {
        let mut facts = quiet(corp());
        facts.info = Ok(UserInfo { locked: true, bad_password_count: 5, password_age_secs: 2 * DAY, ..UserInfo::default() });
        facts.saved = Ok(vec![
            SavedCredential { target: "fs01".into(), user: r"CORP\jparker".into(), kind: 2, saved: Some(NOW - 40 * DAY) },
            SavedCredential { target: "TERMSRV/rds01".into(), user: r"CORP\jparker".into(), kind: 1, saved: None },
        ]);
        facts.stale_sessions = vec![Session { id: 3, account: r"CORP\jparker".into(), state: SESSION_DISCONNECTED, station: String::new() }];
        facts.services = vec![("BackupAgent".into(), "Nightly Backup Agent".into())];
        facts.tasks = Ok(vec![r"\Reports\Export".into()]);
        let f = findings(&facts, band(), NOW);

        let status = by(&f, "Account status");
        assert_eq!((status.value.as_str(), status.severity), ("locked out", Severity::Critical));
        assert!(status.detail.as_deref().unwrap().ends_with("It unlocks by itself 30 minutes after the last wrong password."));
        let unlock = status.action.as_ref().expect("an unlock button");
        assert_eq!((unlock.id.as_str(), unlock.target.as_deref()), ("unlock-account", Some(r"CORP\jparker")));

        let sources = by(&f, "Lockout sources on this PC");
        assert_eq!(sources.severity, Severity::Warning);
        assert_eq!(sources.value, "4 possible: 2 saved credentials, 1 disconnected session, 1 service, 1 scheduled task");

        let saved = by(&f, "Saved credentials");
        assert_eq!(saved.severity, Severity::Warning, "with the account locked, saved credentials are suspects");
        assert!(saved.detail.as_deref().unwrap().starts_with("fs01 (Windows credential, saved 40d ago); TERMSRV/rds01 (app credential)."));
        assert_eq!(saved.action.as_ref().unwrap().id, "clear-saved-credentials");
        let session = by(&f, "Disconnected session 3");
        assert_eq!(session.action.as_ref().unwrap().target.as_deref(), Some("3"));
        assert_eq!(by(&f, "Services signing in as this account").value, "1: Nightly Backup Agent (BackupAgent)");
        assert_eq!(by(&f, "Scheduled tasks with a stored password").value, r"1: \Reports\Export");
        assert_eq!(summary(&f), "Locked out · 4 possible lockout source(s) on this PC");
    }

    #[test]
    fn says_where_to_look_when_nothing_here_explains_a_lockout() {
        let mut facts = quiet(corp());
        facts.info = Ok(UserInfo { locked: true, ..UserInfo::default() });
        let f = findings(&facts, band(), NOW);
        let sources = by(&f, "Lockout sources on this PC");
        assert_eq!((sources.value.as_str(), sources.severity), ("nothing here explains it", Severity::Info));
        let detail = sources.detail.as_deref().unwrap();
        assert!(detail.contains("phone or tablet") && detail.contains("On the domain controller (DC01), event 4740"), "{detail}");

        // Saved credentials with nothing failing are only noted.
        let mut calm = quiet(corp());
        calm.saved = Ok(vec![SavedCredential { target: "fs01".into(), user: r"CORP\jparker".into(), kind: 2, saved: None }]);
        let f = findings(&calm, band(), NOW);
        assert_eq!(by(&f, "Saved credentials").severity, Severity::Info);
        assert_eq!(by(&f, "Lockout sources on this PC").severity, Severity::Info);
    }

    #[test]
    fn grades_the_account_and_its_password() {
        let who = corp();
        let status = |info: UserInfo| status_finding(&Ok(info), Some(&rules()), &who, true);
        assert_eq!(status(UserInfo { disabled: true, ..UserInfo::default() }).value, "disabled");
        let close = status(UserInfo { bad_password_count: 4, ..UserInfo::default() });
        assert_eq!((close.severity, close.value.as_str()), (Severity::Warning, "active, but one wrong password from locking (4 of 5 used)"));
        assert_eq!(status(UserInfo { bad_password_count: 2, ..UserInfo::default() }).value, "active · 2 wrong passwords since the last good one (it locks at 5)");
        let forever = Policy { lockout_duration_secs: None, ..rules() };
        let locked = status_finding(&Ok(UserInfo { locked: true, ..UserInfo::default() }), Some(&forever), &who, false);
        assert!(locked.detail.as_deref().unwrap().ends_with("It stays locked until someone unlocks it.") && locked.action.is_none());
        assert_eq!(status_finding(&Err("access denied".into()), None, &who, true).severity, Severity::Info);

        let pw = |info: UserInfo| password_finding(&Ok(info), Some(&rules()), band()).unwrap();
        let soon = pw(UserInfo { password_age_secs: 81 * DAY, ..UserInfo::default() });
        assert_eq!((soon.value.as_str(), soon.severity), ("expires in 9 days · changed 81 days ago", Severity::Warning));
        assert_eq!(soon.metric.as_ref().unwrap().value, 9.0);
        assert!(!soon.metric.unwrap().higher_is_worse);
        assert_eq!(pw(UserInfo { password_age_secs: 88 * DAY, ..UserInfo::default() }).severity, Severity::Critical);
        assert_eq!(pw(UserInfo { password_age_secs: 89 * DAY + 3600, ..UserInfo::default() }).value, "expires today · changed 89 days ago");
        assert_eq!(pw(UserInfo { password_age_secs: 95 * DAY, ..UserInfo::default() }).value, "expired · changed 95 days ago");
        assert_eq!(pw(UserInfo { password_expired: true, ..UserInfo::default() }).severity, Severity::Critical);
        assert_eq!(pw(UserInfo { password_never_expires: true, password_age_secs: 400 * DAY, ..UserInfo::default() }).value, "never expires · changed 400 days ago");
        assert!(pw(UserInfo { smartcard_required: true, ..UserInfo::default() }).value.starts_with("smart card"));
        assert!(password_finding(&Err("x".into()), None, band()).is_none());
        assert_eq!(policy_finding(Some(&Policy::default())).unwrap().value, "accounts never lock out here");
        assert!(policy_finding(Some(&forever)).unwrap().value.ends_with("stays locked until someone unlocks it"));
    }

    /// A real 4625's shape: a service on this PC failing with a wrong password.
    const FAILED: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID>\
        <Level>0</Level><TimeCreated SystemTime='2027-01-15T07:59:00.1234567Z'/><Channel>Security</Channel></System><EventData>\
        <Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='TargetUserName'>jparker</Data><Data Name='TargetDomainName'>CORP</Data>\
        <Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>5</Data>\
        <Data Name='WorkstationName'>WS-FLINT-07</Data><Data Name='ProcessName'>C:\\Windows\\System32\\services.exe</Data>\
        <Data Name='IpAddress'>-</Data></EventData></Event>";

    #[test]
    fn reads_failed_sign_ins_from_the_security_log() {
        let f = failure_from(FAILED).unwrap();
        assert_eq!((f.user.as_str(), f.domain.as_str(), f.logon_type), ("jparker", "CORP", 5));
        assert_eq!(f.reason, "0xc000006a");
        assert_eq!(f.process, r"C:\Windows\System32\services.exe");
        assert!(failure_from(&FAILED.replace("4625", "4624")).is_none());

        let now = f.time + 300;
        let mut many = vec![f.clone(); 12];
        many.push(Failure { logon_type: 10, source: "10.20.4.9".into(), process: String::new(), time: f.time - 7200, ..f.clone() });
        many.push(Failure { logon_type: 2, reason: "0xC0000234".into(), time: f.time - 9000, ..f.clone() });
        let finding = failures_finding(&Ok(many), "WS-FLINT-07", now);
        assert_eq!(finding.value, "14 · last 5m ago");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(
            finding.detail.as_deref(),
            Some("12 by a service (services.exe): wrong password; 1 over Remote Desktop from 10.20.4.9: wrong password; 1 at the keyboard: account locked")
        );
        assert_eq!(failures_finding(&Ok(Vec::new()), "x", now).severity, Severity::Ok);
        assert_eq!(failures_finding(&Err("reading the Security log needs administrator rights".into()), "x", now).severity, Severity::Info);
    }

    #[test]
    fn reports_mapped_drives() {
        assert_eq!(unc_server(r"\\fs01\home$\jparker"), Some("fs01"));
        assert_eq!(unc_server("//nas.local/media"), Some("nas.local"));
        assert_eq!(unc_server(r"C:\local"), None);
        let up = drive_finding("h", r"\\fs01\home$", None, &Ok("fs01 answers".into()));
        assert_eq!((up.label.as_str(), up.value.as_str(), up.severity), ("Mapped drive H:", r"\\fs01\home$ · fs01 answers", Severity::Ok));
        let down = drive_finding("S", r"\\scan01\inbox", Some(r"CORP\svc_scan"), &Err("can't reach scan01 (10.1.2.3 timed out)".into()));
        assert_eq!(down.severity, Severity::Warning);
        assert!(down.detail.as_deref().unwrap().starts_with(r"Connects as CORP\svc_scan"));
        // Nothing listens on port 9 of this machine.
        assert!(reach("127.0.0.1", 9, std::time::Duration::from_millis(300)).unwrap_err().starts_with("can't reach 127.0.0.1"));
        assert!(reach("no-such-host.invalid", 445, std::time::Duration::from_millis(300)).unwrap_err().ends_with("doesn't resolve"));
    }

    #[test]
    fn reads_linux_account_tools() {
        let chage = "Last password change\t\t\t\t\t: 2026-09-01\nPassword expires\t\t\t\t\t: 2026-11-30\nPassword inactive\t\t\t\t\t: never\n";
        assert_eq!(parse_chage(chage), (Some("2026-09-01".into()), Some("2026-11-30".into())));
        assert_eq!(parse_chage("Password expires : never\n").1.as_deref(), Some("never"));
        let faillock = "jparker:\nWhen                Type  Source                                           Valid\n\
                        2026-11-08 09:14:02 RHOST 10.0.0.9                                             V\n\
                        2026-11-08 09:14:09 TTY   /dev/tty1                                            V\n\
                        2026-11-01 08:00:00 TTY   /dev/tty1                                            I\n";
        assert_eq!(faillock_failures(faillock), 2);
        assert_eq!(faillock_failures("jparker:\nWhen Type Source Valid\n"), 0);
        let mounts = "/dev/nvme0n1p2 / ext4 rw 0 0\n//fs01/home$ /mnt/home cifs rw,vers=3.0 0 0\nnas.local:/export/media /mnt/My\\040Media nfs4 rw 0 0\n[fd00::5]:/data /mnt/data nfs rw 0 0\n";
        assert_eq!(
            network_mounts(mounts),
            vec![
                ("/mnt/home".into(), "//fs01/home$".into(), "fs01".into(), 445),
                ("/mnt/My Media".into(), "nas.local:/export/media".into(), "nas.local".into(), 2049),
                ("/mnt/data".into(), "[fd00::5]:/data".into(), "fd00::5".into(), 2049),
            ]
        );
    }
}
