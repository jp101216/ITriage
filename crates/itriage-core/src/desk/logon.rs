//! Sign-in duration waterfall. Read-only, Windows only.
//!
//! "Please wait for the Group Policy Client" is one of the most common
//! slow-sign-in calls. The change timeline already shows when sign-in policy
//! finished; this says which part took the time: the profile load, and each
//! Group Policy client-side extension (Folder Redirection, Scripts, Drive
//! Maps…), with the ones that failed and how many policy objects applied.
//!
//! It measures what Windows logs. The desktop itself (Explorer, the apps
//! that start with it) comes after this and isn't included.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::gplogon::{Outcome, Waterfall};
use crate::parse::time::epoch_to_rfc3339;
use crate::profile::Band;
use crate::util::ago;

pub struct SignInWaterfall;

impl TriageModule for SignInWaterfall {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.logon",
            "Sign-in speed (Group Policy)",
            Category::Workstation,
            "How long the last sign-in spent loading the profile and applying Group Policy, which policy step took the time or failed, and lost contact with the domain controller during policy processing.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::check(&ctx.profile().thresholds.logon_seconds)
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("Group Policy sign-in timing is Windows-only.".into())
    }
}

/// A Group Policy problem from the System log: 1129 (no domain controller)
/// or 1058 (couldn't read a GPO's gpt.ini from SYSVOL).
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyError {
    pub epoch: u64,
    pub id: u32,
    pub text: String,
}

fn secs(ms: u64) -> String {
    format!("{:.1} s", ms as f64 / 1000.0)
}

/// The rows for the newest sign-in (`user`), the newest startup policy
/// (`computer`), the profile load before that sign-in, and the week's
/// System-log policy errors.
pub fn findings(user: Option<&Waterfall>, computer: Option<&Waterfall>, profile_ms: Option<u64>, errors: &[PolicyError], band: &Band, now: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    match user {
        None => out.push(Finding::info("Last sign-in", "no sign-in policy processing in the last 7 days").with_detail(
            "Nothing to time: this PC may not be in a domain, have no user policy, or nobody has signed in this week. The Group Policy log may also have been cleared.",
        )),
        Some(w) => {
            let policy_ms = w.policy_ms.unwrap_or_else(|| w.phases.iter().map(|p| p.ms).sum());
            let total_ms = policy_ms + profile_ms.unwrap_or(0);
            let total_s = total_ms as f64 / 1000.0;
            let parts = match profile_ms {
                Some(p) => format!("Profile {} + Group Policy {}", secs(p), secs(policy_ms)),
                None => format!("Group Policy {} (the profile load wasn't in the log)", secs(policy_ms)),
            };
            let who = if w.principal.is_empty() { String::new() } else { format!(" for {}", w.principal) };
            let mut detail = format!("{parts}{who}, started {} UTC. The desktop (Explorer and startup apps) comes after this and isn't counted.", epoch_to_rfc3339(w.started));
            if w.policy_ms.is_none() {
                detail.push_str(" Group Policy never logged that it finished, so this is the sum of the steps that did.");
            }
            out.push(
                Finding::new("Last sign-in (profile + Group Policy)", format!("{} · {}", secs(total_ms), ago(now.saturating_sub(w.started))), band.high(total_s))
                    .with_detail(detail)
                    .with_metric(total_s, "s", true),
            );
            if let Some(p) = profile_ms {
                out.push(Finding::new("User profile load", secs(p), band.high(p as f64 / 1000.0)).with_metric(p as f64 / 1000.0, "s", true));
            }
            let slow_total = band.high(total_s) != Severity::Ok;
            for phase in w.slowest(3).iter().filter(|p| p.ms > 0) {
                let share = if total_ms > 0 { phase.ms as f64 / total_ms as f64 * 100.0 } else { 0.0 };
                let severity = if slow_total && share >= 40.0 { Severity::Warning } else { Severity::Info };
                out.push(
                    Finding::new(format!("Policy step: {}", phase.name), format!("{} · {share:.0}% of the sign-in", secs(phase.ms)), severity)
                        .with_metric(phase.ms as f64 / 1000.0, "s", true),
                );
            }
            for phase in w.phases.iter().filter(|p| p.outcome != Outcome::Ok) {
                let failed = phase.outcome == Outcome::Failed;
                let code = phase.error.as_deref().map(|e| format!("error {e} · ")).unwrap_or_default();
                out.push(
                    Finding::new(
                        format!("Policy step {}: {}", if failed { "failed" } else { "warned" }, phase.name),
                        format!("{code}{}", secs(phase.ms)),
                        if failed { Severity::Critical } else { Severity::Warning },
                    )
                    .with_detail("Event 7016 (failed) or 6016 (warning) in the Group Policy log. Run gpresult /h on this PC for that extension's details."),
                );
            }
            if let Some(code) = &w.error {
                out.push(Finding::warn("Sign-in policy result", format!("finished with error {code}")));
            }
            // Windows logs each list only when it has one to log.
            let counts: Vec<String> = [w.applied.map(|n| format!("{n} applied")), w.filtered.map(|n| format!("{n} filtered out"))].into_iter().flatten().collect();
            if !counts.is_empty() {
                out.push(Finding::info("Group Policy objects", counts.join(" · ")));
            }
        }
    }
    if let Some(c) = computer {
        let value = match c.policy_ms {
            Some(ms) => format!("{} · {}", secs(ms), ago(now.saturating_sub(c.started))),
            None => format!("didn't log finishing · {}", ago(now.saturating_sub(c.started))),
        };
        let f = Finding::new("Computer policy at startup", value, if c.error.is_some() { Severity::Warning } else { Severity::Info })
            .with_detail(c.error.as_deref().map(|e| format!("Finished with error {e}.")).unwrap_or_default());
        out.push(match c.policy_ms {
            Some(ms) => f.with_metric(ms as f64 / 1000.0, "s", true),
            None => f,
        });
    }
    for (id, label, what) in [
        (1129, "Domain controller during policy processing", "no domain controller reachable"),
        (1058, "Policy files (SYSVOL)", "a policy's gpt.ini couldn't be read"),
    ] {
        let hits: Vec<&PolicyError> = errors.iter().filter(|e| e.id == id).collect();
        let Some(last) = hits.iter().max_by_key(|e| e.epoch) else { continue };
        // During the last sign-in it explains that sign-in; otherwise it's history.
        let during = user.is_some_and(|w| last.epoch + 300 >= w.started && last.epoch <= w.started + 600);
        out.push(
            Finding::new(
                label,
                format!("{what} {} in 7 days · last {}", match hits.len() { 1 => "once".to_string(), 2 => "twice".to_string(), n => format!("{n} times") }, ago(now.saturating_sub(last.epoch))),
                if during { Severity::Critical } else { Severity::Warning },
            )
            .with_detail(if last.text.is_empty() {
                format!("System log, Group Policy event {id}.")
            } else {
                format!("System log, Group Policy event {id}: {}", last.text)
            }),
        );
    }
    out
}

pub fn summarise(findings: &[Finding]) -> String {
    match findings.iter().find(|f| f.label == "Last sign-in (profile + Group Policy)") {
        Some(f) => format!("Last sign-in: {}", f.value.split(" · ").next().unwrap_or(&f.value)),
        None => "No sign-in policy processing to time".to_string(),
    }
}

/// "a, b" from a 1058's fields, for the detail line.
#[cfg_attr(not(windows), allow(dead_code))]
fn error_text(data: &[(String, String)]) -> String {
    use crate::parse::blocks::field;
    [
        field(data, &["ErrorDescription"]).map(|d| d.trim_end_matches('.').to_string()),
        field(data, &["FilePath"]).map(|p| format!("file {p}")),
        field(data, &["DCName"]).map(|d| format!("domain controller {}", d.trim_start_matches('\\'))),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" · ")
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::gplogon::{from_event, profile_load_ms, waterfalls, GP_CHANNEL, PROFILE_CHANNEL};
    use crate::win::eventlog::{query_activity, query_xml};

    pub fn check(band: &Band) -> Result<Output, String> {
        // The starts and ends of the week's startup and sign-in cycles, then
        // every event of the newest of each. Periodic refreshes write the
        // same extension events every 90 minutes, so a plain "last N
        // events" query would lose the sign-in behind them.
        const CYCLES: &str = "*[System[(EventID=4000 or EventID=4001 or EventID=8000 or EventID=8001) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        const PROFILE: &str = "*[System[(EventID=1 or EventID=2) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        const ERRORS: &str = "*[System[Provider[@Name='Microsoft-Windows-GroupPolicy'] and (EventID=1058 or EventID=1129) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        let now = crate::util::now_epoch();
        let cycles: Vec<_> = query_xml(GP_CHANNEL, CYCLES, 200)?.iter().filter_map(|x| from_event(x)).collect();
        let newest = waterfalls(&cycles);
        let mut detailed = Vec::new();
        for kind in [true, false] {
            if let Some(w) = newest.iter().find(|w| w.user == kind) {
                let events: Vec<_> = query_activity(GP_CHANNEL, &w.activity, 400)?.iter().filter_map(|x| from_event(x)).collect();
                detailed.extend(waterfalls(&events).into_iter().find(|d| d.activity == w.activity));
            }
        }
        let user = detailed.iter().find(|w| w.user);
        let computer = detailed.iter().find(|w| !w.user);
        let profile = user.and_then(|w| {
            let events: Vec<_> = query_xml(PROFILE_CHANNEL, PROFILE, 200).ok()?.iter().filter_map(|x| from_event(x)).collect();
            profile_load_ms(&events, w.started)
        });
        let errors: Vec<PolicyError> = query_xml("System", ERRORS, 100)
            .unwrap_or_default()
            .iter()
            .filter_map(|x| {
                let e = from_event(x)?;
                Some(PolicyError { epoch: e.epoch, id: e.id, text: error_text(&e.data) })
            })
            .collect();
        let rows = findings(user, computer, profile, &errors, band, now);
        Ok(Output::new(summarise(&rows), rows))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::gplogon::Phase;

    fn sign_in(policy_s: u64, phases: Vec<Phase>) -> Waterfall {
        Waterfall {
            user: true,
            started: 1_794_600_000,
            policy_ms: Some(policy_s * 1000),
            phases,
            applied: Some(12),
            filtered: Some(3),
            principal: "CORP\\jparker".into(),
            error: None,
            activity: "a".into(),
        }
    }

    fn phase(name: &str, ms: u64, outcome: Outcome) -> Phase {
        Phase { name: name.into(), ms, outcome, error: (outcome != Outcome::Ok).then(|| "2".to_string()) }
    }

    #[test]
    fn names_the_step_that_took_the_time() {
        let band = Band { warn: 60.0, crit: 120.0 };
        let w = sign_in(55, vec![phase("Folder Redirection", 41_000, Outcome::Ok), phase("Scripts", 5_000, Outcome::Ok), phase("Drive Maps", 2_000, Outcome::Failed)]);
        let rows = findings(Some(&w), None, Some(8_000), &[], &band, 1_794_600_000 + 3_600);
        let get = |l: &str| rows.iter().find(|f| f.label == l).unwrap_or_else(|| panic!("{l}: {rows:#?}"));
        let total = get("Last sign-in (profile + Group Policy)");
        assert_eq!((total.value.as_str(), total.severity), ("63.0 s · 1h ago", Severity::Warning));
        assert_eq!(total.metric.as_ref().unwrap().value, 63.0);
        assert!(total.detail.as_deref().unwrap().starts_with("Profile 8.0 s + Group Policy 55.0 s for CORP\\jparker"));
        let fr = get("Policy step: Folder Redirection");
        assert_eq!((fr.value.as_str(), fr.severity), ("41.0 s · 65% of the sign-in", Severity::Warning));
        assert_eq!(get("Policy step: Scripts").severity, Severity::Info);
        assert_eq!(get("Policy step failed: Drive Maps").severity, Severity::Critical);
        assert_eq!(get("Group Policy objects").value, "12 applied · 3 filtered out");
        assert_eq!(summarise(&rows), "Last sign-in: 63.0 s");
    }

    #[test]
    fn a_quick_sign_in_is_fine_and_a_missing_one_is_a_gap() {
        let band = Band { warn: 60.0, crit: 120.0 };
        let w = sign_in(9, vec![phase("Registry", 400, Outcome::Ok)]);
        let rows = findings(Some(&w), None, Some(1_500), &[], &band, 1_794_600_100);
        assert!(rows.iter().all(|f| f.severity.rank() < Severity::Warning.rank()), "{rows:#?}");
        let only_filtered = Waterfall { applied: None, filtered: Some(1), ..sign_in(9, vec![]) };
        let rows = findings(Some(&only_filtered), None, None, &[], &band, 1_794_600_100);
        assert_eq!(rows.iter().find(|f| f.label == "Group Policy objects").unwrap().value, "1 filtered out", "seen on a Windows Server 2025 runner");
        let none = findings(None, None, None, &[], &band, 0);
        assert_eq!((none[0].label.as_str(), none[0].severity), ("Last sign-in", Severity::Info));
        assert_eq!(summarise(&none), "No sign-in policy processing to time");
    }

    #[test]
    fn a_lost_domain_controller_during_sign_in_is_critical() {
        let band = Band { warn: 60.0, crit: 120.0 };
        let w = sign_in(70, vec![]);
        let errors = [
            PolicyError { epoch: w.started + 30, id: 1129, text: String::new() },
            PolicyError { epoch: w.started - 86_400, id: 1058, text: "The network path was not found · file \\\\corp.example.org\\SysVol\\corp.example.org\\Policies\\{31B2F340}\\gpt.ini".into() },
        ];
        let rows = findings(Some(&w), None, None, &errors, &band, w.started + 600);
        let dc = rows.iter().find(|f| f.label == "Domain controller during policy processing").unwrap();
        assert_eq!((dc.severity, dc.value.as_str()), (Severity::Critical, "no domain controller reachable once in 7 days · last 9m ago"));
        let sysvol = rows.iter().find(|f| f.label == "Policy files (SYSVOL)").unwrap();
        assert_eq!(sysvol.severity, Severity::Warning, "yesterday's doesn't explain this sign-in");
        assert!(sysvol.detail.as_deref().unwrap().contains("gpt.ini"));
        let total = rows.iter().find(|f| f.label.starts_with("Last sign-in")).unwrap();
        assert!(total.detail.as_deref().unwrap().contains("the profile load wasn't in the log"));
    }

    #[test]
    fn reads_a_1058s_fields_into_words() {
        let data = vec![
            ("ErrorDescription".to_string(), "The network path was not found. ".to_string()),
            ("DCName".to_string(), "\\\\DC01.corp.example.org".to_string()),
            ("FilePath".to_string(), "\\\\corp.example.org\\sysvol\\gpt.ini".to_string()),
        ];
        assert_eq!(error_text(&data), "The network path was not found · file \\\\corp.example.org\\sysvol\\gpt.ini · domain controller DC01.corp.example.org");
    }
}
