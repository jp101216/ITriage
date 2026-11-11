//! Fixed adaptive diagnostic runbooks. Plans contain read-only module IDs,
//! never shell commands or automatic repairs.
use crate::{ModuleResult, TriageModule};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize)]
pub struct Runbook {
    pub id: &'static str,
    pub title: &'static str,
    pub symptom: &'static str,
}
pub const RUNBOOKS: &[Runbook] = &[
    Runbook {
        id: "printing",
        title: "Printing fails",
        symptom: "A printer is unavailable or jobs stay queued.",
    },
    Runbook {
        id: "vpn",
        title: "VPN connects but apps don't",
        symptom: "Check the tunnel, routing, proxy and application path.",
    },
    Runbook {
        id: "sign-in",
        title: "Sign-in keeps prompting",
        symptom: "Check account state, clock and device / SSO diagnostics.",
    },
    Runbook {
        id: "slow-app",
        title: "An application is slow",
        symptom: "Separate resource pressure from application connectivity and recent changes.",
    },
    Runbook {
        id: "slow-pc",
        title: "The whole PC is slow",
        symptom: "Check load, memory, disk space and startup, then the drive's health and what changed.",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub modules: Vec<String>,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookTrace {
    pub id: String,
    pub steps: Vec<Decision>,
    pub finished: bool,
    pub conclusion: String,
}

pub fn conclusion(results: &[ModuleResult]) -> String {
    let gaps = results.iter().filter(|r| r.error.is_some()).count();
    let problems = results.iter().filter(|r| r.error.is_none() && r.status().rank() >= 2).count();
    if gaps > 0 {
        format!("{problems} check(s) need attention; {gaps} check(s) could not run. Review the evidence gaps before deciding the cause.")
    } else if problems > 0 {
        format!("{problems} check(s) need attention. Review their findings and any offered fixes; finishing this runbook does not mean the issue is repaired.")
    } else {
        "These checks did not reproduce a fault. Use Record issue while the user reproduces it, or export a case for escalation.".into()
    }
}

pub fn next(id: &str, results: &[ModuleResult]) -> Result<Decision, String> {
    next_for(id, results, false)
}
fn next_for(id: &str, results: &[ModuleResult], has_target: bool) -> Result<Decision, String> {
    let initial: &[&str] = match id {
        "printing" => &["desk.printers", "proc.services"],
        "vpn" => &["desk.wifi", "net.connectivity", "net.proxy"],
        "sign-in" if cfg!(windows) => &["desk.identity", "desk.account", "desk.time"],
        "sign-in" => &["desk.account", "desk.time", "net.connectivity"],
        "slow-app" => &["proc.top", "system.memory", "system.disk", "net.applications"],
        "slow-pc" => &["proc.top", "system.memory", "system.disk", "system.startup"],
        _ => return Err(format!("Unknown troubleshooting runbook `{id}`.")),
    };
    let missing = |ids: &[&str]| {
        ids.iter()
            .filter(|id| !results.iter().any(|r| r.module_id == **id))
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
    };
    let mut first = missing(initial);
    if has_target && !results.iter().any(|r| r.module_id == "net.target") {
        first.push("net.target".into());
    }
    if !first.is_empty() {
        return Ok(Decision {
            modules: first,
            reason: "Start with the checks closest to the reported symptom. These checks only inspect the computer.".into(),
        });
    }
    let bad = |id: &str| {
        results
            .iter()
            .any(|r| r.module_id == id && (r.error.is_some() || r.status().rank() >= 2))
    };
    let (more, reason): (&[&str], &str) = match id {
        "printing" if bad("desk.printers") || bad("proc.services") => (&["site.checks", "net.connectivity", "site.apps"], "Printing or service evidence needs attention. Check the site's print service and network dependencies before choosing a fix."),
        "vpn" => (&["site.checks", "net.applications", "net.wifi-auth", "desk.time"], "A running VPN client does not establish that the application path works. Test configured endpoints, authentication history and clock state."),
        "sign-in" if initial.iter().any(|id| bad(id)) => if cfg!(windows) {
            (&["desk.domain", "net.connectivity", "net.proxy", "site.checks"], "Account, SSO or clock evidence needs attention. Check domain and connection dependencies, preserving unavailable checks as gaps.")
        } else { (&["net.proxy", "site.checks"], "Check the site's connectivity dependencies before escalating the account problem.") },
        "slow-app" => (&["site.apps", "site.checks", "system.reliability", "system.changes"], "Compare the application's required version and service path with resource pressure, failures and recent change evidence."),
        // Adding up folders takes a while: only when the disk is the problem.
        "slow-pc" if bad("system.disk") => (&["system.storage", "system.reliability", "system.changes"], "The disk needs attention: see what is using the space, whether the drive is healthy, and what changed recently."),
        "slow-pc" => (&["system.reliability", "system.changes"], "Free space isn't the problem. Check the drive's health and crash history, and what changed recently."),
        _ => (&[], "The initial checks did not establish a fault. Capture the intermittent issue or export the evidence."),
    };
    Ok(Decision {
        modules: missing(more),
        reason: reason.into(),
    })
}

/// The shell owns progress streaming and cancellation. Returning None from
/// `execute` stops at a safe module boundary and preserves completed results.
pub fn run(
    id: &str,
    execute: impl FnMut(&dyn TriageModule, usize, usize, &str) -> Option<ModuleResult>,
) -> Result<(Vec<ModuleResult>, RunbookTrace), String> {
    run_for(id, false, execute)
}
pub fn run_for(
    id: &str,
    has_target: bool,
    mut execute: impl FnMut(&dyn TriageModule, usize, usize, &str) -> Option<ModuleResult>,
) -> Result<(Vec<ModuleResult>, RunbookTrace), String> {
    let mut results = Vec::new();
    let mut trace = RunbookTrace {
        id: id.into(),
        steps: Vec::new(),
        finished: false,
        conclusion: String::new(),
    };
    for _ in 0..4 {
        let decision = next_for(id, &results, has_target)?;
        if decision.modules.is_empty() {
            trace.finished = true;
            break;
        }
        let total = results.len() + decision.modules.len();
        trace.steps.push(decision.clone());
        for wanted in &decision.modules {
            let module = crate::registry()
                .into_iter()
                .find(|m| m.info().id == *wanted)
                .ok_or_else(|| format!("Runbook refers to unknown module {wanted}"))?;
            if module.info().mutating {
                return Err("A diagnostic runbook may not change the machine.".into());
            }
            let Some(result) = execute(module.as_ref(), results.len(), total, &decision.reason) else {
                trace.conclusion = "Stopped before all diagnostic steps finished. Completed evidence was retained.".into();
                return Ok((results, trace));
            };
            results.push(result);
        }
    }
    trace.conclusion = conclusion(&results);
    Ok((results, trace))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_explicit_target_is_not_lost_in_a_guided_run() {
        let (results, trace) = run_for("vpn", true, |m, _, _, _| Some(ModuleResult::failed(&m.info(), "fixture"))).unwrap();
        assert_eq!(results.iter().filter(|r| r.module_id == "net.target").count(), 1);
        assert!(trace.steps[0].modules.iter().any(|id| id == "net.target"));
    }
    #[test]
    fn every_runbook_finishes_and_printing_branches_on_actual_findings() {
        for book in RUNBOOKS {
            for problem in [false, true] {
                let (_, trace) = run(book.id, |m, _, _, _| {
                    let mut r = ModuleResult::failed(&m.info(), "");
                    r.error = None;
                    r.findings = vec![if problem {
                        crate::Finding::warn("Fixture", "needs attention")
                    } else {
                        crate::Finding::ok("Fixture", "healthy")
                    }];
                    Some(r)
                })
                .unwrap();
                assert!(trace.finished);
                if book.id == "printing" {
                    assert_eq!(trace.steps.len(), if problem { 2 } else { 1 });
                }
            }
        }
    }
    #[test]
    fn a_slow_pc_only_has_its_folders_added_up_when_the_disk_is_the_problem() {
        let run_with = |disk_is_full: bool| {
            run("slow-pc", |m, _, _, _| {
                let mut r = ModuleResult::failed(&m.info(), "");
                r.error = None;
                r.findings = vec![if disk_is_full && m.info().id == "system.disk" {
                    crate::Finding::crit("C:\\", "2% free")
                } else {
                    crate::Finding::ok("Fixture", "healthy")
                }];
                Some(r)
            })
            .unwrap()
        };
        let ids = |results: &[ModuleResult]| results.iter().map(|r| r.module_id.clone()).collect::<Vec<_>>();
        let (full, trace) = run_with(true);
        assert_eq!(ids(&full), ["proc.top", "system.memory", "system.disk", "system.startup", "system.storage", "system.reliability", "system.changes"]);
        assert!(trace.finished && trace.steps[1].reason.contains("what is using the space"));
        let (fine, trace) = run_with(false);
        assert!(!ids(&fine).contains(&"system.storage".to_string()));
        assert!(trace.finished && trace.steps.len() == 2);
    }

    #[test]
    fn adaptive_vpn_plan_is_read_only_bounded_and_keeps_its_reasoning() {
        let (results, trace) = run("vpn", |m, _, _, _| {
            assert!(!m.info().mutating);
            let mut result = ModuleResult::failed(&m.info(), "fixture unavailable");
            result.log.push("fixture, no real check".into());
            Some(result)
        })
        .unwrap();
        assert!(trace.finished && trace.steps.len() == 2 && results.len() < 12);
        assert!(results.iter().any(|r| r.module_id == "net.applications"));
        assert!(trace.conclusion.contains("could not run"));
        let mut ids = results.iter().map(|r| r.module_id.clone()).collect::<Vec<_>>();
        let before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), before);
    }
    #[test]
    fn cancellation_and_unknown_runbooks_do_not_start_more_checks() {
        assert!(run("unknown", |_, _, _, _| panic!("must not execute")).is_err());
        let (results, trace) = run("printing", |_, _, _, _| None).unwrap();
        assert!(results.is_empty() && !trace.finished);
    }
}
