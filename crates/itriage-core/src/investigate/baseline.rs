//! Working-PC baselines: compare configuration observations across hosts,
//! without treating unique identities or changing performance as drift.
use crate::Report;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Difference {
    pub module: String,
    pub label: String,
    pub baseline: Option<String>,
    pub current: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub baseline_host: String,
    pub current_host: String,
    pub baseline_generated: String,
    pub current_generated: String,
    pub role: Option<String>,
    pub differences: Vec<Difference>,
    pub gaps: Vec<String>,
}

fn comparable(module: &str, label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    if [
        "serial",
        "hostname",
        "signed-in",
        "user",
        "session",
        "uptime",
        "pid",
        "thumbprint",
        "ip address",
        "bssid",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        return false;
    }
    match module {
        "system.info" => matches!(
            label,
            "OS" | "Kernel" | "Architecture" | "Model" | "BIOS" | "Motherboard" | "Total memory"
        ),
        "site.apps" | "site.checks" => {
            !lower.contains("server") && !lower.contains("endpoint") && !label.contains(':') && !lower.contains("requirements")
        }
        "proc.services" => !matches!(label, "Running services" | "Stopped by design (skipped)"),
        "sec.posture" => !lower.contains("admin") && !lower.contains("definition"),
        "desk.devices" => !lower.contains("devices detected"),
        _ => false,
    }
}

fn observations(r: &Report) -> BTreeMap<(String, String), String> {
    r.results
        .iter()
        .filter(|m| !m.preview && m.error.is_none())
        .flat_map(|m| {
            m.findings
                .iter()
                .filter(|f| f.metric.is_none() && comparable(&m.module_id, &f.label))
                .map(|f| ((m.module_id.clone(), f.label.clone()), f.value.clone()))
        })
        .collect()
}

pub fn compare(baseline: &Report, current: &Report) -> Result<Comparison, String> {
    if baseline.cancelled || current.cancelled {
        return Err("Use finished reports for a working-PC baseline; cancelled runs can omit evidence.".into());
    }
    if baseline.host.platform != current.host.platform {
        return Err("Working-PC baselines must use the same operating-system platform.".into());
    }
    if baseline.role.is_some() && current.role.is_some() && baseline.role != current.role {
        return Err("These reports have different workstation roles. Choose a working PC with the same role.".into());
    }
    let (old, new) = (observations(baseline), observations(current));
    if old.is_empty() || new.is_empty() {
        return Err("Both reports need configuration checks such as System information or Required apps.".into());
    }
    let mut keys = old.keys().chain(new.keys()).cloned().collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    let differences = keys
        .into_iter()
        .filter_map(|(module, label)| {
            let key = (module.clone(), label.clone());
            let (a, b) = (old.get(&key), new.get(&key));
            (a != b).then(|| Difference {
                module,
                label,
                baseline: a.cloned(),
                current: b.cloned(),
            })
        })
        .collect();
    let mut gaps = vec!["A finding absent from one report was not observed there; it does not prove the component is missing. A baseline difference is not automatically a fault.".into()];
    if baseline.role.is_none() || current.role.is_none() {
        gaps.push(
            "A workstation role is missing. Confirm the two PCs serve the same purpose; set role in the site profile for future runs."
                .into(),
        );
    }
    if baseline.profile != current.profile {
        gaps.push("Site profiles differ; their required apps and thresholds may differ too.".into());
    }
    for r in [baseline, current] {
        if let Some(updated) = &r.evidence_updated {
            gaps.push(format!(
                "{}: this case was updated at {updated}; its configuration observations still come from the checks collected at {}.",
                r.host.hostname, r.generated
            ));
        }
        for m in r.results.iter().filter(|m| m.error.is_some() || m.preview) {
            gaps.push(format!("{}: {} was unavailable or previewed.", r.host.hostname, m.title));
        }
    }
    Ok(Comparison {
        baseline_host: baseline.host.hostname.clone(),
        current_host: current.host.hostname.clone(),
        baseline_generated: baseline.generated.clone(),
        current_generated: current.generated.clone(),
        role: current.role.clone().or_else(|| baseline.role.clone()),
        differences,
        gaps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Category, Finding, ModuleInfo, ModuleResult};
    fn report(host: &str, version: &str) -> Report {
        let mut h = crate::host_context();
        h.hostname = host.into();
        let mut result = ModuleResult::failed(&ModuleInfo::new("site.apps", "Apps", Category::Site, ""), "");
        result.error = None;
        result.findings = vec![Finding::ok("Client", version), Finding::info("Serial number", host)];
        Report::new(h, None, vec![result], false).with_role("clinical")
    }
    #[test]
    fn cross_host_comparison_has_explicit_direction_and_ignores_identifiers() {
        let (a, b) = (report("GOOD", "24.2"), report("BAD", "23.1"));
        let c = compare(&a, &b).unwrap();
        assert_eq!(c.differences.len(), 1);
        assert_eq!(c.differences[0].baseline.as_deref(), Some("24.2"));
        assert_eq!(c.current_host, "BAD");
        assert!(compare(&a, &b.clone().with_role("server")).is_err());
    }
}
