//! Required & clinical apps. Read-only.
//!
//! Checks the site profile's `[[require.app]]` list (installed, and at least
//! `min_version`), then reports which well-known clinical-workstation
//! clients are present: virtual desktop, badge-tap SSO, EHR, dictation, VPN
//! and endpoint security. The watchlist only reports what it finds; nothing
//! on it is assumed to be required anywhere.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::version::{compare, meets};
use crate::profile::AppReq;
use crate::util::plural;

pub struct SiteApps;

impl TriageModule for SiteApps {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "site.apps",
            "Required & clinical apps",
            Category::Site,
            "Apps the site profile requires (with minimum versions), plus which clinical clients are installed: Citrix, Imprivata, Epic, Dragon, VPN, EDR.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        ctx.log("Reading the installed-programs list…");
        let installed = imp::inventory()?;
        let reqs = &ctx.profile().require.app;
        let mut findings = check_required(reqs, &installed);
        let missing = findings.iter().filter(|f| f.severity.rank() >= Severity::Warning.rank()).count();
        let watched = watchlist(&installed, reqs);
        let found = watched.len();
        findings.extend(watched);

        let summary = match (reqs.len(), missing) {
            (0, _) => format!(
                "{} {} installed · {found} watched clinical client{} found",
                installed.len(),
                if cfg!(windows) { "programs" } else { "packages" },
                plural(found)
            ),
            (n, 0) => format!("All {n} required app{} present", plural(n)),
            (n, m) => format!("{m} of {n} required app{} missing or out of date", plural(n)),
        };
        if findings.is_empty() {
            findings.push(Finding::info(
                "Clinical clients",
                "none of the watched clients are installed, and the site profile requires none",
            ));
        }
        Ok(Output::new(summary, findings))
    }
}

/// An installed program: (display name or package name, version).
type Installed = (String, String);

/// Installed entries whose name contains `needle` (case-insensitive).
fn matching<'a>(installed: &'a [Installed], needle: &str) -> Vec<&'a Installed> {
    let n = needle.to_lowercase();
    installed.iter().filter(|(name, _)| name.to_lowercase().contains(&n)).collect()
}

fn check_required(reqs: &[AppReq], installed: &[Installed]) -> Vec<Finding> {
    reqs.iter()
        .map(|r| {
            let label = r.label.clone().unwrap_or_else(|| r.name.clone());
            let hits = matching(installed, &r.name);
            let Some((name, version)) = hits.into_iter().max_by(|a, b| compare(&a.1, &b.1)) else {
                return Finding::warn(label, "not installed");
            };
            let shown = if version.is_empty() { "version unknown".to_string() } else { version.clone() };
            match &r.min_version {
                Some(min) if !meets(version, min) => {
                    Finding::warn(label, format!("{shown} · needs {min} or later")).with_detail(name.clone())
                }
                _ => Finding::ok(label, shown).with_detail(name.clone()),
            }
        })
        .collect()
}

/// (role, display-name fragments, Linux package names)
const WATCHLIST: &[(&str, &[&str], &[&str])] = &[
    ("Virtual desktop", &["Citrix Workspace"], &["icaclient"]),
    ("Virtual desktop", &["Horizon Client"], &["vmware-horizon-client", "omnissa-horizon-client"]),
    ("Badge-tap SSO", &["Imprivata"], &[]),
    ("EHR client", &["Hyperspace", "Hyperdrive"], &[]),
    ("Dictation", &["Dragon Medical", "PowerMic"], &[]),
    ("VPN", &["Cisco Secure Client", "AnyConnect", "GlobalProtect", "Zscaler", "FortiClient"], &["globalprotect", "zscaler"]),
    ("Endpoint security", &["CrowdStrike", "SentinelOne", "Sophos", "Trellix", "Carbon Black"], &["falcon-sensor", "sentinelagent"]),
];

/// Watched clients that are installed and not already covered by a requirement.
fn watchlist(installed: &[Installed], reqs: &[AppReq]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for (role, names, packages) in WATCHLIST {
        let fragments: &[&str] = if cfg!(windows) { names } else { packages };
        for fragment in fragments {
            for (name, version) in matching(installed, fragment) {
                let required = reqs.iter().any(|r| name.to_lowercase().contains(&r.name.to_lowercase()));
                if required || seen.contains(&name.as_str()) {
                    continue;
                }
                seen.push(name.as_str());
                let value = if version.is_empty() { name.clone() } else { format!("{name} {version}") };
                out.push(Finding::info(role.to_string(), value));
            }
        }
    }
    out
}

#[cfg(windows)]
mod imp {
    use super::Installed;

    pub fn inventory() -> Result<Vec<Installed>, String> {
        Ok(crate::win::apps::installed().into_iter().map(|p| (p.name, p.version)).collect())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Installed;
    use crate::util::{capture, cmd, command_exists};

    /// Package names and versions from the distribution's package database.
    pub fn inventory() -> Result<Vec<Installed>, String> {
        if command_exists("dpkg-query") {
            // Status first, so removed-but-configured packages can be skipped.
            let mut c = cmd("dpkg-query");
            c.args(["-W", "-f", "${Status}\t${Package}\t${Version}\n"]).env("LC_ALL", "C");
            let out = capture(c)?;
            return Ok(out
                .stdout
                .lines()
                .filter_map(|l| {
                    let mut f = l.split('\t');
                    let (status, name, version) = (f.next()?, f.next()?, f.next()?);
                    status.ends_with(" installed").then(|| (name.to_string(), version.to_string()))
                })
                .collect());
        }
        let (program, args, sep): (&str, &[&str], char) = if command_exists("rpm") {
            ("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], '\t')
        } else if command_exists("pacman") {
            ("pacman", &["-Q"], ' ')
        } else {
            return Err("No package database found (dpkg, rpm or pacman).".into());
        };
        let mut c = cmd(program);
        c.args(args).env("LC_ALL", "C");
        let out = capture(c)?;
        if !out.success() {
            return Err(format!("{program} couldn't list packages."));
        }
        Ok(out
            .stdout
            .lines()
            .filter_map(|l| l.split_once(sep))
            .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed() -> Vec<Installed> {
        vec![
            ("Citrix Workspace 2402".into(), "24.2.0.187".into()),
            ("Citrix Workspace(USB)".into(), "24.2.0.187".into()),
            ("Imprivata OneSign Agent".into(), "7.11.0".into()),
            ("CrowdStrike Windows Sensor".into(), "7.18.18604.0".into()),
            ("7-Zip 24.08 (x64)".into(), "24.08".into()),
        ]
    }

    fn req(name: &str, min: Option<&str>) -> AppReq {
        AppReq { name: name.into(), min_version: min.map(str::to_string), label: None }
    }

    #[test]
    fn checks_requirements_and_versions() {
        let reqs = vec![
            req("Citrix Workspace", Some("24.2")),
            req("Imprivata", Some("7.12")),
            req("Dragon Medical One", None),
        ];
        let f = check_required(&reqs, &installed());
        assert_eq!(f[0].severity, Severity::Ok);
        assert_eq!(f[0].value, "24.2.0.187");
        assert_eq!(f[1].severity, Severity::Warning);
        assert!(f[1].value.contains("needs 7.12"), "{}", f[1].value);
        assert_eq!(f[2].value, "not installed");
    }

    #[cfg(windows)]
    #[test]
    fn watchlist_skips_required_apps() {
        let reqs = vec![req("Citrix Workspace", None)];
        let w = watchlist(&installed(), &reqs);
        assert!(w.iter().all(|f| !f.value.contains("Citrix")));
        assert!(w.iter().any(|f| f.label == "Badge-tap SSO"));
        assert!(w.iter().any(|f| f.label == "Endpoint security"));
    }
}
