//! Major-incident awareness: "this matches a known incident" in the first
//! seconds, so a technician doesn't troubleshoot an outage from scratch.
//!
//! The site publishes a small JSON file of open incidents. Only a managed
//! profile may name it (a user's own profile can't put a fake banner in
//! front of a technician), only over HTTPS, fetched once per run with a
//! short timeout. A fetch that fails is a quiet note in the report, never
//! an error.
//!
//! ```json
//! { "updated": "2026-11-12T13:05:00Z",
//!   "incidents": [ { "id": "INC0012345", "title": "VPN gateway outage",
//!     "module": "net.target", "match": "vpn\\.example\\.org",
//!     "subnets": ["10.20.0.0/16"], "url": "https://status.example.org/INC0012345" } ] }
//! ```
//!
//! An incident applies when everything it names holds: a finding in that
//! module (any module, without one) whose label, value or detail matches the
//! case-insensitive regular expression, and this PC having an address in
//! one of the subnets. One that names neither is site-wide and always applies.

use crate::model::ModuleResult;
use crate::parse::net::Subnet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// The feed's size limit: a status file is a few kilobytes.
const MAX_INCIDENTS: usize = 50;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Feed {
    #[serde(default)]
    pub updated: Option<String>,
    #[serde(default)]
    pub incidents: Vec<Incident>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default, rename = "match")]
    pub pattern: Option<String>,
    #[serde(default)]
    pub subnets: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// An incident this run matched, as kept in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnownIncident {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// What matched: "Destination test: TCP 443: timed out" or "address
    /// 10.20.4.17 in 10.20.0.0/16".
    pub because: String,
}

fn clean(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}

/// The incidents that apply to this run.
pub fn matches(feed: &Feed, results: &[ModuleResult], addresses: &[IpAddr]) -> Vec<KnownIncident> {
    let mut out = Vec::new();
    for incident in feed.incidents.iter().take(MAX_INCIDENTS) {
        let id = clean(&incident.id, 40);
        let title = clean(&incident.title, 200);
        if id.is_empty() || title.is_empty() {
            continue;
        }
        let mut because = Vec::new();
        if !incident.subnets.is_empty() {
            let subnets: Vec<Subnet> = incident.subnets.iter().filter_map(|s| Subnet::parse(s).ok()).collect();
            let Some((ip, net)) = addresses.iter().find_map(|ip| subnets.iter().find(|n| n.contains(*ip)).map(|n| (*ip, *n))) else { continue };
            because.push(format!("address {ip} in {net}"));
        }
        if let Some(pattern) = incident.pattern.as_deref().filter(|p| !p.trim().is_empty()) {
            // Built small: a status file is someone else's text.
            let Ok(re) = regex::RegexBuilder::new(pattern).case_insensitive(true).size_limit(1 << 16).build() else { continue };
            let module = incident.module.as_deref().filter(|m| !m.trim().is_empty());
            let hit = results
                .iter()
                .filter(|r| module.is_none_or(|m| r.module_id.eq_ignore_ascii_case(m)))
                .find_map(|r| {
                    r.findings
                        .iter()
                        .find(|f| re.is_match(&f.label) || re.is_match(&f.value) || f.detail.as_deref().is_some_and(|d| re.is_match(d)))
                        .map(|f| format!("{}: {}: {}", r.title, f.label, clean(&f.value, 120)))
                });
            match hit {
                Some(h) => because.push(h),
                None => continue,
            }
        }
        if because.is_empty() {
            because.push("site-wide".into());
        }
        let url = incident.url.as_deref().map(|u| clean(u, 300)).filter(|u| u.starts_with("https://"));
        out.push(KnownIncident { id, title, url, because: because.join(" · ") });
    }
    out
}

/// The feed's address, when the profile may name one: a managed profile,
/// an `https://` URL.
pub fn source(profile: &crate::profile::Profile, profile_source: &str) -> Option<(String, Duration)> {
    let url = profile.status.url.as_deref()?.trim();
    if profile_source != "managed" || !url.starts_with("https://") || url.chars().any(char::is_whitespace) {
        return None;
    }
    Some((url.to_string(), Duration::from_millis(profile.status.timeout_ms.clamp(500, 10_000))))
}

pub fn parse(text: &str) -> Result<Feed, String> {
    serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| format!("not a status feed ({e})"))
}

/// Fetch the feed and match it: (incidents, a note when the feed couldn't
/// be read).
pub fn check(profile: &crate::profile::Profile, profile_source: &str, results: &[ModuleResult]) -> (Vec<KnownIncident>, Option<String>) {
    let Some((url, timeout)) = source(profile, profile_source) else {
        return (Vec::new(), None);
    };
    let feed = match crate::net::http_get(&url, timeout).and_then(|t| parse(&t)) {
        Ok(f) => f,
        Err(e) => return (Vec::new(), Some(format!("The site's incident feed couldn't be read: {}", clean(&e, 200)))),
    };
    let addresses: Vec<IpAddr> = crate::net::interfaces()
        .unwrap_or_default()
        .iter()
        .filter(|i| i.up && !i.loopback)
        .flat_map(|i| i.addresses.iter().map(|a| a.ip))
        .filter(|ip| crate::net::is_usable(*ip))
        .collect();
    (matches(&feed, results, &addresses), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Finding, ModuleInfo};

    const FEED: &str = r#"{ "updated": "2026-11-12T13:05:00Z",
      "incidents": [
        { "id": "INC0012345", "title": "VPN gateway outage", "module": "net.target", "match": "vpn\\.example\\.org",
          "url": "https://status.example.org/INC0012345" },
        { "id": "INC0012346", "title": "Ward 4 switch down", "subnets": ["10.20.0.0/16"] },
        { "id": "INC0012347", "title": "EHR slow for everyone" },
        { "id": "INC0012348", "title": "Print server", "match": "prn09", "subnets": ["10.99.0.0/16"] },
        { "id": "INC0012349", "title": "Bad pattern", "match": "(" },
        { "id": "", "title": "no id" }
      ] }"#;

    fn result(id: &str, findings: Vec<Finding>) -> ModuleResult {
        let mut r = ModuleResult::failed(&ModuleInfo::new(id, "Destination test", Category::Network, ""), "");
        r.error = None;
        r.findings = findings;
        r
    }

    #[test]
    fn incidents_match_by_module_pattern_and_subnet() {
        let feed = parse(FEED).unwrap();
        let results = vec![result("net.target", vec![Finding::crit("TCP 443 to VPN.example.org", "timed out")])];
        let here: Vec<IpAddr> = vec!["10.20.4.17".parse().unwrap()];
        let found = matches(&feed, &results, &here);
        let ids: Vec<&str> = found.iter().map(|k| k.id.as_str()).collect();
        assert_eq!(ids, ["INC0012345", "INC0012346", "INC0012347"]);
        assert_eq!(found[0].because, "Destination test: TCP 443 to VPN.example.org: timed out");
        assert_eq!(found[0].url.as_deref(), Some("https://status.example.org/INC0012345"));
        assert_eq!(found[1].because, "address 10.20.4.17 in 10.20.0.0/16");
        assert_eq!(found[2].because, "site-wide");
        // Elsewhere, and with nothing failing, only the site-wide one applies.
        let elsewhere = matches(&feed, &[result("net.target", vec![])], &["10.30.1.1".parse().unwrap()]);
        assert_eq!(elsewhere.iter().map(|k| k.id.as_str()).collect::<Vec<_>>(), ["INC0012347"]);
        // The module limits where the pattern looks.
        let other = matches(&feed, &[result("site.checks", vec![Finding::crit("vpn.example.org", "down")])], &[]);
        assert!(!other.iter().any(|k| k.id == "INC0012345"));
    }

    #[test]
    fn only_a_managed_profile_over_https_names_a_feed() {
        let mut p = crate::profile::Profile::default();
        p.status.url = Some("https://itstatus.example.org/itriage.json".into());
        assert!(source(&p, "managed").is_some());
        assert!(source(&p, "user").is_none(), "a user's own profile can't add a banner");
        assert!(source(&p, "env").is_none());
        p.status.url = Some("http://itstatus.example.org/itriage.json".into());
        assert!(source(&p, "managed").is_none(), "HTTPS only");
        p.status.url = Some("https://a.example.org/x -o /tmp/y".into());
        assert!(source(&p, "managed").is_none());
        assert!(parse("<html>sign in</html>").is_err());
        let p = crate::profile::Profile::from_toml("[status]\nurl = \"https://itstatus.example.org/itriage.json\"\ntimeout_ms = 50\n").unwrap();
        assert_eq!(source(&p, "managed").unwrap().1, Duration::from_millis(500), "a timeout too short to work is raised");
    }

    #[test]
    fn feed_text_is_cleaned() {
        let feed = parse(r#"{"incidents":[{"id":"INC1\u0007","title":"Outage\nline two","url":"javascript:alert(1)"}]}"#).unwrap();
        let found = matches(&feed, &[], &[]);
        assert_eq!((found[0].id.as_str(), found[0].title.as_str(), found[0].url.as_deref()), ("INC1", "Outageline two", None));
    }
}
