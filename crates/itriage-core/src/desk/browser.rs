//! Microsoft Edge's Internet Explorer mode and its Enterprise Mode Site
//! List. Read-only, Windows only.
//!
//! Older clinical and departmental web apps often work only in IE mode.
//! When the site list is stale, unreachable, or missing an entry, those
//! apps break for everyone at once and it looks like the app is down. This
//! reads the two Edge policies, fetches the list the way it's configured
//! (a web address or a file share), and says which of the site's own
//! application URLs open in IE mode.

use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
use crate::parse::sitelist::{self, SiteList};
use crate::util::human_bytes;

pub struct EdgeSiteList;

impl TriageModule for EdgeSiteList {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.browser",
            "Edge IE mode site list",
            Category::Workstation,
            "Whether Edge's Internet Explorer mode is set up, whether its Enterprise Mode Site List can be fetched and read, and which of the site's application URLs (and the target) open in IE mode.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let mut urls: Vec<(String, String)> =
            ctx.profile().require.application.iter().map(|a| (a.label.clone(), a.url.clone())).collect();
        if let Some(t) = ctx.target() {
            urls.push((t.host.clone(), t.host.clone()));
        }
        let facts = imp::gather(urls);
        let rows = findings(&facts);
        let attention = rows.iter().filter(|f| f.severity.rank() >= crate::model::Severity::Warning.rank()).count();
        Ok(Output::new(
            match (attention, facts.level, facts.location.is_some()) {
                (0, None | Some(0), false) => "IE mode isn't set up in Edge".to_string(),
                (0, _, _) => "Edge IE mode and its site list look healthy".to_string(),
                (n, _, _) => format!("{n} IE mode finding{} need{} attention", crate::util::plural(n), if n == 1 { "s" } else { "" }),
            },
            rows,
        ))
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("Edge's IE mode is Windows-only.".into())
    }
}

/// What was read and fetched. Plain data, so the grading is tested on any OS.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// `InternetExplorerIntegrationLevel`, and whose policy set it.
    pub level: Option<u32>,
    pub level_scope: &'static str,
    /// `InternetExplorerIntegrationSiteList`.
    pub location: Option<String>,
    pub location_scope: &'static str,
    /// The fetch: the list, its size and how long it took, or why not.
    pub fetched: Option<Result<(SiteList, usize, u64), String>>,
    pub edge_version: Option<String>,
    /// The site's application URLs and the target: label, URL.
    pub urls: Vec<(String, String)>,
}

pub fn findings(f: &Facts) -> Vec<Finding> {
    let mut out = Vec::new();
    let scope = |s: &str| if s.is_empty() { String::new() } else { format!(" ({s} policy)") };
    let ie_on = matches!(f.level, Some(1 | 2));
    out.push(match f.level {
        None => Finding::info("IE integration", "not set by policy: no site opens in IE mode unless the user turns it on"),
        Some(0) => Finding::info("IE integration", format!("None{}", scope(f.level_scope))),
        Some(1) => Finding::ok("IE integration", format!("Internet Explorer mode{}", scope(f.level_scope))),
        Some(2) => Finding::warn("IE integration", format!("Internet Explorer 11{}", scope(f.level_scope)))
            .with_detail("This setting opens listed sites in the standalone Internet Explorer 11, which is retired. Microsoft's guidance is IE mode (value 1)."),
        Some(n) => Finding::warn("IE integration", format!("unknown value {n}{}", scope(f.level_scope))),
    });
    match (&f.location, ie_on) {
        (None, true) => out.push(
            Finding::warn("Enterprise site list", "IE mode is on, but no site list is set")
                .with_detail("Without InternetExplorerIntegrationSiteList, Edge only opens sites in IE mode that the user adds by hand."),
        ),
        (None, false) => {}
        (Some(loc), _) => {
            let mut row = match &f.fetched {
                None => Finding::info("Enterprise site list", "not fetched"),
                Some(Err(why)) => Finding::warn("Enterprise site list", format!("can't be fetched: {why}")).with_detail(format!(
                    "{loc}{}. Edge keeps using the copy it downloaded last, so sites that already worked still do, but changes to the list won't arrive. edge://compat/enterprise shows what Edge itself has.",
                    scope(f.location_scope)
                )),
                Some(Ok((list, size, ms))) => {
                    let ie = list.sites.iter().filter(|s| s.ie_mode()).count();
                    let version = list.version.map(|v| format!("version {v} · ")).unwrap_or_default();
                    let words = format!("{version}{} entr{} ({ie} in IE mode) · {} in {ms} ms", list.sites.len(), if list.sites.len() == 1 { "y" } else { "ies" }, human_bytes(*size as u64));
                    let detail = format!("{loc}{}. Fetched by ITriage's account through the system proxy; Edge fetches it as the user, which can differ on a file share. edge://compat/enterprise shows what Edge itself has.", scope(f.location_scope));
                    if list.legacy {
                        Finding::info("Enterprise site list", format!("{words} · version 1 schema")).with_detail(format!(
                            "{detail} It's in Internet Explorer 11's own (version 1) format; Microsoft's Enterprise Mode Site List Manager converts it to version 2."
                        ))
                    } else if list.sites.is_empty() {
                        Finding::warn("Enterprise site list", format!("{words} · empty")).with_detail(detail)
                    } else {
                        Finding::ok("Enterprise site list", words).with_detail(detail)
                    }
                }
            };
            if !ie_on {
                row = Finding::warn("Enterprise site list", "set, but IE integration isn't set to IE mode, so Edge ignores it")
                    .with_detail(format!("{loc}{}. The site list only applies with InternetExplorerIntegrationLevel = 1.", scope(f.location_scope)));
            }
            out.push(row);
        }
    }
    if let Some(v) = &f.edge_version {
        out.push(Finding::info("Microsoft Edge", v.clone()));
    }
    if let Some(Ok((list, _, _))) = &f.fetched {
        if ie_on {
            for (label, url) in &f.urls {
                let (value, detail) = match sitelist::lookup(list, url) {
                    Some(site) if site.ie_mode() => (
                        format!("opens in IE mode{}", if site.compat_mode.is_empty() { String::new() } else { format!(" ({})", site.compat_mode) }),
                        format!("{url} matches the entry {}", site.url),
                    ),
                    Some(site) => ("opens in Edge".to_string(), format!("{url} matches the entry {} (open in {})", site.url, if site.open_in.is_empty() { "Edge" } else { &site.open_in })),
                    None => ("opens in Edge (not in the list)".to_string(), format!("No entry matches {url}. If this app needs IE mode, it's missing from the site list.")),
                };
                out.push(Finding::info(format!("Site: {label}"), value).with_detail(detail));
            }
        }
    }
    out
}

/// A `file:` URL as a path Windows can open: `file:///C:/x` → `C:/x`,
/// `file://server/share/x` → `\\server\share\x`. Other text is returned as is.
pub fn local_path(location: &str) -> String {
    let lower = location.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("file:").map(|_| &location[5..]) {
        let rest = rest.trim_start_matches('/');
        let decoded = rest.replace("%20", " ");
        // `C:/…` after the slashes is a drive; anything else is a server.
        if decoded.len() >= 2 && decoded.as_bytes()[1] == b':' {
            return decoded;
        }
        return format!(r"\\{}", decoded.replace('/', "\\"));
    }
    location.to_string()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::win::registry::{read_dword, read_string, HKLM};
    use std::time::{Duration, Instant};

    const POLICY: &str = r"SOFTWARE\Policies\Microsoft\Edge";
    const MAX_BYTES: usize = 8 * 1024 * 1024;

    pub fn gather(urls: Vec<(String, String)>) -> Facts {
        let who = crate::win::session::person().ok();
        let user_key = who.as_ref().map(|p| p.key(POLICY));
        let mut f = Facts { urls, ..Facts::default() };
        // Machine policy wins over user policy in Edge.
        let dword = |name: &str| {
            read_dword(HKLM, POLICY, name).map(|v| (v, "computer")).or_else(|| {
                who.as_ref().zip(user_key.as_deref()).and_then(|(p, k)| read_dword(p.root, k, name)).map(|v| (v, "user"))
            })
        };
        let string = |name: &str| {
            read_string(HKLM, POLICY, name).map(|v| (v, "computer")).or_else(|| {
                who.as_ref().zip(user_key.as_deref()).and_then(|(p, k)| read_string(p.root, k, name)).map(|v| (v, "user"))
            })
        };
        if let Some((v, scope)) = dword("InternetExplorerIntegrationLevel") {
            (f.level, f.level_scope) = (Some(v), scope);
        }
        if let Some((v, scope)) = string("InternetExplorerIntegrationSiteList").filter(|(v, _)| !v.trim().is_empty()) {
            (f.location, f.location_scope) = (Some(v.trim().to_string()), scope);
        }
        if let Some(loc) = &f.location {
            f.fetched = Some(fetch(loc));
        }
        f.edge_version = edge_exe().and_then(|p| crate::win::apps::file_version(&p));
        f
    }

    fn fetch(location: &str) -> Result<(SiteList, usize, u64), String> {
        let started = Instant::now();
        let lower = location.to_ascii_lowercase();
        let bytes = if lower.starts_with("http://") || lower.starts_with("https://") {
            crate::win::net::http_get_bytes(location, Duration::from_secs(10), MAX_BYTES)?
        } else {
            let path = std::path::PathBuf::from(local_path(location));
            let meta = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            if meta.len() > MAX_BYTES as u64 {
                return Err(format!("{} is larger than {} MiB", path.display(), MAX_BYTES / 1024 / 1024));
            }
            std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?
        };
        let ms = started.elapsed().as_millis() as u64;
        let text = decode(&bytes);
        let list = sitelist::parse(&text)?;
        Ok((list, bytes.len(), ms))
    }

    /// UTF-8 or UTF-16 (a list saved from Notepad can be either).
    fn decode(bytes: &[u8]) -> String {
        let utf16 = |le: bool, b: &[u8]| {
            let units: Vec<u16> = b.chunks_exact(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) }).collect();
            String::from_utf16_lossy(&units)
        };
        match bytes {
            [0xFF, 0xFE, rest @ ..] => utf16(true, rest),
            [0xFE, 0xFF, rest @ ..] => utf16(false, rest),
            _ => String::from_utf8_lossy(bytes).into_owned(),
        }
    }

    fn edge_exe() -> Option<std::path::PathBuf> {
        const APP_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe";
        read_string(HKLM, APP_PATH, "")
            .map(|p| std::path::PathBuf::from(p.trim_matches('"')))
            .filter(|p| p.is_file())
            .or_else(|| {
                [crate::win::dirs::program_files_x86(), crate::win::dirs::program_files()]
                    .into_iter()
                    .flatten()
                    .map(|d| d.join(r"Microsoft\Edge\Application\msedge.exe"))
                    .find(|p| p.is_file())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    const LIST: &str = r#"<site-list version="12"><site url="ehr.example.org/legacy"><compat-mode>IE8Enterprise</compat-mode><open-in>IE11</open-in></site><site url="ehr.example.org"><open-in>MSEdge</open-in></site></site-list>"#;

    fn facts() -> Facts {
        Facts {
            level: Some(1),
            level_scope: "computer",
            location: Some("https://intranet.example.org/sites.xml".into()),
            location_scope: "computer",
            fetched: Some(Ok((sitelist::parse(LIST).unwrap(), LIST.len(), 84))),
            edge_version: Some("142.0.3595.53".into()),
            urls: vec![
                ("EHR legacy charting".into(), "https://ehr.example.org/legacy/chart.aspx".into()),
                ("EHR".into(), "https://ehr.example.org/".into()),
                ("Lab results".into(), "https://lab.example.org/".into()),
            ],
        }
    }

    #[test]
    fn a_healthy_list_says_where_each_app_opens() {
        let rows = findings(&facts());
        let value = |label: &str| rows.iter().find(|r| r.label == label).map(|r| (r.severity, r.value.clone())).unwrap();
        assert_eq!(value("IE integration"), (Severity::Ok, "Internet Explorer mode (computer policy)".into()));
        assert_eq!(value("Enterprise site list").0, Severity::Ok);
        assert!(value("Enterprise site list").1.starts_with("version 12 · 2 entries (1 in IE mode) · "));
        assert_eq!(value("Site: EHR legacy charting").1, "opens in IE mode (IE8Enterprise)");
        assert_eq!(value("Site: EHR").1, "opens in Edge");
        assert_eq!(value("Site: Lab results").1, "opens in Edge (not in the list)");
        assert_eq!(value("Microsoft Edge").1, "142.0.3595.53");
    }

    #[test]
    fn unreachable_missing_and_ignored_lists_are_warnings() {
        let down = Facts { fetched: Some(Err("intranet.example.org answered HTTP 404".into())), ..facts() };
        let rows = findings(&down);
        let list = rows.iter().find(|r| r.label == "Enterprise site list").unwrap();
        assert_eq!((list.severity, list.value.as_str()), (Severity::Warning, "can't be fetched: intranet.example.org answered HTTP 404"));
        assert!(list.detail.as_deref().unwrap().contains("keeps using the copy it downloaded last"));
        assert!(!rows.iter().any(|r| r.label.starts_with("Site: ")), "no lookups without a list");

        let missing = findings(&Facts { location: None, fetched: None, ..facts() });
        assert_eq!(missing[1].value, "IE mode is on, but no site list is set");

        let ignored = findings(&Facts { level: Some(0), ..facts() });
        assert_eq!(ignored[1].value, "set, but IE integration isn't set to IE mode, so Edge ignores it");

        let off = findings(&Facts { level: None, location: None, fetched: None, edge_version: None, ..facts() });
        assert_eq!(off.len(), 1);
        assert_eq!(off[0].severity, Severity::Info);
        assert_eq!(findings(&Facts { level: Some(2), ..facts() })[0].severity, Severity::Warning);
    }

    #[test]
    fn file_urls_become_paths() {
        assert_eq!(local_path("file:///C:/Policies/sites.xml"), "C:/Policies/sites.xml");
        assert_eq!(local_path("file://fs01.corp.example.org/policies/Site%20List.xml"), r"\\fs01.corp.example.org\policies\Site List.xml");
        assert_eq!(local_path(r"\\fs01\policies\sites.xml"), r"\\fs01\policies\sites.xml");
        assert_eq!(local_path(r"C:\sites.xml"), r"C:\sites.xml");
    }
}
