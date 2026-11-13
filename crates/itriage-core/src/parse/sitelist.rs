//! The Enterprise Mode Site List that tells Microsoft Edge which sites open
//! in Internet Explorer mode.
//!
//! Version 2 of the schema:
//!
//! ```xml
//! <site-list version="205">
//!   <site url="www.contoso.com/travel">
//!     <compat-mode>IE8Enterprise</compat-mode>
//!     <open-in>IE11</open-in>
//!   </site>
//! </site-list>
//! ```
//!
//! `open-in` of `IE11` means IE mode; `MSEdge` and `None` mean Edge. The
//! older version 1 (`<rules version="1">` with `<emie>` and `<docMode>`
//! domains) is read for its version and entry count and reported as
//! legacy. A URL is matched against the most specific entry: its host or a
//! parent domain, then the longest path prefix.

#[derive(Debug, Clone, PartialEq)]
pub struct Site {
    /// As written: `www.contoso.com/travel`, `contoso.com:8080`.
    pub url: String,
    pub compat_mode: String,
    pub open_in: String,
}

impl Site {
    pub fn ie_mode(&self) -> bool {
        self.open_in.eq_ignore_ascii_case("IE11")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteList {
    pub version: Option<u32>,
    /// The version 1 schema (Internet Explorer 11's own).
    pub legacy: bool,
    pub sites: Vec<Site>,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// The value of `name="…"` (or '…') inside one opening tag.
fn attr(tag: &str, name: &str) -> Option<String> {
    let at = tag.find(&format!("{name}="))? + name.len() + 1;
    let quote = tag[at..].chars().next().filter(|q| *q == '"' || *q == '\'')?;
    let rest = &tag[at + 1..];
    Some(unescape(&rest[..rest.find(quote)?]))
}

/// The text of the first `<tag …>text</tag>` in `body`.
fn element(body: &str, tag: &str) -> Option<String> {
    let open = body.find(&format!("<{tag}"))?;
    let after = &body[open..];
    let start = after.find('>')? + 1;
    if after[..start].ends_with("/>") {
        return Some(String::new());
    }
    let end = after.find(&format!("</{tag}>"))?;
    Some(unescape(after[start..end].trim()))
}

pub fn parse(xml: &str) -> Result<SiteList, String> {
    let xml = xml.trim_start_matches('\u{feff}');
    if let Some(root) = xml.find("<site-list") {
        let tag = &xml[root..root + xml[root..].find('>').ok_or("The site list's root tag isn't closed.")?];
        let version = attr(tag, "version").and_then(|v| v.trim().parse().ok());
        let mut sites = Vec::new();
        let mut rest = &xml[root..];
        while let Some(at) = rest.find("<site ").or_else(|| rest.find("<site\t")).or_else(|| rest.find("<site\n")) {
            let block = &rest[at..];
            let open_end = block.find('>').ok_or("A <site> tag isn't closed.")?;
            let open = &block[..open_end];
            let (body, next) = if open.ends_with('/') {
                ("", open_end + 1)
            } else {
                let close = block.find("</site>").ok_or("A <site> has no </site>.")?;
                (&block[open_end + 1..close], close + "</site>".len())
            };
            if let Some(url) = attr(open, "url").filter(|u| !u.trim().is_empty()) {
                sites.push(Site {
                    url: url.trim().to_string(),
                    compat_mode: element(body, "compat-mode").unwrap_or_default(),
                    open_in: element(body, "open-in").unwrap_or_default(),
                });
            }
            rest = &block[next..];
        }
        return Ok(SiteList { version, legacy: false, sites });
    }
    if let Some(root) = xml.find("<rules") {
        let tag = &xml[root..root + xml[root..].find('>').ok_or("The site list's root tag isn't closed.")?];
        let version = attr(tag, "version").and_then(|v| v.trim().parse().ok());
        let mut sites = Vec::new();
        if let Some(emie) = xml.find("<emie>") {
            let body = &xml[emie..xml[emie..].find("</emie>").map(|e| emie + e).unwrap_or(xml.len())];
            let mut rest = body;
            while let Some(at) = rest.find("<domain") {
                let block = &rest[at..];
                let start = block.find('>').map(|i| i + 1).unwrap_or(block.len());
                let end = block[start..].find('<').map(|i| start + i).unwrap_or(block.len());
                let domain = unescape(block[start..end].trim());
                if !domain.is_empty() {
                    sites.push(Site { url: domain, compat_mode: String::new(), open_in: "IE11".into() });
                }
                rest = &block[end..];
            }
        }
        return Ok(SiteList { version, legacy: true, sites });
    }
    Err("This isn't an Enterprise Mode Site List: there's no <site-list> or <rules> root.".into())
}

/// Host (lower case, no port), port and path of a URL or a site entry.
fn split(url: &str) -> (String, Option<u16>, String) {
    let no_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let (authority, path) = match no_scheme.find('/') {
        Some(i) => (&no_scheme[..i], &no_scheme[i..]),
        None => (no_scheme, ""),
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && !h.contains(':') => (h, p.parse().ok()),
        _ => (authority, None),
    };
    let path = path.split(['?', '#']).next().unwrap_or("").trim_end_matches('/').to_ascii_lowercase();
    (host.trim_matches(['[', ']']).to_ascii_lowercase(), port, path)
}

/// The most specific entry that applies to `url`, if any.
pub fn lookup<'a>(list: &'a SiteList, url: &str) -> Option<&'a Site> {
    let (host, port, path) = split(url);
    list.sites
        .iter()
        .filter_map(|site| {
            let (h, p, sp) = split(&site.url);
            let host_ok = host == h || host.ends_with(&format!(".{h}"));
            let port_ok = p.is_none() || p == port;
            let path_ok = sp.is_empty() || path == sp || path.starts_with(&format!("{sp}/"));
            (host_ok && port_ok && path_ok && !h.is_empty()).then_some((site, (h.len(), sp.len(), p.is_some())))
        })
        .max_by_key(|(_, specificity)| *specificity)
        .map(|(site, _)| site)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<site-list version="205">
  <created-by>
    <tool>EMIESiteListManager</tool>
    <version>10.0.14357.1004</version>
    <date-created>7/15/2016 05:35:31</date-created>
  </created-by>
  <site url="www.contoso.com/travel">
    <compat-mode>IE8Enterprise</compat-mode>
    <open-in>IE11</open-in>
  </site>
  <site url="contoso.com">
    <compat-mode>default</compat-mode>
    <open-in>None</open-in>
  </site>
  <site url="ehr.example.org:8443/legacy">
    <compat-mode>IE7Enterprise</compat-mode>
    <open-in allow-redirect="true">IE11</open-in>
  </site>
  <site url="intranet.example.org/new"><open-in>MSEdge</open-in></site>
</site-list>"#;

    #[test]
    fn reads_version_2() {
        let list = parse(V2).unwrap();
        assert_eq!((list.version, list.legacy, list.sites.len()), (Some(205), false, 4));
        assert_eq!(list.sites[0], Site { url: "www.contoso.com/travel".into(), compat_mode: "IE8Enterprise".into(), open_in: "IE11".into() });
        assert!(list.sites[2].ie_mode(), "an attribute on open-in doesn't hide its value");
        assert!(!list.sites[3].ie_mode());
    }

    #[test]
    fn the_most_specific_entry_wins() {
        let list = parse(V2).unwrap();
        let mode = |url: &str| lookup(&list, url).map(|s| s.ie_mode());
        assert_eq!(mode("https://www.contoso.com/travel/booking.aspx"), Some(true));
        assert_eq!(mode("https://www.contoso.com/TRAVEL"), Some(true), "paths match whatever their case");
        assert_eq!(mode("https://www.contoso.com/travelogue"), Some(false), "a longer word isn't the same path");
        assert_eq!(mode("https://portal.contoso.com/"), Some(false), "subdomains take the domain's entry");
        assert_eq!(mode("https://ehr.example.org:8443/legacy/chart"), Some(true));
        assert_eq!(mode("https://ehr.example.org/legacy/chart"), None, "a port in the entry has to match");
        assert_eq!(mode("https://www.fabrikam.com/"), None);
        assert_eq!(mode("notcontoso.com"), None, "a suffix isn't a parent domain");
    }

    #[test]
    fn reads_the_legacy_schema_and_refuses_anything_else() {
        let v1 = r#"<rules version="1"><emie><domain exclude="false">contoso.com<path exclude="false">/travel</path></domain><domain>fabrikam.com</domain></emie><docMode><domain docMode="5">contoso.com</domain></docMode></rules>"#;
        let list = parse(v1).unwrap();
        assert_eq!((list.version, list.legacy, list.sites.len()), (Some(1), true, 2));
        assert!(parse("<html><body>Sign in</body></html>").is_err(), "a proxy's sign-in page isn't a site list");
    }
}
