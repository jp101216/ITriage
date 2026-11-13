//! A local, reviewable handoff. Only evidence already present in a report is
//! included; this module never follows a report-supplied path to collect files.
use crate::Report;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_BYTES: usize = 20 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    pub include_logs: bool,
    pub redact_identifiers: bool,
    pub custom_terms: Vec<String>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            include_logs: false,
            redact_identifiers: true,
            custom_terms: Vec::new(),
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub name: String,
    pub bytes: usize,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Preview {
    pub files: Vec<Entry>,
    pub bytes: usize,
    pub text: String,
    pub redacted: bool,
    pub note: String,
    /// The exact text files to be archived, so the technician can inspect
    /// every included field, including optional logs, before exporting.
    pub contents: BTreeMap<String, String>,
}
pub struct Prepared {
    pub preview: Preview,
    files: Vec<(String, Vec<u8>)>,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|e| e.to_string())
}

/// Replace values consistently across every representation. The dictionary
/// itself is deliberately never written to the bundle.
struct Redactor {
    /// Every term in one pattern, so each string is read once however many
    /// terms there are. `None` when there is nothing to replace.
    pattern: Option<Regex>,
    /// Lower-cased term → its pseudonym.
    pseudonyms: HashMap<String, String>,
}

/// Accounts that name nobody.
const GENERIC_ACCOUNTS: &[&str] = &[
    "administrator", "admin", "user", "users", "guest", "system", "root", "public", "default", "defaultaccount", "default user",
    "all users", "local service", "network service", "localsystem", "nobody",
];
/// What stands before a backslash in something that isn't DOMAIN\user:
/// built-in authorities, registry hives.
const NOT_A_DOMAIN: &[&str] = &[
    "authority", "builtin", "service", "manager", "host", "workgroup", "hklm", "hkcu", "hku", "hkcr", "hkey_local_machine",
    "hkey_current_user", "hkey_users", "hkey_classes_root", "software", "system", "microsoft", "windows",
];
/// Public resolvers a check names on purpose. Hiding them hides what was tested.
const WELL_KNOWN_ADDRESSES: &[&str] = &["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"];
/// Checks whose dotted numbers are versions ("24.2.0.187"), never addresses.
fn reports_versions(module_id: &str) -> bool {
    module_id.starts_with("update.")
        || matches!(
            module_id,
            "site.apps" | "system.changes" | "system.info" | "system.startup" | "system.storage" | "sec.posture" | "system.reliability" | "desk.devices"
        )
}

/// What an address is, without saying which: a pseudonym that keeps
/// "private", "public" or "link-local" keeps the diagnosis readable (a
/// 169.254 address still says DHCP failed). `None` for addresses that
/// identify nobody.
fn address_kind(ip: std::net::IpAddr) -> Option<&'static str> {
    use std::net::IpAddr;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || WELL_KNOWN_ADDRESSES.contains(&ip.to_string().as_str()) {
        return None;
    }
    Some(match ip {
        // 255.x is a mask or a broadcast.
        IpAddr::V4(v4) if v4.octets()[0] == 255 => return None,
        IpAddr::V4(v4) if v4.is_link_local() => "link-local-address",
        IpAddr::V4(v4) if v4.is_private() || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])) => "private-address",
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => "link-local-address",
        IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0xfc00 => "private-address",
        _ => "public-address",
    })
}

/// Is the dotted number at `range` of `text` written like a version: after
/// "v" or "version", or as part of a longer run of digits and dots?
fn looks_like_a_version(text: &str, range: std::ops::Range<usize>) -> bool {
    let before = &text[..range.start];
    let after = &text[range.end..];
    let lead = before.to_ascii_lowercase();
    let lead = lead.trim_end_matches([' ', ':', '(']);
    before.ends_with(|c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        || ["version", "ver", "ver.", "build", "release", "driver", "firmware", "bios"].iter().any(|w| lead.ends_with(w))
        || after.starts_with(|c: char| c.is_ascii_alphabetic() || matches!(c, '-' | '+' | '~' | '_'))
        || (after.starts_with('.') && after[1..].starts_with(|c: char| c.is_ascii_digit()))
}

impl Redactor {
    fn new(report: &Report, options: &Options) -> Result<Self, String> {
        if options.custom_terms.len() > 100 || options.custom_terms.iter().any(|s| s.len() > 512) {
            return Err("Use at most 100 custom privacy terms of 512 bytes each.".into());
        }
        let mut values: BTreeMap<String, &'static str> = BTreeMap::new();
        if options.redact_identifiers {
            Self::known_identifiers(report, &mut values);
            Self::found_identifiers(report, &mut values)?;
        }
        for term in options.custom_terms.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            values.insert(term.into(), "custom");
        }
        // One pseudonym for a term however it is capitalised.
        let mut terms: Vec<(String, &'static str)> = Vec::new();
        for (term, kind) in values {
            if !term.is_empty() && !terms.iter().any(|(t, _)| t.eq_ignore_ascii_case(&term)) {
                terms.push((term, kind));
            }
        }
        if terms.len() > 2000 {
            return Err("More than 2000 distinct privacy terms were found. Export a smaller case or omit logs.".into());
        }
        // Longest first: where two terms could match at one place, the
        // longer one wins ("CORP-PC-07" before "CORP"). The pattern is read
        // once per string, and a pseudonym is never looked at again, so one
        // term can't rewrite another's replacement.
        terms.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        let mut counters: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut pseudonyms = HashMap::new();
        let mut alternatives = Vec::with_capacity(terms.len());
        for (term, kind) in &terms {
            let count = counters.entry(kind).or_default();
            *count += 1;
            pseudonyms.insert(term.to_lowercase(), format!("[{kind}-{count}]"));
            // Boundaries avoid replacing "PC" in TCP.
            let prefix = if term.chars().next().is_some_and(char::is_alphanumeric) { r"\b" } else { "" };
            let suffix = if term.chars().last().is_some_and(char::is_alphanumeric) { r"\b" } else { "" };
            alternatives.push(format!("{prefix}{}{suffix}", regex::escape(term)));
        }
        let pattern = if alternatives.is_empty() {
            None
        } else {
            Some(
                regex::RegexBuilder::new(&format!("(?i)(?:{})", alternatives.join("|")))
                    .size_limit(256 << 20)
                    .dfa_size_limit(64 << 20)
                    .build()
                    .map_err(|e| format!("The privacy terms couldn't be prepared: {e}"))?,
            )
        };
        Ok(Self { pattern, pseudonyms })
    }

    /// Identifiers the checks report under a known name.
    fn known_identifiers(report: &Report, values: &mut BTreeMap<String, &'static str>) {
        let mut add = |text: &str, kind: &'static str| {
            let text = text.trim();
            if text.chars().count() >= 2 {
                values.insert(text.to_string(), kind);
            }
        };
        // DOMAIN\user, user@domain or a bare name: the person, and the domain.
        let account = |text: &str, add: &mut dyn FnMut(&str, &'static str)| {
            let text = text.trim();
            if text.is_empty() || text.contains(' ') && !text.contains('\\') {
                return;
            }
            let (domain, user) = text.rsplit_once('\\').unwrap_or(("", text));
            if !GENERIC_ACCOUNTS.contains(&user.to_ascii_lowercase().as_str()) && user.chars().count() >= 3 {
                add(user, "account");
            }
            let last = domain.rsplit(' ').next().unwrap_or(domain);
            if domain.chars().count() >= 3 && !NOT_A_DOMAIN.contains(&last.to_ascii_lowercase().as_str()) {
                add(domain, "domain");
            }
        };
        add(&report.host.hostname, "host");
        if let Some(baseline) = &report.baseline {
            add(&baseline.baseline_host, "host");
            add(&baseline.current_host, "host");
        }
        for m in &report.results {
            for f in &m.findings {
                let label = f.label.to_ascii_lowercase();
                let value = f.value.trim();
                let one_word = !value.is_empty() && !value.contains(char::is_whitespace);
                if label.contains("serial") {
                    // "not reported by the firmware" isn't a serial number.
                    if one_word && value.len() >= 3 && value != "REDACTED" {
                        add(value, "serial");
                    }
                } else if ["signed-in user", "current user", "user identity"].iter().any(|k| label.contains(k)) {
                    account(value, &mut add);
                } else if m.module_id == "desk.account" && label == "account" {
                    account(value.split(" · ").next().unwrap_or(value), &mut add);
                } else if label.contains("bssid") || label.contains("thumbprint") {
                    if value.len() >= 3 {
                        add(value, "identifier");
                    }
                } else if label.contains("ssid") || (m.module_id == "desk.wifi" && label == "network") {
                    // The Wi-Fi network's name, unless Windows withheld it.
                    if !value.starts_with("name hidden") {
                        add(value, "network");
                    }
                } else if m.module_id == "desk.domain" {
                    match label.as_str() {
                        "domain" if !value.starts_with("not joined") => add(value, "domain"),
                        "domain" => {
                            if let Some(workgroup) = value.split("workgroup ").nth(1).filter(|w| !w.eq_ignore_ascii_case("WORKGROUP")) {
                                add(workgroup, "domain");
                            }
                        }
                        "signed in via" if one_word => add(value.trim_start_matches('\\'), "host"),
                        "ad site" => add(value, "site"),
                        _ => {}
                    }
                }
                // "SSID: Corp · ProfileName: Corp" in a Wi-Fi event's fields.
                if m.module_id == "net.wifi-auth" {
                    for part in f.detail.as_deref().unwrap_or_default().split(" · ") {
                        if let Some((key, name)) = part.split_once(": ") {
                            let key = key.to_ascii_lowercase();
                            if (key.contains("ssid") || key.contains("profile")) && !key.contains("bssid") {
                                add(name, "network");
                            }
                        }
                    }
                }
            }
        }
        if let Some(recording) = &report.recording {
            for s in &recording.samples {
                // "Corp · signal 72% · AP aa:bb:…": the name comes first.
                if let Some(name) = s.wifi.as_deref().and_then(|w| w.split(" · ").next()) {
                    if !matches!(name, "not connected" | "network name hidden" | "no active Wi-Fi listed") && !name.starts_with('*') {
                        add(name, "network");
                    }
                }
            }
        }
    }

    /// Identifiers recognised by their shape, wherever they are.
    fn found_identifiers(report: &Report, values: &mut BTreeMap<String, &'static str>) -> Result<(), String> {
        // Every string in the report, with the check it belongs to.
        fn strings<'a>(value: &'a serde_json::Value, module: &'a str, out: &mut Vec<(&'a str, &'a str)>) {
            match value {
                serde_json::Value::String(s) => out.push((module, s)),
                serde_json::Value::Array(a) => a.iter().for_each(|v| strings(v, module, out)),
                serde_json::Value::Object(o) => {
                    let module = o.get("module_id").and_then(|m| m.as_str()).unwrap_or(module);
                    o.values().for_each(|v| strings(v, module, out));
                }
                _ => (),
            }
        }
        let whole = serde_json::to_value(report).map_err(|e| e.to_string())?;
        let mut texts = Vec::new();
        strings(&whole, "", &mut texts);
        let compile = |pattern: &str| Regex::new(pattern).map_err(|e| e.to_string());
        let email = compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")?;
        let ipv4 = compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")?;
        let ipv6 = compile(r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:]{0,39}")?;
        let mac = compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")?;
        let windows_account = compile(r"(?i)[A-Z0-9_.\-]{2,}\\[A-Z0-9_.$\-]+")?;
        // C:\Users\name, and the forms policy events write it in:
        // %OSDRIVE%\USERS\NAME (AppLocker), \Device\HarddiskVolume3\Users\name (App Control).
        let home = compile(r#"(?i)(?:(?:[A-Z]:|%OSDRIVE%|\\Device\\HarddiskVolume[0-9]+)\\Users\\|/home/)([^\\/\s:"']+)"#)?;
        // An account's SID (AppLocker names the user that way).
        let sid = compile(r"\bS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\b")?;
        for (module, text) in texts {
            for found in email.find_iter(text) {
                values.insert(found.as_str().into(), "account");
            }
            for found in mac.find_iter(text) {
                values.insert(found.as_str().into(), "network");
            }
            for found in ipv6.find_iter(text) {
                if let Some(kind) = found.as_str().parse::<std::net::Ipv6Addr>().ok().and_then(|ip| address_kind(ip.into())) {
                    values.insert(found.as_str().into(), kind);
                }
            }
            if !reports_versions(module) {
                for found in ipv4.find_iter(text) {
                    if looks_like_a_version(text, found.range()) {
                        continue;
                    }
                    if let Some(kind) = found.as_str().parse::<std::net::Ipv4Addr>().ok().and_then(|ip| address_kind(ip.into())) {
                        values.insert(found.as_str().into(), kind);
                    }
                }
            }
            for found in windows_account.find_iter(text) {
                // Part of a path or a registry key, not DOMAIN\user.
                let before = text[..found.start()].chars().next_back();
                let after = text[found.end()..].chars().next();
                if before.is_some_and(|c| c.is_alphanumeric() || matches!(c, '\\' | '/' | ':')) || after == Some('\\') {
                    continue;
                }
                let (domain, user) = found.as_str().split_once('\\').unwrap_or(("", found.as_str()));
                let lower = user.to_ascii_lowercase();
                if NOT_A_DOMAIN.contains(&domain.to_ascii_lowercase().as_str())
                    || [".exe", ".dll", ".sys", ".inf", ".log", ".msi", ".ps1", ".bat", ".cmd", ".txt", ".ini", ".dat"].iter().any(|e| lower.ends_with(e))
                {
                    continue;
                }
                if user.chars().count() >= 3 && !GENERIC_ACCOUNTS.contains(&lower.as_str()) {
                    values.insert(user.into(), "account");
                }
                if domain.chars().count() >= 3 {
                    values.entry(domain.into()).or_insert("domain");
                }
            }
            for found in sid.find_iter(text) {
                values.insert(found.as_str().into(), "account");
            }
            for captures in home.captures_iter(text) {
                if let Some(name) = captures.get(1).map(|m| m.as_str()) {
                    if name.chars().count() >= 3 && !GENERIC_ACCOUNTS.contains(&name.to_ascii_lowercase().as_str()) {
                        values.insert(name.into(), "account");
                    }
                }
            }
        }
        Ok(())
    }

    fn text(&self, text: &str) -> String {
        let Some(pattern) = &self.pattern else {
            return text.to_string();
        };
        pattern
            .replace_all(text, |found: &regex::Captures| {
                let term = found[0].to_lowercase();
                self.pseudonyms
                    .get(&term)
                    // Case folding the pattern knows and `to_lowercase` doesn't.
                    .or_else(|| self.pseudonyms.iter().find(|(known, _)| known.to_uppercase() == found[0].to_uppercase()).map(|(_, p)| p))
                    .cloned()
                    .unwrap_or_else(|| "[removed]".to_string())
            })
            .into_owned()
    }
    fn value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => *s = self.text(s),
            serde_json::Value::Array(a) => a.iter_mut().for_each(|v| self.value(v)),
            serde_json::Value::Object(o) => o
                .iter_mut()
                .filter(|(k, _)| {
                    !matches!(
                        k.as_str(),
                        "category"
                            | "severity"
                            | "module_id"
                            | "module"
                            | "platform"
                            | "unit"
                            | "tool_version"
                            | "generated"
                            | "evidence_updated"
                            | "baseline_generated"
                            | "current_generated"
                            | "started"
                            | "at"
                    )
                })
                .for_each(|(_, v)| self.value(v)),
            _ => (),
        }
    }
}

pub fn prepare(report: &Report, options: &Options) -> Result<Prepared, String> {
    // Check the size before cloning or building a replacement dictionary.
    if serde_json::to_vec(report).map_err(|e| e.to_string())?.len() > MAX_BYTES {
        return Err("The report exceeds the 20 MiB case limit.".into());
    }
    let mut report = report.clone();
    if !options.include_logs {
        for m in &mut report.results {
            m.log.clear();
        }
    }
    let redactor = Redactor::new(&report, options)?;
    let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    redactor.value(&mut value);
    let report: Report = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let mut texts = BTreeMap::new();
    texts.insert("report.json".into(), json(&report)?);
    let text = crate::report::render_text(&report, None, options.include_logs);
    texts.insert("report.txt".into(), text.clone());
    texts.insert(
        "versions.txt".into(),
        format!(
            "ITriage report producer: {}\nBundle exporter: {}\nReport schema: {}\nPlatform: {}\nOS: {}\n",
            report.tool_version,
            env!("CARGO_PKG_VERSION"),
            report.schema,
            report.host.platform,
            report.host.os
        ),
    );
    texts.insert("timeline.json".into(), json(&crate::investigate::timeline::rows(&report))?);
    if let Some(recording) = &report.recording {
        texts.insert("recording.csv".into(), crate::investigate::recording::csv(recording));
    }
    if let Some(baseline) = &report.baseline {
        texts.insert("baseline.json".into(), json(baseline)?);
    }
    if let Some(runbook) = &report.runbook {
        texts.insert("runbook.json".into(), json(runbook)?);
    }
    if options.include_logs {
        for (i, m) in report.results.iter().enumerate().filter(|(_, m)| !m.log.is_empty()) {
            let id: String = m
                .module_id
                .chars()
                .take(80)
                .map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' })
                .collect();
            texts.insert(format!("logs/{i:03}-{id}.txt"), m.log.join("\n"));
        }
    }
    let manifest = texts
        .iter()
        .map(|(name, text)| Entry {
            name: name.clone(),
            bytes: text.len(),
            sha256: hash(text.as_bytes()),
        })
        .collect::<Vec<_>>();
    texts.insert("manifest.json".into(), json(&manifest)?);
    let sums = texts
        .iter()
        .map(|(name, text)| format!("{}  {name}\n", hash(text.as_bytes())))
        .collect::<String>();
    texts.insert("SHA256SUMS.txt".into(), sums);
    let files = texts
        .iter()
        .map(|(name, text)| Entry {
            name: name.clone(),
            bytes: text.len(),
            sha256: hash(text.as_bytes()),
        })
        .collect::<Vec<_>>();
    let bytes = texts.values().map(String::len).sum();
    if bytes > MAX_BYTES || texts.len() > 512 {
        return Err("The case exceeds the 20 MiB / 512-file limit. Export fewer checks or omit logs.".into());
    }
    let preview = Preview { files, bytes, text, redacted: options.redact_identifiers, note: "Known identifiers are pseudonymized when selected. Review every included file for site-specific sensitive text; this is not a guarantee of anonymity. Only existing report evidence is included; unavailable logs are not collected retroactively.".into(), contents: texts.clone() };
    Ok(Prepared {
        preview,
        files: texts.into_iter().map(|(n, t)| (n, t.into_bytes())).collect(),
    })
}

impl Prepared {
    /// Stored ZIP with fixed filenames, CRC-32, UTF-8 names and deterministic
    /// timestamps. No imported archive or arbitrary source path is processed.
    pub fn zip(&self) -> Vec<u8> {
        fn u16to(out: &mut Vec<u8>, n: u16) {
            out.extend_from_slice(&n.to_le_bytes());
        }
        fn u32to(out: &mut Vec<u8>, n: u32) {
            out.extend_from_slice(&n.to_le_bytes());
        }
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, bytes) in &self.files {
            let offset = out.len() as u32;
            let crc = crc32fast::hash(bytes);
            let size = bytes.len() as u32;
            u32to(&mut out, 0x04034b50);
            for n in [20, 0x800, 0, 0, 33] {
                u16to(&mut out, n);
            }
            for n in [crc, size, size] {
                u32to(&mut out, n);
            }
            u16to(&mut out, name.len() as u16);
            u16to(&mut out, 0);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(bytes);
            u32to(&mut central, 0x02014b50);
            for n in [20, 20, 0x800, 0, 0, 33] {
                u16to(&mut central, n);
            }
            for n in [crc, size, size] {
                u32to(&mut central, n);
            }
            for n in [name.len() as u16, 0, 0, 0, 0] {
                u16to(&mut central, n);
            }
            u32to(&mut central, 0);
            u32to(&mut central, offset);
            central.extend_from_slice(name.as_bytes());
        }
        let offset = out.len() as u32;
        let size = central.len() as u32;
        out.extend_from_slice(&central);
        u32to(&mut out, 0x06054b50);
        for n in [0, 0, self.files.len() as u16, self.files.len() as u16] {
            u16to(&mut out, n);
        }
        u32to(&mut out, size);
        u32to(&mut out, offset);
        u16to(&mut out, 0);
        out
    }
    pub fn write_new(&self, path: &Path) -> Result<(), String> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|e| format!("Can't create {}: {e}", path.display()))?;
        if let Err(e) = file.write_all(&self.zip()).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(format!("Can't finish case: {e}"));
        }
        Ok(())
    }
    pub fn save(&self) -> Result<PathBuf, String> {
        let dir = crate::paths::data_dir().ok_or("No local data folder is available.")?.join("cases");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let stamp = crate::investigate::recording::now_ms();
        for n in 0..100 {
            let path = dir.join(format!("ITriage-case-{stamp}-{n}.zip"));
            if path.exists() {
                continue;
            }
            self.write_new(&path)?;
            return Ok(path);
        }
        Err("Could not allocate a case filename.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_export_cannot_overwrite_an_existing_file_and_is_private_on_unix() {
        let path = std::env::temp_dir().join(format!(
            "itriage-private-case-{}-{}.zip",
            std::process::id(),
            crate::investigate::recording::now_ms()
        ));
        let prepared = prepare(&Report::new(crate::host_context(), None, vec![], false), &Options::default()).unwrap();
        prepared.write_new(&path).unwrap();
        assert!(prepared.write_new(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        }
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn privacy_terms_cannot_corrupt_structural_enums_or_leave_baseline_hostnames() {
        let mut host = crate::host_context();
        host.hostname = "critical".into();
        let mut m = crate::ModuleResult::failed(
            &crate::ModuleInfo::new("system.info", "System", crate::Category::Network, ""),
            "critical on critical",
        );
        m.findings = vec![crate::Finding::crit("Host", "critical")];
        let mut r = Report::new(host, None, vec![m], false);
        r.baseline = Some(crate::investigate::baseline::Comparison {
            baseline_host: "PRIVATE-BASELINE".into(),
            current_host: "critical".into(),
            baseline_generated: r.generated.clone(),
            current_generated: r.generated.clone(),
            role: None,
            differences: vec![],
            gaps: vec![],
        });
        let case = prepare(&r, &Options::default()).unwrap();
        let exported: Report = serde_json::from_str(&case.preview.contents["report.json"]).unwrap();
        assert_eq!(exported.results[0].findings[0].severity, crate::Severity::Critical);
        assert_eq!(exported.results[0].category, crate::Category::Network);
        assert!(!case.preview.contents["baseline.json"].contains("PRIVATE-BASELINE"));
        assert_eq!(exported.baseline.unwrap().current_host, exported.host.hostname);
    }
    #[test]
    fn identifiers_are_consistent_and_the_manifest_hashes_exported_bytes() {
        let mut host = crate::host_context();
        host.hostname = "PRIVATE-PC".into();
        let mut r = Report::new(host, None, vec![], false);
        r.ticket = Some("contact me@example.org via 10.20.30.40 on PRIVATE-PC".into());
        let prepared = prepare(&r, &Options::default()).unwrap();
        let all = prepared.preview.contents.values().cloned().collect::<Vec<_>>().join("\n");
        for private in ["PRIVATE-PC", "me@example.org", "10.20.30.40"] {
            assert!(!all.contains(private));
        }
        let parsed: serde_json::Value = serde_json::from_str(&prepared.preview.contents["report.json"]).unwrap();
        assert!(parsed["ticket"]
            .as_str()
            .unwrap()
            .contains(parsed["host"]["hostname"].as_str().unwrap()));
        let manifest: serde_json::Value = serde_json::from_str(&prepared.preview.contents["manifest.json"]).unwrap();
        for entry in manifest.as_array().unwrap() {
            let name = entry["name"].as_str().unwrap();
            assert_eq!(entry["sha256"], hash(prepared.preview.contents[name].as_bytes()));
        }
        assert_eq!(prepared.zip(), prepare(&r, &Options::default()).unwrap().zip());
    }
    /// A report with one check holding `findings`, on a PC called WS-FLINT-07.
    fn report_with(module: &str, findings: Vec<crate::Finding>) -> Report {
        let mut host = crate::host_context();
        host.hostname = "WS-FLINT-07".into();
        let mut m = crate::ModuleResult::failed(&crate::ModuleInfo::new(module, "Check", crate::Category::System, ""), "");
        m.error = None;
        m.findings = findings;
        Report::new(host, None, vec![m], false)
    }

    fn exported(report: &Report) -> String {
        prepare(report, &Options::default()).unwrap().preview.contents["report.txt"].clone()
    }

    #[test]
    fn policy_block_paths_and_sids_are_pseudonymized() {
        use crate::Finding;
        let r = report_with(
            "sec.blocks",
            vec![
                Finding::warn("AppLocker: EXE rules: no rule allows it · TOOL.EXE", "blocked once · last 1h ago")
                    .with_detail("Blocked: %OSDRIVE%\\USERS\\DSMITH\\DOWNLOADS\\TOOL.EXE · Account: S-1-5-21-1004336348-1177238915-682003330-1104"),
                Finding::warn("App Control: policy Ward PCs · plugin.dll", "blocked once · last 2h ago")
                    .with_detail("Blocked: \\Device\\HarddiskVolume3\\Users\\mjones\\AppData\\plugin.dll"),
            ],
        );
        let text = exported(&r);
        for private in ["DSMITH", "dsmith", "mjones", "1004336348"] {
            assert!(!text.contains(private), "{private} is still in:\n{text}");
        }
        assert!(text.contains("Ward PCs") && text.contains("plugin.dll"), "policy and file names stay readable");
    }

    #[test]
    fn network_names_accounts_and_domains_are_replaced_consistently() {
        use crate::Finding;
        let mut r = report_with(
            "desk.wifi",
            vec![
                Finding::ok("Network", "ContosoHealth-Staff").with_detail("Intel(R) Wi-Fi 6E AX211"),
                Finding::info("VPN", "tunnel up for CONTOSO\\jparker; profile in C:\\Users\\jparker\\AppData\\vpn.xml"),
            ],
        );
        let mut account = crate::ModuleResult::failed(&crate::ModuleInfo::new("desk.account", "Account", crate::Category::System, ""), "");
        account.error = None;
        account.findings = vec![
            Finding::info("Account", "CONTOSO\\jparker · domain account").with_detail("Checked on DC01.corp.contoso.example."),
            Finding::info("Services signing in as this account", "1: BackupSvc runs as jparker"),
        ];
        let mut domain = crate::ModuleResult::failed(&crate::ModuleInfo::new("desk.domain", "Domain", crate::Category::System, ""), "");
        domain.error = None;
        domain.findings = vec![Finding::ok("Domain", "corp.contoso.example"), Finding::ok("Signed in via", "\\\\DC01.corp.contoso.example"), Finding::info("AD site", "Flint-HQ")];
        r.results.push(account);
        r.results.push(domain);
        let text = exported(&r);
        for private in ["ContosoHealth-Staff", "jparker", "CONTOSO", "contoso", "Flint-HQ", "DC01", "WS-FLINT-07"] {
            assert!(!text.contains(private), "{private} is still in:\n{text}");
        }
        // The same person is the same pseudonym with and without the domain, and in a path.
        assert!(text.contains("tunnel up for [domain-2]\\[account-1]; profile in C:\\Users\\[account-1]\\AppData\\vpn.xml"), "{text}");
        assert!(text.contains("BackupSvc runs as [account-1]"), "{text}");
        assert!(text.contains("Network: [network-1]"), "{text}");
        assert!(text.contains("Intel(R) Wi-Fi 6E AX211"), "the adapter's model isn't an identifier");
    }

    #[test]
    fn paths_versions_and_well_known_addresses_stay_readable() {
        use crate::Finding;
        let mut r = report_with(
            "net.connectivity",
            vec![
                Finding::ok("Default route", "via 10.20.4.1 on Ethernet (from 10.20.4.57)"),
                Finding::ok("Outbound TCP (8.8.8.8:53)", "connected in 15 ms"),
                Finding::info("Public IP", "203.0.113.9"),
                Finding::warn("Interface Wi-Fi", "169.254.12.7/16 · mask 255.255.0.0 · loopback 127.0.0.1"),
                Finding::info("Driver", "C:\\Windows\\System32\\drivers\\netwtw14.sys version 23.60.1.2 (HKLM\\SOFTWARE\\Intel)"),
                Finding::info("Runs as", "NT AUTHORITY\\SYSTEM and BUILTIN\\Administrators"),
            ],
        );
        let mut apps = crate::ModuleResult::failed(&crate::ModuleInfo::new("site.apps", "Apps", crate::Category::System, ""), "");
        apps.error = None;
        apps.findings = vec![Finding::ok("Contoso Client", "24.2.0.187"), Finding::info("Serial number", "not reported by the firmware")];
        r.results.push(apps);
        let text = exported(&r);
        // Addresses keep what kind they are, and nothing else.
        assert!(text.contains("via [private-address-2] on Ethernet (from [private-address-1])"), "{text}");
        assert!(text.contains("Public IP: [public-address-1]"), "{text}");
        assert!(text.contains("[link-local-address-1]/16 · mask 255.255.0.0 · loopback 127.0.0.1"), "{text}");
        // What a check names on purpose, and what isn't an address at all.
        for kept in [
            "Outbound TCP (8.8.8.8:53)",
            "C:\\Windows\\System32\\drivers\\netwtw14.sys version 23.60.1.2 (HKLM\\SOFTWARE\\Intel)",
            "NT AUTHORITY\\SYSTEM and BUILTIN\\Administrators",
            "Contoso Client: 24.2.0.187",
            "Serial number: not reported by the firmware",
        ] {
            assert!(text.contains(kept), "{kept} was changed:\n{text}");
        }
        for private in ["10.20.4.1", "10.20.4.57", "203.0.113.9", "169.254.12.7"] {
            assert!(!text.contains(private), "{private}");
        }
    }

    #[test]
    fn a_large_case_is_read_once_however_many_terms_it_has() {
        use crate::Finding;
        // 400 different addresses and accounts, and 8,000 log lines naming them.
        let findings: Vec<Finding> = (0..400).map(|i| Finding::info(format!("Client {i}"), format!("10.{}.{}.7 as CORP\\user{i:04}", i / 200, i % 200))).collect();
        let mut r = report_with("net.connectivity", findings);
        r.results[0].log = (0..8_000).map(|i| format!("{} connected from 10.{}.{}.7 as CORP\\user{:04} on WS-FLINT-07", i, (i % 400) / 200, i % 200, i % 400)).collect();
        let started = std::time::Instant::now();
        let case = prepare(&r, &Options { include_logs: true, ..Options::default() }).unwrap();
        let took = started.elapsed();
        let log = &case.preview.contents["logs/000-net.connectivity.txt"];
        assert!(!log.contains("user0") && !log.contains("WS-FLINT-07") && !log.contains("10.1."), "{}", &log[..300]);
        assert!(log.lines().next().unwrap().starts_with("0 connected from [private-address-"));
        // Generous: this is about not taking minutes, and a debug build is slow.
        assert!(took < std::time::Duration::from_secs(20), "took {took:?}");
    }

    #[test]
    fn zip_names_never_come_from_a_report_path_and_logs_are_opt_in() {
        let info = crate::ModuleInfo::new("../../escape", "Test", crate::Category::System, "");
        let mut m = crate::ModuleResult::failed(&info, "fixture");
        m.log.push("private log".into());
        let r = Report::new(crate::host_context(), None, vec![m], false);
        assert!(!prepare(&r, &Options::default())
            .unwrap()
            .preview
            .contents
            .values()
            .any(|s| s.contains("private log")));
        let case = prepare(
            &r,
            &Options {
                include_logs: true,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(case.preview.files.iter().all(|e| !e.name.contains("/../")));
        assert!(case.preview.contents.values().any(|s| s.contains("private log")));
    }
}
