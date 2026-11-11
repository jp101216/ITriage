//! A local, reviewable handoff. Only evidence already present in a report is
//! included; this module never follows a report-supplied path to collect files.
use crate::Report;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
    terms: Vec<(Regex, String)>,
}
impl Redactor {
    fn new(report: &Report, options: &Options) -> Result<Self, String> {
        if options.custom_terms.len() > 100 || options.custom_terms.iter().any(|s| s.len() > 512) {
            return Err("Use at most 100 custom privacy terms of 512 bytes each.".into());
        }
        let mut values: BTreeMap<String, String> = BTreeMap::new();
        if options.redact_identifiers {
            values.insert(report.host.hostname.clone(), "host".into());
            if let Some(baseline) = &report.baseline {
                values.insert(baseline.baseline_host.clone(), "host".into());
                values.insert(baseline.current_host.clone(), "host".into());
            }
            for m in &report.results {
                for f in &m.findings {
                    let label = f.label.to_ascii_lowercase();
                    if [
                        "serial",
                        "signed-in user",
                        "current user",
                        "user identity",
                        "ssid",
                        "bssid",
                        "thumbprint",
                    ]
                    .iter()
                    .any(|k| label.contains(k))
                        && f.value.len() >= 3
                    {
                        values.insert(f.value.clone(), "identifier".into());
                    }
                }
            }
            let serialized = json(report)?;
            for (pattern, kind) in [
                (r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "account"),
                (r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", "address"),
                (r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:]{0,39}", "address"),
                (r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", "network"),
            ] {
                let re = Regex::new(pattern).map_err(|e| e.to_string())?;
                for found in re.find_iter(&serialized) {
                    if kind != "address" || found.as_str().parse::<std::net::IpAddr>().is_ok() {
                        values.insert(found.as_str().into(), kind.into());
                    }
                }
            }
            // Work on decoded strings for Windows accounts and home paths.
            fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
                match value {
                    serde_json::Value::String(s) => out.push(s.clone()),
                    serde_json::Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
                    serde_json::Value::Object(o) => o.values().for_each(|v| strings(v, out)),
                    _ => (),
                }
            }
            let mut texts = Vec::new();
            strings(&serde_json::to_value(report).map_err(|e| e.to_string())?, &mut texts);
            for (pattern, group) in [
                (r"(?i)\b[A-Z0-9_.-]{2,}\\[A-Z0-9_.$-]+", 0),
                (r"(?i)(?:C:\\Users\\|/home/)([^\\/\s]+)", 1),
            ] {
                let re = Regex::new(pattern).map_err(|e| e.to_string())?;
                for text in &texts {
                    for captures in re.captures_iter(text) {
                        if let Some(v) = captures.get(group) {
                            values.insert(v.as_str().into(), "account".into());
                        }
                    }
                }
            }
        }
        for term in options.custom_terms.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            values.insert(term.into(), "custom".into());
        }
        let mut values = values.into_iter().filter(|(s, _)| !s.is_empty()).collect::<Vec<_>>();
        if values.len() > 2000 {
            return Err("More than 2000 distinct privacy terms were found. Export a smaller case or omit logs.".into());
        }
        values.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        // One replacement pass: pseudonyms can never be rewritten by
        // a later dictionary entry. Boundaries avoid replacing "PC" in TCP.
        let mut counters: BTreeMap<String, usize> = BTreeMap::new();
        let mut terms = Vec::new();
        for (term, kind) in values {
            let count = counters.entry(kind.clone()).or_default();
            *count += 1;
            let prefix = if term.chars().next().is_some_and(char::is_alphanumeric) {
                r"\b"
            } else {
                ""
            };
            let suffix = if term.chars().last().is_some_and(char::is_alphanumeric) {
                r"\b"
            } else {
                ""
            };
            let re = Regex::new(&format!("(?i){prefix}{}{suffix}", regex::escape(&term))).map_err(|e| e.to_string())?;
            terms.push((re, format!("[{kind}-{}]", *count)));
        }
        Ok(Self { terms })
    }
    fn text(&self, text: &str) -> String {
        let mut matches = self
            .terms
            .iter()
            .flat_map(|(re, replacement)| re.find_iter(text).map(move |m| (m.start(), m.end(), replacement)))
            .collect::<Vec<_>>();
        matches.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        let mut out = String::new();
        let mut end = 0;
        for (start, stop, replacement) in matches {
            if start >= end {
                out.push_str(&text[end..start]);
                out.push_str(replacement);
                end = stop;
            }
        }
        out.push_str(&text[end..]);
        out
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
        let mut file = std::fs::File::create_new(path).map_err(|e| format!("Can't create {}: {e}", path.display()))?;
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
