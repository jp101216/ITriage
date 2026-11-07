//! Site profiles: one TOML file per environment that says what "healthy"
//! means there (required services, apps, endpoints, peripherals, the time
//! server), which one-click fixes may run, and which knowledge-base article
//! goes with which finding.
//!
//! Lookup order, first match wins:
//! 1. **Managed** (machine-wide, admin-writable): `%ProgramData%\itriage\profile.toml`
//!    or `/etc/itriage/profile.toml`. Authoritative, so users can't override it.
//! 2. `ITRIAGE_PROFILE=<path>`, for testing. Ignored when a managed profile exists.
//! 3. **User**: `%APPDATA%\itriage\profile.toml` or `~/.config/itriage/profile.toml`.
//! 4. **Built-in**: no requirements, everything allowed.
//!
//! A managed profile that fails to parse fails *closed*: itriage drops to
//! read-only instead of silently running without the organisation's policy.

use crate::model::{Finding, KbLink, ModuleInfo, ModuleResult, Severity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub policy: Policy,
    pub time: TimeSettings,
    pub require: Requirements,
    pub kb: Vec<KbRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Anything that changes the machine: fixes, cleanup, installs.
    pub allow_changes: bool,
    /// The two install modules (OS & apps, drivers & firmware).
    pub allow_installs: bool,
    /// One-click fixes that may run. Absent means every built-in fix.
    /// Entries are fix ids (`restart-spooler`), or `start-service:<name>` to
    /// allow starting one specific service.
    pub fixes: Option<Vec<String>>,
    /// Which view the app opens in.
    pub start_in: Mode,
    /// `false` keeps the app in self-service mode (a kiosk for end users).
    pub technician_view: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_changes: true,
            allow_installs: true,
            fixes: None,
            start_in: Mode::Technician,
            technician_view: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Technician,
    SelfService,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeSettings {
    /// NTP server to measure the clock against. Default: the machine's own
    /// time source (a domain controller on domain-joined Windows).
    pub server: Option<String>,
    /// Expected time zone: a Windows zone name ("Eastern Standard Time") or an
    /// IANA one ("America/Detroit"). A mismatch is flagged.
    pub zone: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Requirements {
    pub service: Vec<ServiceReq>,
    pub app: Vec<AppReq>,
    pub endpoint: Vec<EndpointReq>,
    pub device: Vec<DeviceReq>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceReq {
    /// Windows service name or systemd unit.
    pub name: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppReq {
    /// Matched against installed programs' display names (Windows) or
    /// package names (Linux), case-insensitively.
    pub name: String,
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReq {
    pub label: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceReq {
    pub label: String,
    /// Case-insensitive substring of the device's name.
    #[serde(rename = "match")]
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbRule {
    /// Limit the rule to one module id; absent matches any module.
    #[serde(default)]
    pub module: Option<String>,
    /// Case-insensitive substring of the finding's label, value or detail.
    #[serde(rename = "match")]
    pub pattern: String,
    pub title: String,
    pub url: String,
}

/// What the UI needs to know about the active profile.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileStatus {
    /// "managed", "env", "user" or "built-in".
    pub source: &'static str,
    pub path: Option<String>,
    pub error: Option<String>,
    pub name: String,
    pub description: String,
    pub policy: Policy,
    pub requirements: usize,
    pub kb_rules: usize,
}

pub struct Loaded {
    pub profile: Profile,
    pub status: ProfileStatus,
}

/// Find and load the active profile (see the module docs for the order).
pub fn load() -> Loaded {
    let managed = crate::paths::managed_dir().map(|d| d.join("profile.toml"));
    if let Some(path) = managed.filter(|p| p.is_file()) {
        return match Profile::from_path(&path) {
            Ok(p) => loaded(p, "managed", Some(path), None),
            Err(e) => loaded(
                Profile::fail_closed(),
                "managed",
                Some(path),
                Some(format!("{e} Running read-only until the managed profile is fixed.")),
            ),
        };
    }
    if let Some(path) = std::env::var_os("ITRIAGE_PROFILE").map(PathBuf::from) {
        return match Profile::from_path(&path) {
            Ok(p) => loaded(p, "env", Some(path), None),
            Err(e) => loaded(Profile::default(), "built-in", Some(path), Some(e)),
        };
    }
    let user = crate::paths::config_dir().map(|d| d.join("profile.toml"));
    if let Some(path) = user.filter(|p| p.is_file()) {
        return match Profile::from_path(&path) {
            Ok(p) => loaded(p, "user", Some(path), None),
            Err(e) => loaded(Profile::default(), "built-in", Some(path), Some(e)),
        };
    }
    loaded(Profile::default(), "built-in", None, None)
}

fn loaded(profile: Profile, source: &'static str, path: Option<PathBuf>, error: Option<String>) -> Loaded {
    let status = ProfileStatus {
        source,
        path: path.map(|p| p.display().to_string()),
        error,
        name: if profile.name.is_empty() { "Default".into() } else { profile.name.clone() },
        description: profile.description.clone(),
        policy: profile.policy.clone(),
        requirements: profile.requirement_count(),
        kb_rules: profile.kb.len(),
    };
    Loaded { profile, status }
}

impl Profile {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Can't read profile {}: {e}.", path.display()))?;
        Self::from_toml(&text).map_err(|e| format!("Profile {} is invalid: {e}", path.display()))
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.to_string().trim().to_string())
    }

    /// What a broken managed profile turns into: read-only, no fixes.
    pub fn fail_closed() -> Self {
        Profile {
            name: "Locked (managed profile error)".into(),
            policy: Policy {
                allow_changes: false,
                allow_installs: false,
                fixes: Some(Vec::new()),
                ..Policy::default()
            },
            ..Profile::default()
        }
    }

    /// The built-in default, for contexts that weren't given a profile.
    pub fn builtin() -> &'static Profile {
        static DEFAULT: OnceLock<Profile> = OnceLock::new();
        DEFAULT.get_or_init(Profile::default)
    }

    pub fn requirement_count(&self) -> usize {
        let r = &self.require;
        r.service.len() + r.app.len() + r.endpoint.len() + r.device.len()
    }

    /// Why the policy blocks a module, if it does.
    pub fn block_reason(&self, info: &ModuleInfo) -> Option<String> {
        if !info.mutating {
            return None;
        }
        if !self.policy.allow_changes {
            return Some("Blocked by site policy: this profile is read-only.".into());
        }
        if info.id.starts_with("update.") && !self.policy.allow_installs {
            return Some("Blocked by site policy: updates are deployed centrally here.".into());
        }
        None
    }

    /// May this fix run? `start-service` allows any service;
    /// `start-service:Spooler` allows only that one.
    pub fn fix_allowed(&self, id: &str, target: Option<&str>) -> bool {
        if !self.policy.allow_changes {
            return false;
        }
        let Some(list) = &self.policy.fixes else {
            return true;
        };
        list.iter().map(|e| e.trim()).any(|entry| match entry.split_once(':') {
            None => entry.eq_ignore_ascii_case(id),
            Some((eid, etarget)) => {
                eid.eq_ignore_ascii_case(id) && target.is_some_and(|t| t.eq_ignore_ascii_case(etarget))
            }
        })
    }

    /// The KB article for a finding, if a rule matches.
    pub fn kb_for(&self, module_id: &str, f: &Finding) -> Option<KbLink> {
        self.kb
            .iter()
            .find(|r| {
                r.module.as_deref().is_none_or(|m| m.eq_ignore_ascii_case(module_id))
                    && (contains_ci(&f.label, &r.pattern)
                        || contains_ci(&f.value, &r.pattern)
                        || f.detail.as_deref().is_some_and(|d| contains_ci(d, &r.pattern)))
            })
            .map(|r| KbLink {
                title: r.title.clone(),
                url: r.url.clone(),
            })
    }

    /// Apply the profile to a finished result: drop fixes the policy doesn't
    /// allow, and link KB articles to findings that need attention.
    pub fn annotate(&self, result: &mut ModuleResult) {
        for f in &mut result.findings {
            if f.action
                .as_ref()
                .is_some_and(|a| !self.fix_allowed(&a.id, a.target.as_deref()))
            {
                f.action = None;
            }
            if f.kb.is_none() && f.severity.rank() >= Severity::Warning.rank() {
                f.kb = self.kb_for(&result.module_id, f);
            }
        }
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    !needle.is_empty() && haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, FixRef};

    const EXAMPLE: &str = r#"
        name = "Clinical workstation (example)"
        description = "Shared nursing-unit PCs"

        [policy]
        allow_installs = false
        fixes = ["restart-spooler", "clear-print-queue", "start-service:W32Time"]
        start_in = "self-service"

        [time]
        server = "dc01.example.org"

        [[require.service]]
        name = "Spooler"
        label = "Print Spooler"

        [[require.app]]
        name = "Citrix Workspace"
        min_version = "24.2"

        [[require.endpoint]]
        label = "EHR gateway"
        host = "ehr-gateway.example.org"
        port = 443

        [[require.device]]
        label = "Badge reader"
        match = "pcProx"

        [[kb]]
        module = "desk.printers"
        match = "stuck"
        title = "Clear a stuck print queue"
        url = "https://kb.example.org/print-queue"
    "#;

    fn info(id: &str, mutating: bool) -> ModuleInfo {
        let i = ModuleInfo::new(id, "t", Category::System, "d");
        if mutating { i.mutating() } else { i }
    }

    #[test]
    fn parses_a_full_profile() {
        let p = Profile::from_toml(EXAMPLE).unwrap();
        assert_eq!(p.name, "Clinical workstation (example)");
        assert!(p.policy.allow_changes, "unspecified fields keep their defaults");
        assert!(!p.policy.allow_installs);
        assert_eq!(p.policy.start_in, Mode::SelfService);
        assert_eq!(p.time.server.as_deref(), Some("dc01.example.org"));
        assert_eq!(p.requirement_count(), 4);
        assert_eq!(p.require.app[0].min_version.as_deref(), Some("24.2"));
        assert_eq!(p.require.device[0].pattern, "pcProx");
        assert_eq!(p.kb.len(), 1);
    }

    #[test]
    fn empty_profile_allows_everything() {
        let p = Profile::from_toml("").unwrap();
        assert!(p.fix_allowed("restart-spooler", None));
        assert!(p.fix_allowed("start-service", Some("Anything")));
        assert_eq!(p.block_reason(&info("update.apply", true)), None);
    }

    #[test]
    fn fix_allowlist_semantics() {
        let p = Profile::from_toml(EXAMPLE).unwrap();
        assert!(p.fix_allowed("restart-spooler", None));
        assert!(p.fix_allowed("start-service", Some("w32time")), "case-insensitive target");
        assert!(!p.fix_allowed("start-service", Some("Spooler")), "only the listed service");
        assert!(!p.fix_allowed("gpupdate", None));
    }

    #[test]
    fn policy_blocks_modules() {
        let p = Profile::from_toml(EXAMPLE).unwrap();
        assert!(p.block_reason(&info("update.apply", true)).is_some());
        assert!(p.block_reason(&info("fix.temp", true)).is_none());
        assert!(p.block_reason(&info("system.disk", false)).is_none());
        let closed = Profile::fail_closed();
        assert!(closed.block_reason(&info("fix.temp", true)).is_some());
        assert!(!closed.fix_allowed("restart-spooler", None));
    }

    #[test]
    fn annotate_strips_disallowed_fixes_and_links_kb() {
        let p = Profile::from_toml(EXAMPLE).unwrap();
        let fix = |id: &str| FixRef { id: id.into(), label: "x".into(), target: None, requires_admin: false };
        let mut r = ModuleResult {
            module_id: "desk.printers".into(),
            title: "Printers".into(),
            category: Category::Workstation,
            findings: vec![
                Finding::warn("Ward 4 printer", "3 jobs stuck").with_action(fix("clear-print-queue")),
                Finding::warn("Label printer", "offline").with_action(fix("gpupdate")),
                Finding::ok("Spooler", "running · nothing stuck"),
            ],
            summary: String::new(),
            error: None,
            duration_ms: 0,
        };
        p.annotate(&mut r);
        assert!(r.findings[0].action.is_some());
        assert!(r.findings[1].action.is_none(), "gpupdate isn't on the allowlist");
        assert_eq!(r.findings[0].kb.as_ref().unwrap().url, "https://kb.example.org/print-queue");
        assert!(r.findings[2].kb.is_none(), "OK findings don't get KB links");
    }

    #[test]
    fn rejects_bad_toml_with_a_readable_error() {
        let err = Profile::from_toml("[policy]\nallow_changes = \"maybe\"").unwrap_err();
        assert!(err.contains("allow_changes") || err.contains("bool"), "{err}");
    }
}
