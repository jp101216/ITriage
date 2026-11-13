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
//!
//! A file in the managed place only counts as managed when administrators
//! alone can change it (see [`crate::trust`]). On Windows, standard users
//! can create files under `%ProgramData%`, so a `profile.toml` one of them
//! dropped there is ignored, with a warning, rather than obeyed.

use crate::model::{Finding, KbLink, ModuleInfo, ModuleResult, Severity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub name: String,
    /// Workstation role used to judge whether a working-PC baseline applies.
    pub role: String,
    pub description: String,
    pub policy: Policy,
    pub time: TimeSettings,
    pub network: NetworkSettings,
    pub thresholds: Thresholds,
    pub privacy: Privacy,
    pub updates: UpdateSettings,
    pub security: SecuritySettings,
    pub cleanup: CleanupSettings,
    pub history: HistorySettings,
    pub audit: AuditSettings,
    pub ui: UiSettings,
    pub require: Requirements,
    pub kb: Vec<KbRule>,
}

/// How the app looks. Cosmetic only: a technician's own pick (saved on
/// their computer) wins, and a name the app doesn't know is ignored rather
/// than treated as a broken profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSettings {
    /// The technician console's default theme: red, amber, phosphor, radar,
    /// cyber, holo, tactical, minimal or glass. Absent means red.
    pub theme: Option<String>,
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
    /// Start in remote-safe mode: anything that could drop a remote session
    /// (adapter restarts, DHCP renew, cache purges, policy refreshes) or
    /// restart the PC is locked. Technicians can still switch it off.
    pub remote_safe: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_changes: true,
            allow_installs: true,
            fixes: None,
            start_in: Mode::Technician,
            technician_view: true,
            remote_safe: false,
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

/// The public-IP lookup Invoke-NetTriage uses (api.ipify.org is its fallback).
pub const DEFAULT_EGRESS_URL: &str = "https://ifconfig.me/ip";

/// The network checks' built-in probes and timings (the NetTriage defaults).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSettings {
    /// The built-in public checks: the DNS name lookup, the outbound TCP probe
    /// and the public-IP lookup. Turn off on locked-down egress; the profile's
    /// own endpoints and an explicit `dns_probe` still run.
    pub public_probes: bool,
    /// Name resolved (and timed) by the DNS check.
    pub dns_probe: Option<String>,
    /// `host:port` for the outbound TCP probe.
    pub tcp_probe: Option<String>,
    /// URL that answers with this machine's public IP as plain text. Empty
    /// skips the lookup (NetTriage's `-SkipExternalIP`).
    pub egress_url: String,
    /// Ports the destination test tries when none are given.
    pub target_ports: Vec<u16>,
    /// Time budget for one TCP check, shared by every address a name resolves to.
    pub tcp_timeout_ms: u64,
    /// ICMP echoes per latency probe.
    pub ping_count: u32,
    /// Timeout for each echo.
    pub ping_timeout_ms: u64,
    /// Subnets a NAC system uses for its remediation VLAN
    /// (`["10.250.0.0/16"]`). A wired address inside one is critical.
    pub quarantine_subnets: Vec<String>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            public_probes: true,
            dns_probe: None,
            tcp_probe: None,
            egress_url: DEFAULT_EGRESS_URL.into(),
            target_ports: vec![443, 80, 445, 3389],
            tcp_timeout_ms: 1500,
            ping_count: 4,
            ping_timeout_ms: 1000,
            quarantine_subnets: Vec::new(),
        }
    }
}

impl NetworkSettings {
    /// The name to time, if any: an explicit one always runs; the public
    /// default only with public probes on.
    pub fn dns_probe_name(&self) -> Option<String> {
        self.dns_probe
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.public_probes.then(|| "www.microsoft.com".to_string()))
    }
    /// The public-IP lookup services, if the lookup runs at all.
    pub fn egress_urls(&self) -> Vec<String> {
        if self.public_probes {
            crate::net::egress_urls(&self.egress_url)
        } else {
            Vec::new()
        }
    }
    pub fn tcp_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.tcp_timeout_ms.clamp(100, 60_000))
    }
    pub fn ping_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.ping_timeout_ms.clamp(100, 60_000))
    }
    /// The outbound TCP probe, if any (same rule as the DNS probe).
    pub fn tcp_probe_target(&self) -> Option<(String, u16)> {
        let spec = self
            .tcp_probe
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.public_probes.then(|| "8.8.8.8:53".to_string()))?;
        let (host, port) = spec.trim().rsplit_once(':')?;
        Some((host.trim_matches(['[', ']']).to_string(), port.parse().ok()?))
    }
}

/// A warning and a critical level for one measurement.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Band {
    pub warn: f64,
    pub crit: f64,
}

impl Band {
    const fn new(warn: f64, crit: f64) -> Self {
        Self { warn, crit }
    }
    /// Grade a value where higher is worse (latency, load, loss).
    pub fn high(&self, value: f64) -> Severity {
        if value >= self.crit {
            Severity::Critical
        } else if value >= self.warn {
            Severity::Warning
        } else {
            Severity::Ok
        }
    }
    /// Grade a value where lower is worse (free space, signal).
    pub fn low(&self, value: f64) -> Severity {
        if value <= self.crit {
            Severity::Critical
        } else if value <= self.warn {
            Severity::Warning
        } else {
            Severity::Ok
        }
    }
}

/// Alert levels. The defaults are Invoke-NetTriage's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub uptime_days: Band,
    pub cpu_pct: Band,
    pub memory_pct: Band,
    /// Lower is worse.
    pub disk_free_pct: Band,
    pub disk_latency_ms: Band,
    /// Lower is worse.
    pub wifi_signal_pct: Band,
    pub gateway_rtt_ms: Band,
    /// DNS servers and destinations beyond the local network.
    pub network_rtt_ms: Band,
    pub dns_ms: Band,
    pub packet_loss_pct: Band,
    /// Days since the antivirus definitions were last updated.
    pub definitions_age_days: Band,
    /// Days until the signed-in user's password expires. Lower is worse.
    pub password_expiry_days: Band,
    /// Seconds from power-on to a usable desktop (or to sign-in on Linux).
    pub startup_seconds: Band,
    /// Seconds a sign-in spends loading the profile and applying Group Policy.
    pub logon_seconds: Band,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            uptime_days: Band::new(7.0, 14.0),
            cpu_pct: Band::new(75.0, 90.0),
            memory_pct: Band::new(80.0, 90.0),
            disk_free_pct: Band::new(15.0, 10.0),
            disk_latency_ms: Band::new(15.0, 30.0),
            wifi_signal_pct: Band::new(70.0, 50.0),
            gateway_rtt_ms: Band::new(20.0, 50.0),
            network_rtt_ms: Band::new(80.0, 150.0),
            dns_ms: Band::new(100.0, 300.0),
            packet_loss_pct: Band::new(1.0, 10.0),
            definitions_age_days: Band::new(3.0, 7.0),
            password_expiry_days: Band::new(14.0, 3.0),
            startup_seconds: Band::new(60.0, 120.0),
            logon_seconds: Band::new(60.0, 120.0),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Privacy {
    /// Replace the machine serial number with "REDACTED" in results.
    pub redact_serial: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateSettings {
    /// When Windows Update drivers install alongside the OEM tool.
    pub windows_update_drivers: DriverSource,
    /// Suspend BitLocker for one restart before the manufacturer's tool
    /// runs, so a BIOS update doesn't leave the PC asking for its recovery
    /// key. On unless the profile turns it off.
    pub suspend_bitlocker: bool,
    /// Tell the technician when a newer ITriage has been released. One
    /// request a day to GitHub; it downloads and installs nothing. Also off
    /// whenever `[network] public_probes` is off.
    pub notify: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self { windows_update_drivers: DriverSource::default(), suspend_bitlocker: true, notify: true }
    }
}

/// What the security posture check expects of this site's PCs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecuritySettings {
    /// Must the system drive be encrypted? Absent: a laptop without
    /// encryption is a warning and a desktop is only noted. `true` makes it
    /// critical everywhere; `false` only notes it.
    pub require_encryption: Option<bool>,
    /// `false` flags a signed-in user who is an administrator of the PC.
    pub user_may_be_admin: bool,
    /// Warn when a machine certificate's revocation list expires within
    /// this many hours (unless the CA publishes a new one first).
    pub crl_warn_hours: u32,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self { require_encryption: None, user_may_be_admin: true, crl_warn_hours: 24 }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriverSource {
    /// Only when there's no OEM tool, so the two don't keep replacing each
    /// other's drivers.
    #[default]
    Auto,
    /// Always, after the OEM tool (what Invoke-UpdateSystem does).
    Always,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CleanupSettings {
    /// Temp files and folders created or changed more recently than this are kept.
    pub temp_min_age_hours: u32,
}

impl Default for CleanupSettings {
    fn default() -> Self {
        Self { temp_min_age_hours: 24 }
    }
}

/// The audit trail. The local file is always written.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditSettings {
    /// Copy each audit line to the Windows Application event log or syslog,
    /// for WEF and SIEM collection. Only a managed profile can turn it off.
    pub event_log: bool,
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self { event_log: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HistorySettings {
    /// Saved runs kept in the history folder; 0 keeps them all.
    pub keep: usize,
}

impl Default for HistorySettings {
    fn default() -> Self {
        Self { keep: 100 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Requirements {
    pub service: Vec<ServiceReq>,
    pub app: Vec<AppReq>,
    pub endpoint: Vec<EndpointReq>,
    pub device: Vec<DeviceReq>,
    /// Explicit application health URLs; no URLs are probed by default.
    pub application: Vec<crate::investigate::applications::ApplicationProbe>,
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
    pub ui: UiSettings,
}

pub struct Loaded {
    pub profile: Profile,
    pub status: ProfileStatus,
}

/// Find and load the active profile (see the module docs for the order).
pub fn load() -> Loaded {
    let managed = crate::paths::managed_dir().map(|d| d.join("profile.toml"));
    load_from(managed.filter(|p| p.is_file()), crate::trust::profile)
}

/// `trusted` says whether the file in the managed place is really the
/// organisation's: one that only administrators can change. One a user put
/// there is ignored, with a warning. It doesn't get to set policy, and it
/// doesn't get to lock the app either, which a broken managed profile does.
fn load_from(managed: Option<PathBuf>, trusted: impl Fn(&Path) -> Result<(), String>) -> Loaded {
    let mut ignored = None;
    if let Some(path) = managed {
        match trusted(&path) {
            Ok(()) => {
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
            Err(why) => {
                ignored = Some(format!(
                    "The profile at {} was ignored: {why}. Only a profile that administrators alone can change counts as the organisation's.",
                    path.display()
                ));
            }
        }
    }
    let mut found = load_unmanaged();
    if found.status.error.is_none() {
        found.status.error = ignored;
    }
    found
}

fn load_unmanaged() -> Loaded {
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
        ui: profile.ui.clone(),
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
        r.service.len() + r.app.len() + r.endpoint.len() + r.device.len() + r.application.len()
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
            return !crate::actions::OPT_IN.iter().any(|o| o.eq_ignore_ascii_case(id));
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
    fn opt_in_fixes_need_naming() {
        let open = Profile::default();
        assert!(open.fix_allowed("restart-spooler", None), "no list: everything ordinary is allowed");
        assert!(!open.fix_allowed("keep-usb-awake", None), "but not an opt-in fix");
        assert!(open.fix_allowed("restore-usb-power", None), "putting things back isn't opt-in");
        let listed = Profile::from_toml("[policy]\nfixes = [\"Keep-USB-Awake\"]\n").unwrap();
        assert!(listed.fix_allowed("keep-usb-awake", None));
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
            log: Vec::new(),
            restart_required: false,
            preview: false,
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

    #[test]
    fn thresholds_default_to_nettriage_and_can_be_overridden() {
        let p = Profile::from_toml("[thresholds]\nwifi_signal_pct = { warn = 60.0, crit = 40.0 }").unwrap();
        let t = &p.thresholds;
        assert_eq!(t.cpu_pct, Band::new(75.0, 90.0));
        assert_eq!(t.disk_free_pct.low(12.0), Severity::Warning);
        assert_eq!(t.disk_free_pct.low(10.0), Severity::Critical);
        assert_eq!(t.gateway_rtt_ms.high(19.9), Severity::Ok);
        assert_eq!(t.gateway_rtt_ms.high(20.0), Severity::Warning);
        assert_eq!(t.wifi_signal_pct.low(55.0), Severity::Warning, "overridden band");
    }

    #[test]
    fn shipped_example_profiles_parse() {
        let clinical = Profile::from_toml(include_str!("../../../profiles/clinical-workstation.example.toml")).unwrap();
        assert!(clinical.policy.remote_safe && !clinical.network.public_probes);
        assert_eq!(clinical.network.tcp_probe_target(), Some(("ehr-gateway.example.org".into(), 443)));
        assert_eq!(clinical.thresholds.wifi_signal_pct, Band::new(70.0, 50.0), "commented bands keep the defaults");
        assert_eq!(clinical.security.require_encryption, Some(true));
        assert!(!clinical.security.user_may_be_admin && !clinical.updates.notify);
        assert!(clinical.fix_allowed("clear-saved-credentials", None) && clinical.fix_allowed("unlock-account", Some(r"CORP\jparker")));
        assert!(!clinical.fix_allowed("restart-computer", None), "not on its list");
        let lab = Profile::from_toml(include_str!("../../../profiles/home-lab.toml")).unwrap();
        assert_eq!(lab.updates.windows_update_drivers, DriverSource::Always);
        assert_eq!(lab.network.target_ports, vec![22, 443, 445, 8006]);
        assert_eq!(lab.history.keep, 0);
        assert!(lab.security.user_may_be_admin && lab.security.require_encryption.is_none() && lab.updates.notify, "the defaults");
        assert_eq!(lab.thresholds.password_expiry_days, Band::new(14.0, 3.0));
        let strict = Profile::from_toml("[thresholds]\ndefinitions_age_days = { warn = 1, crit = 2 }\n[security]\nrequire_encryption = false").unwrap();
        assert_eq!(strict.thresholds.definitions_age_days.high(1.0), Severity::Warning);
        assert_eq!(strict.security.require_encryption, Some(false));
        let ints = Profile::from_toml("[thresholds]\nuptime_days = { warn = 3, crit = 5 }").unwrap();
        assert_eq!(ints.thresholds.uptime_days, Band::new(3.0, 5.0), "whole numbers work in bands");
    }

    #[test]
    fn a_profile_from_before_the_new_keys_still_parses() {
        // 0.9.0's thresholds, with nothing newer: every new key takes its default.
        let old = Profile::from_toml("[thresholds]\nstartup_seconds = { warn = 45, crit = 90 }\n[security]\nuser_may_be_admin = false\n").unwrap();
        assert_eq!(old.thresholds.startup_seconds, Band::new(45.0, 90.0));
        assert_eq!(old.thresholds.logon_seconds, Band::new(60.0, 120.0));
        assert_eq!(old.security.crl_warn_hours, 24);
        assert!(old.audit.event_log, "the system-log copy is on unless a profile says otherwise");
        assert!(!old.security.user_may_be_admin, "the keys it had are kept");
        let tuned = Profile::from_toml("[thresholds]\nlogon_seconds = { warn = 30, crit = 60 }\n[security]\ncrl_warn_hours = 48").unwrap();
        assert_eq!(tuned.security.crl_warn_hours, 48);
        assert_eq!(tuned.thresholds.logon_seconds.high(45.0), Severity::Warning);
    }

    #[test]
    fn ui_theme_is_optional_and_reaches_the_status() {
        assert_eq!(Profile::from_toml("").unwrap().ui.theme, None, "no [ui] means the built-in theme");
        let p = Profile::from_toml("[ui]\ntheme = \"minimal\"").unwrap();
        assert_eq!(p.ui.theme.as_deref(), Some("minimal"));
        let status = loaded(p, "user", None, None).status;
        assert_eq!(status.ui.theme.as_deref(), Some("minimal"));
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["ui"]["theme"], "minimal", "the frontend reads profile.ui.theme");
        // A theme this build doesn't know is the frontend's to ignore, not a broken profile.
        assert!(Profile::from_toml("[ui]\ntheme = \"vaporwave\"").is_ok());
    }

    #[test]
    fn a_managed_profile_must_be_one_only_administrators_can_change() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-managed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile.toml");
        std::fs::write(&path, "name = \"Ward PCs\"\n[policy]\nallow_changes = false\n").unwrap();

        let real = load_from(Some(path.clone()), |_| Ok(()));
        assert_eq!((real.status.source, real.status.name.as_str()), ("managed", "Ward PCs"));
        assert!(!real.profile.policy.allow_changes && real.status.error.is_none());

        // The same file, but a user could have written it: not obeyed, not
        // allowed to lock the app, and the technician is told.
        let planted = load_from(Some(path.clone()), |_| Err("it can be changed by Users".into()));
        assert_ne!(planted.status.source, "managed");
        assert!(planted.profile.policy.allow_changes, "a planted profile sets no policy");
        let warning = planted.status.error.expect("the technician is told");
        assert!(warning.contains("was ignored") && warning.contains("Users"), "{warning}");

        // A broken profile that is the organisation's still fails closed.
        std::fs::write(&path, "[policy]\nallow_changes = \"maybe\"").unwrap();
        let broken = load_from(Some(path.clone()), |_| Ok(()));
        assert!(!broken.profile.policy.allow_changes && broken.status.error.is_some());
        // The same breakage from a user's file locks nothing.
        assert!(load_from(Some(path), |_| Err("x".into())).profile.policy.allow_changes);
        assert!(Profile::default().updates.suspend_bitlocker, "on unless a profile turns it off");
        assert!(!Profile::from_toml("[updates]\nsuspend_bitlocker = false").unwrap().updates.suspend_bitlocker);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn public_probes_can_be_switched_off() {
        let open = Profile::default();
        assert_eq!(open.network.dns_probe_name().as_deref(), Some("www.microsoft.com"));
        assert_eq!(open.network.tcp_probe_target(), Some(("8.8.8.8".into(), 53)));
        let locked = Profile::from_toml("[network]\npublic_probes = false\ndns_probe = \"intranet.example.org\"").unwrap();
        assert_eq!(locked.network.dns_probe_name().as_deref(), Some("intranet.example.org"));
        assert_eq!(locked.network.tcp_probe_target(), None);
        let v6 = Profile::from_toml("[network]\ntcp_probe = \"[2001:db8::1]:443\"").unwrap();
        assert_eq!(v6.network.tcp_probe_target(), Some(("2001:db8::1".into(), 443)));
    }
}
