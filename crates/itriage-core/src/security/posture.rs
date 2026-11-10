//! Security posture. Read-only.
//!
//! Is the disk encrypted, is antivirus on and current, is the firewall on,
//! did the PC start with Secure Boot, is there a TPM, and who can administer
//! it. On Windows one fixed PowerShell script gathers the facts (each part on
//! its own, so one that can't be read doesn't hide the rest) and the plain
//! functions here turn them into findings; they're tested on any OS. On
//! Linux the facts come from `/sys`, `/etc/group` and `systemctl`.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::psjson::{list, or_default};
use crate::profile::{Band, SecuritySettings};
use serde::Deserialize;

pub struct SecurityPosture;

impl TriageModule for SecurityPosture {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "sec.posture",
            "Security posture",
            Category::Security,
            "Disk encryption, antivirus and how old its definitions are, the firewall, Secure Boot, the TPM, and who is an administrator of this PC.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::check(ctx)
    }
}

/// Gathers the facts, changing nothing. Every part is tried on its own.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const POSTURE: &str = r#"
$ErrorActionPreference = 'Stop'
$r = [ordered]@{}

$drive = 'C:'
try { $drive = [string](Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive } catch {}
$enc = [ordered]@{ Drive = $drive; State = 'unknown'; Detail = '' }
try {
  $v = Get-BitLockerVolume -MountPoint $drive
  $p = [string]$v.ProtectionStatus
  $s = [string]$v.VolumeStatus
  if ($p -eq 'On') { $enc.State = 'on' }
  elseif ($s -eq 'FullyDecrypted') { $enc.State = 'off' }
  elseif ($s -eq 'FullyEncrypted') { $enc.State = 'suspended' }
  else { $enc.State = 'changing' }
  $enc.Detail = [string]$v.EncryptionMethod
} catch {
  try {
    $code = [int](New-Object -ComObject Shell.Application).NameSpace($drive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
    if ($code -eq 1 -or $code -eq 6) { $enc.State = 'on' }
    elseif ($code -eq 2) { $enc.State = 'off' }
    elseif ($code -eq 5) { $enc.State = 'suspended' }
    elseif ($code -eq 3 -or $code -eq 4) { $enc.State = 'changing' }
  } catch { $enc.Detail = [string]$_.Exception.Message }
}
$r.Encryption = $enc

$r.Defender = $null
$r.DefenderError = ''
try {
  $mp = Get-MpComputerStatus
  $r.Defender = [ordered]@{
    Antivirus = [bool]$mp.AntivirusEnabled
    RealTime = [bool]$mp.RealTimeProtectionEnabled
    Mode = [string]$mp.AMRunningMode
    Tamper = [bool]$mp.IsTamperProtected
    SignatureVersion = [string]$mp.AntivirusSignatureVersion
    SignatureAgeDays = [int64]$mp.AntivirusSignatureAge
  }
} catch { $r.DefenderError = [string]$_.Exception.Message }

$r.Products = @()
try { $r.Products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object { [ordered]@{ Name = [string]$_.displayName; State = [int64]$_.productState } }) } catch {}
$r.Firewalls = @()
try { $r.Firewalls = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct | ForEach-Object { [ordered]@{ Name = [string]$_.displayName; State = [int64]$_.productState } }) } catch {}

$r.Firewall = @()
$r.FirewallError = ''
try { $r.Firewall = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Enabled = ([string]$_.Enabled -eq 'True') } }) } catch { $r.FirewallError = [string]$_.Exception.Message }
$r.Active = @()
try { $r.Active = @(Get-NetConnectionProfile | ForEach-Object { [string]$_.NetworkCategory }) } catch {}

$r.SecureBoot = $null
try { $r.SecureBoot = [int](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled).UEFISecureBootEnabled } catch {}
$r.Firmware = $null
try { $r.Firmware = [int](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType).PEFirmwareType } catch {}

$r.Tpm = @()
try { $r.Tpm = @(Get-PnpDevice -Class SecurityDevices -PresentOnly | ForEach-Object { [ordered]@{ Name = [string]$_.FriendlyName; Status = [string]$_.Status } }) } catch {}

$r.Uac = $null
try { $r.Uac = [int](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA } catch {}

$r.Admins = @()
$r.AdminsError = ''
try {
  $r.Admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Kind = [string]$_.ObjectClass } })
} catch {
  try {
    $group = (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    $r.Admins = @(([ADSI]"WinNT://./$group,group").psbase.Invoke('Members') | ForEach-Object {
      $path = [string]$_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
      $kind = [string]$_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
      [ordered]@{ Name = (($path -replace '^WinNT://', '') -replace '/', '\'); Kind = $kind }
    })
  } catch { $r.AdminsError = [string]$_.Exception.Message }
}
$r.BuiltinAdminEnabled = $null
try { $r.BuiltinAdminEnabled = [bool](Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' } | Select-Object -First 1).Enabled } catch {}

$r.RunningAs = $null
try {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $r.RunningAs = [ordered]@{ Name = [string]$id.Name; Admin = (@($id.Claims | Where-Object { $_.Value -eq 'S-1-5-32-544' }).Count -gt 0) }
} catch {}

$r.Sensors = @()
try {
  $names = 'Sense','CSFalconService','SentinelAgent','CbDefense','CylanceSvc','xagt','SAVService','Sophos MCS Agent','mfemms','ekrn','cyserver','Tanium Client','WazuhSvc','ElasticEndpoint'
  $r.Sensors = @(Get-Service -Name $names -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Display = [string]$_.DisplayName; Running = ([string]$_.Status -eq 'Running') } })
} catch {}

Send-ITriage $r
"#;

// ------------------------------------------------------------------ facts

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Posture {
    pub encryption: Option<Encryption>,
    pub defender: Option<Defender>,
    #[serde(deserialize_with = "or_default")]
    pub defender_error: String,
    /// Antivirus products registered with Windows Security (not on Server).
    #[serde(deserialize_with = "list")]
    pub products: Vec<Product>,
    /// Third-party firewalls registered with Windows Security.
    #[serde(deserialize_with = "list")]
    pub firewalls: Vec<Product>,
    #[serde(deserialize_with = "list")]
    pub firewall: Vec<FirewallProfile>,
    #[serde(deserialize_with = "or_default")]
    pub firewall_error: String,
    /// The category of each connected network: Public, Private, DomainAuthenticated.
    #[serde(deserialize_with = "list")]
    pub active: Vec<String>,
    pub secure_boot: Option<i64>,
    /// 1 legacy BIOS, 2 UEFI.
    pub firmware: Option<i64>,
    #[serde(deserialize_with = "list")]
    pub tpm: Vec<Device>,
    pub uac: Option<i64>,
    #[serde(deserialize_with = "list")]
    pub admins: Vec<Admin>,
    #[serde(deserialize_with = "or_default")]
    pub admins_error: String,
    pub builtin_admin_enabled: Option<bool>,
    pub running_as: Option<RunningAs>,
    #[serde(deserialize_with = "list")]
    pub sensors: Vec<Sensor>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Encryption {
    #[serde(deserialize_with = "or_default")]
    pub drive: String,
    /// on, off, suspended, changing or unknown.
    #[serde(deserialize_with = "or_default")]
    pub state: String,
    #[serde(deserialize_with = "or_default")]
    pub detail: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Defender {
    pub antivirus: bool,
    pub real_time: bool,
    #[serde(deserialize_with = "or_default")]
    pub mode: String,
    pub tamper: bool,
    #[serde(deserialize_with = "or_default")]
    pub signature_version: String,
    pub signature_age_days: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Product {
    #[serde(deserialize_with = "or_default")]
    pub name: String,
    /// Windows Security's `productState` bit field.
    pub state: i64,
}

impl Product {
    pub fn on(&self) -> bool {
        (self.state >> 12) & 0xF == 1
    }
    pub fn out_of_date(&self) -> bool {
        (self.state >> 4) & 0xF != 0
    }
    fn is_defender(&self) -> bool {
        self.name.to_ascii_lowercase().contains("defender")
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct FirewallProfile {
    #[serde(deserialize_with = "or_default")]
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Device {
    #[serde(deserialize_with = "or_default")]
    pub name: String,
    #[serde(deserialize_with = "or_default")]
    pub status: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Admin {
    #[serde(deserialize_with = "or_default")]
    pub name: String,
    #[serde(deserialize_with = "or_default")]
    pub kind: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct RunningAs {
    #[serde(deserialize_with = "or_default")]
    pub name: String,
    pub admin: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Sensor {
    #[serde(deserialize_with = "or_default")]
    pub name: String,
    #[serde(deserialize_with = "or_default")]
    pub display: String,
    pub running: bool,
}

/// What the grading needs to know besides the facts.
pub struct Site<'a> {
    pub settings: &'a SecuritySettings,
    pub definitions_age_days: Band,
    /// A laptop or tablet (it has a battery). `None`: couldn't tell.
    pub portable: Option<bool>,
    /// Whoever is signed in at the PC: `CORP\jparker`.
    pub user: Option<&'a str>,
    /// This computer's name, to drop from `WS-1\Administrator`.
    pub hostname: &'a str,
}

// ---------------------------------------------------------------- grading

pub fn encryption_finding(drive: &str, state: &str, detail: &str, what: &str, site: &Site) -> Finding {
    const LABEL: &str = "Disk encryption";
    let on = if drive.is_empty() { String::new() } else { format!("{drive} ") };
    match state {
        "on" => {
            let how = if detail.is_empty() || detail == "None" { String::new() } else { format!(" ({detail})") };
            Finding::ok(LABEL, format!("{on}{what} is on{how}"))
        }
        "suspended" => Finding::warn(LABEL, format!("{on}encrypted, but {what} protection is suspended")).with_detail(
            "The key is stored on the drive unprotected until protection resumes. It resumes by itself after the \
             restart that follows a firmware update; if it doesn't, resume it by hand.",
        ),
        "changing" => Finding::info(LABEL, format!("{on}encrypting or decrypting right now")),
        "off" => {
            let severity = match (site.settings.require_encryption, site.portable) {
                (Some(true), _) => Severity::Critical,
                (Some(false), _) => Severity::Info,
                (None, Some(true)) => Severity::Warning,
                (None, _) => Severity::Info,
            };
            let mut f = Finding::new(LABEL, format!("{on}not encrypted"), severity);
            if severity != Severity::Info {
                f = f.with_detail("Anyone who takes this PC or its drive can read everything on it.");
            }
            f
        }
        _ => Finding::info(
            LABEL,
            format!("{on}state not readable{}", if detail.is_empty() { String::new() } else { format!(" ({detail})") }),
        )
        .with_detail("Some PCs only report this to an administrator."),
    }
}

/// The antivirus findings: whether something is protecting the PC, and how
/// old its definitions are.
pub fn antivirus_findings(p: &Posture, band: Band) -> Vec<Finding> {
    const LABEL: &str = "Antivirus";
    const DEFS: &str = "Antivirus definitions";
    let third: Vec<&Product> = p.products.iter().filter(|x| !x.is_defender() && !x.name.is_empty()).collect();
    let third_on: Vec<&Product> = third.iter().copied().filter(|x| x.on()).collect();
    let mut out = Vec::new();

    if !third_on.is_empty() {
        let names: Vec<&str> = third_on.iter().map(|x| x.name.as_str()).collect();
        let mut f = Finding::ok(LABEL, format!("{}: on", names.join(", ")));
        if let Some(d) = &p.defender {
            if !d.mode.is_empty() {
                f = f.with_detail(format!("Microsoft Defender: {}", d.mode.to_lowercase()));
            }
        }
        out.push(f);
        let stale: Vec<&str> = third_on.iter().filter(|x| x.out_of_date()).map(|x| x.name.as_str()).collect();
        out.push(if stale.is_empty() {
            Finding::ok(DEFS, "up to date")
        } else {
            Finding::warn(DEFS, format!("{} reports its definitions are out of date", stale.join(", ")))
        });
        return out;
    }

    if let Some(d) = &p.defender {
        let passive = d.mode.to_ascii_lowercase().contains("passive");
        if d.antivirus && d.real_time {
            let tamper = if d.tamper { " · tamper protection on" } else { "" };
            out.push(Finding::ok(LABEL, format!("Microsoft Defender: real-time protection on{tamper}")));
        } else if passive {
            out.push(
                Finding::crit(LABEL, "Microsoft Defender is in passive mode, and no other antivirus reports as on")
                    .with_detail("Passive mode expects another product to do the protecting. Nothing is."),
            );
        } else {
            let mut f = Finding::crit(LABEL, "Microsoft Defender: real-time protection is off");
            if !third.is_empty() {
                let names: Vec<&str> = third.iter().map(|x| x.name.as_str()).collect();
                f = f.with_detail(format!("Also installed, and reporting as off: {}.", names.join(", ")));
            }
            out.push(f);
        }
        out.push(definitions(DEFS, d, band));
        return out;
    }

    if let Some(d) = p.products.iter().find(|x| x.is_defender()) {
        // Windows Security knows about Defender, but its own status couldn't be read.
        out.push(if d.on() {
            Finding::ok(LABEL, "Microsoft Defender: on")
        } else {
            Finding::crit(LABEL, "Microsoft Defender: off")
        });
        if d.on() && d.out_of_date() {
            out.push(Finding::warn(DEFS, "Windows Security reports them as out of date"));
        }
        return out;
    }
    if !third.is_empty() {
        let names: Vec<&str> = third.iter().map(|x| x.name.as_str()).collect();
        out.push(Finding::crit(LABEL, format!("{}: installed, but reporting as off", names.join(", "))));
        return out;
    }
    let mut f = Finding::warn(LABEL, "none found");
    if !p.defender_error.is_empty() {
        f = f.with_detail(format!("Microsoft Defender didn't answer: {}", p.defender_error));
    }
    out.push(f);
    out
}

fn definitions(label: &str, d: &Defender, band: Band) -> Finding {
    let version = if d.signature_version.is_empty() { String::new() } else { format!("version {} · ", d.signature_version) };
    // Defender reports a huge number when it has never updated.
    if !(0..=3650).contains(&d.signature_age_days) {
        return Finding::crit(label, format!("{version}never updated"));
    }
    let age = d.signature_age_days;
    let when = match age {
        0 => "updated today".to_string(),
        1 => "updated yesterday".to_string(),
        n => format!("updated {n} days ago"),
    };
    Finding::new(label, format!("{version}{when}"), band.high(age as f64)).with_metric(age as f64, "days", true)
}

pub fn firewall_finding(p: &Posture) -> Finding {
    const LABEL: &str = "Firewall";
    let third: Vec<&str> = p.firewalls.iter().filter(|x| x.on() && !x.name.is_empty()).map(|x| x.name.as_str()).collect();
    if p.firewall.is_empty() {
        if !third.is_empty() {
            return Finding::info(LABEL, format!("{} is registered as the firewall", third.join(", ")));
        }
        let why = if p.firewall_error.is_empty() { String::new() } else { format!(": {}", p.firewall_error) };
        return Finding::info(LABEL, format!("couldn't read the Windows Firewall profiles{why}"));
    }
    let active: Vec<String> = p
        .active
        .iter()
        .map(|a| if a.eq_ignore_ascii_case("DomainAuthenticated") { "Domain".to_string() } else { a.clone() })
        .collect();
    let in_use = |name: &str| active.iter().any(|a| a.eq_ignore_ascii_case(name));
    let off: Vec<&str> = p.firewall.iter().filter(|f| !f.enabled).map(|f| f.name.as_str()).collect();
    let using = if active.is_empty() { String::new() } else { format!("In use now: {}.", join_and(&active.iter().map(String::as_str).collect::<Vec<_>>())) };
    if off.is_empty() {
        let names: Vec<&str> = p.firewall.iter().map(|f| f.name.as_str()).collect();
        return Finding::ok(LABEL, format!("Windows Firewall is on for {}", join_and(&names))).with_detail(using);
    }
    let profiles = format!("{} profile{}", join_and(&off), if off.len() == 1 { "" } else { "s" });
    if !third.is_empty() {
        return Finding::info(LABEL, format!("Windows Firewall is off for the {profiles}; {} is registered as the firewall", third.join(", ")))
            .with_detail(using);
    }
    if off.iter().any(|n| in_use(n)) {
        Finding::crit(LABEL, format!("Windows Firewall is off for the {profiles}")).with_detail(format!(
            "{using} Nothing is filtering connections to this PC on the network it's on."
        ))
    } else {
        Finding::warn(LABEL, format!("Windows Firewall is off for the {profiles}"))
            .with_detail(format!("{using} It isn't the profile in use, but it will be on another network."))
    }
}

/// "a", "a and b", "a, b and c".
fn join_and(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

pub fn secure_boot_finding(on: Option<bool>, legacy_bios: bool) -> Finding {
    const LABEL: &str = "Secure Boot";
    match on {
        Some(true) => Finding::ok(LABEL, "on"),
        Some(false) => Finding::warn(LABEL, "off").with_detail(
            "The PC will start an operating system or boot loader that nobody has signed. It's switched on in the firmware (UEFI) settings.",
        ),
        None if legacy_bios => Finding::info(LABEL, "not available: this PC starts in legacy BIOS mode"),
        None => Finding::info(LABEL, "not reported by this PC"),
    }
}

pub fn tpm_finding(devices: &[(String, String)]) -> Finding {
    const LABEL: &str = "TPM";
    match devices.first() {
        None => Finding::info(LABEL, "none found").with_detail(if cfg!(windows) {
            "Without a TPM, BitLocker needs a password or a USB key at every start, and Windows 11 isn't supported."
        } else {
            "Without a TPM, disk encryption can't unlock by itself at start-up."
        }),
        Some((name, status)) if status.is_empty() || status.eq_ignore_ascii_case("OK") => Finding::ok(LABEL, name.clone()),
        Some((name, status)) => Finding::warn(LABEL, format!("{name}: {status}")),
    }
}

pub fn uac_finding(enabled: Option<i64>) -> Option<Finding> {
    const LABEL: &str = "User Account Control";
    match enabled? {
        0 => Some(Finding::warn(LABEL, "off").with_detail("Every program an administrator starts runs with full rights, without asking.")),
        _ => Some(Finding::ok(LABEL, "on")),
    }
}

/// Who can administer the PC. `user_is_admin` is about whoever is signed in.
pub fn admins_finding(names: &[String], user_is_admin: bool, builtin_enabled: Option<bool>, error: &str, site: &Site) -> Finding {
    const LABEL: &str = "Administrators of this PC";
    if names.is_empty() {
        let why = if error.is_empty() { "the list came back empty".to_string() } else { error.to_string() };
        return Finding::info(LABEL, format!("couldn't list them: {why}"));
    }
    let local = format!("{}\\", site.hostname.to_ascii_lowercase());
    let shown: Vec<String> = names
        .iter()
        .map(|n| if n.to_ascii_lowercase().starts_with(&local) { n[local.len()..].to_string() } else { n.clone() })
        .collect();
    let mut notes = Vec::new();
    if user_is_admin {
        notes.push(match site.user {
            Some(u) => format!("The signed-in user ({u}) is an administrator of this PC."),
            None => "The signed-in user is an administrator of this PC.".to_string(),
        });
    }
    if builtin_enabled == Some(true) {
        notes.push("The built-in Administrator account is enabled.".to_string());
    }
    let severity = if user_is_admin && !site.settings.user_may_be_admin { Severity::Warning } else { Severity::Info };
    Finding::new(LABEL, format!("{}: {}", shown.len(), shown.join(", ")), severity).with_detail(notes.join(" "))
}

fn sensor_name(service: &str, display: &str) -> String {
    let known = match service.to_ascii_lowercase().as_str() {
        "sense" => "Microsoft Defender for Endpoint",
        "csfalconservice" => "CrowdStrike Falcon",
        "sentinelagent" => "SentinelOne",
        "cbdefense" => "Carbon Black",
        "cylancesvc" => "Cylance",
        "xagt" => "Trellix (FireEye) Endpoint",
        "savservice" | "sophos mcs agent" => "Sophos",
        "mfemms" => "Trellix (McAfee) Endpoint Security",
        "ekrn" => "ESET",
        "cyserver" => "Cortex XDR",
        "tanium client" => "Tanium",
        "wazuhsvc" => "Wazuh",
        "elasticendpoint" => "Elastic Defend",
        _ => "",
    };
    if known.is_empty() {
        display.to_string()
    } else {
        known.to_string()
    }
}

pub fn sensor_findings(sensors: &[Sensor]) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for s in sensors {
        let name = sensor_name(&s.name, &s.display);
        let label = format!("EDR sensor ({name})");
        if out.iter().any(|f| f.label == label) {
            continue; // two services of one product
        }
        if s.running {
            out.push(Finding::ok(label, "running"));
        } else if !s.name.eq_ignore_ascii_case("Sense") {
            // Defender for Endpoint's service exists, stopped, on every PC
            // that was never onboarded; the others only exist when installed.
            out.push(Finding::warn(label, "installed, but its service isn't running"));
        }
    }
    out
}

/// Every finding for a Windows PC, in the order the report shows them.
pub fn windows_findings(p: &Posture, site: &Site) -> Vec<Finding> {
    let mut out = Vec::new();
    match &p.encryption {
        Some(e) => out.push(encryption_finding(&e.drive, &e.state, &e.detail, "BitLocker", site)),
        None => out.push(encryption_finding("", "unknown", "", "BitLocker", site)),
    }
    out.extend(antivirus_findings(p, site.definitions_age_days));
    out.extend(sensor_findings(&p.sensors));
    out.push(firewall_finding(p));
    out.push(secure_boot_finding(p.secure_boot.map(|v| v != 0), p.firmware == Some(1)));
    let tpm: Vec<(String, String)> = p.tpm.iter().map(|d| (d.name.clone(), d.status.clone())).collect();
    out.push(tpm_finding(&tpm));
    out.extend(uac_finding(p.uac));

    let names: Vec<String> = p.admins.iter().map(|a| a.name.clone()).filter(|n| !n.is_empty()).collect();
    let same = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    let user_is_admin = match (site.user, &p.running_as) {
        // ITriage is running as the signed-in user: Windows says outright
        // whether they're an administrator, through groups too.
        (Some(user), Some(me)) if same(user, &me.name) => me.admin,
        (Some(user), _) => names.iter().any(|n| same(n, user)),
        (None, Some(me)) => me.admin,
        (None, None) => false,
    };
    out.push(admins_finding(&names, user_is_admin, p.builtin_admin_enabled, &p.admins_error, site));
    out
}

/// One line for the card: what needs attention, or that nothing does.
pub fn summary(findings: &[Finding]) -> String {
    let problems: Vec<&str> = findings
        .iter()
        .filter(|f| f.severity.rank() >= Severity::Warning.rank())
        .map(|f| f.label.as_str())
        .collect();
    match problems.len() {
        0 => "No gaps found".to_string(),
        n => format!("{n} to look at: {}", problems.join(", ").to_lowercase()),
    }
}

#[cfg(windows)]
mod imp {
    use super::*;

    pub fn check(ctx: &RunContext) -> Result<Output, String> {
        let out = crate::win::ps::run(POSTURE, ctx, std::time::Duration::from_secs(120))?;
        let facts: Posture = crate::fixes::json(&out.stdout).map_err(|e| format!("{e} ({})", crate::util::exit_label(out.code)))?;
        let user = crate::win::session::console_user().or_else(crate::win::session::current_account);
        let hostname = sysinfo::System::host_name().unwrap_or_default();
        let profile = ctx.profile();
        let site = Site {
            settings: &profile.security,
            definitions_age_days: profile.thresholds.definitions_age_days,
            portable: crate::win::domain::power().map(|(_, _, battery)| battery),
            user: user.as_deref(),
            hostname: &hostname,
        };
        let findings = windows_findings(&facts, &site);
        Ok(Output::new(summary(&findings), findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::util::{capture_for, cmd, command_exists};
    use std::path::Path;
    use std::time::Duration;

    const SECURE_BOOT_VAR: &str = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    /// Units of the endpoint agents a desk is likely to meet on Linux.
    const AGENTS: [(&str, &str); 9] = [
        ("falcon-sensor", "CrowdStrike Falcon"),
        ("sentinelone", "SentinelOne"),
        ("mdatp", "Microsoft Defender for Endpoint"),
        ("cbagentd", "Carbon Black"),
        ("sophos-spl", "Sophos"),
        ("elastic-agent", "Elastic Agent"),
        ("wazuh-agent", "Wazuh"),
        ("esets", "ESET"),
        ("clamav-daemon", "ClamAV"),
    ];

    pub fn check(ctx: &RunContext) -> Result<Output, String> {
        let user = std::env::var("SUDO_USER").or_else(|_| std::env::var("USER")).ok().filter(|u| !u.is_empty() && u != "root");
        let hostname = sysinfo::System::host_name().unwrap_or_default();
        let profile = ctx.profile();
        let site = Site {
            settings: &profile.security,
            definitions_age_days: profile.thresholds.definitions_age_days,
            portable: Some(has_battery()),
            user: user.as_deref(),
            hostname: &hostname,
        };

        let mut findings = Vec::new();
        let state = match root_device().map(|dev| encrypted(Path::new("/sys/dev/block"), &dev)) {
            Some(true) => "on",
            Some(false) => "off",
            None => "unknown",
        };
        let detail = if state == "unknown" { "the root file system isn't on an ordinary disk" } else { "LUKS" };
        findings.push(encryption_finding("/", state, detail, "disk encryption", &site));

        let active = active_units(AGENTS.iter().map(|(unit, _)| *unit));
        let running: Vec<&str> = AGENTS.iter().filter(|(unit, _)| active.iter().any(|a| a == unit)).map(|(_, name)| *name).collect();
        findings.push(if running.is_empty() {
            Finding::info("Endpoint protection", "no agent found running").with_detail(
                "Looked for CrowdStrike, SentinelOne, Defender for Endpoint, Carbon Black, Sophos, Elastic, Wazuh, ESET and ClamAV.",
            )
        } else {
            Finding::ok("Endpoint protection", format!("{}: running", running.join(", ")))
        });

        findings.push(firewall());
        let secure_boot = std::fs::read(SECURE_BOOT_VAR).ok().and_then(|bytes| bytes.get(4).map(|b| *b == 1));
        findings.push(secure_boot_finding(secure_boot, !Path::new("/sys/firmware/efi").exists()));
        let tpm = std::fs::read_to_string("/sys/class/tpm/tpm0/tpm_version_major")
            .ok()
            .map(|v| vec![(format!("TPM {}.0", v.trim()), String::new())])
            .or_else(|| Path::new("/sys/class/tpm/tpm0").exists().then(|| vec![("TPM present".to_string(), String::new())]))
            .unwrap_or_default();
        findings.push(tpm_finding(&tpm));

        let admins = group_members(&std::fs::read_to_string("/etc/group").unwrap_or_default(), &["sudo", "wheel", "admin"]);
        let user_is_admin = user.as_deref().is_some_and(|u| admins.iter().any(|a| a == u));
        let mut f = admins_finding(&admins, user_is_admin, None, "nobody is in the sudo, wheel or admin group", &site);
        f.label = "Administrators (sudo)".to_string();
        findings.push(f);

        Ok(Output::new(summary(&findings), findings))
    }

    fn has_battery() -> bool {
        std::fs::read_dir("/sys/class/power_supply")
            .map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().starts_with("BAT")))
            .unwrap_or(false)
    }

    /// The `major:minor` of the device the root file system is on. `None`
    /// for btrfs subvolumes, overlays and network roots, which have no
    /// single block device.
    fn root_device() -> Option<String> {
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        root_device_in(&mounts)
    }

    pub(super) fn root_device_in(mountinfo: &str) -> Option<String> {
        mountinfo.lines().find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.get(4) == Some(&"/") && fields.get(3) == Some(&"/"))
                .then(|| fields.get(2).map(|s| s.to_string()))
                .flatten()
                .filter(|dev| !dev.starts_with("0:"))
        })
    }

    /// Is this block device, or anything it's built on, a dm-crypt (LUKS)
    /// mapping? `sys` is `/sys/dev/block`.
    pub(super) fn encrypted(sys: &Path, device: &str) -> bool {
        fn walk(node: &Path, depth: u8) -> bool {
            if depth > 6 {
                return false;
            }
            if std::fs::read_to_string(node.join("dm/uuid")).is_ok_and(|uuid| uuid.starts_with("CRYPT-")) {
                return true;
            }
            std::fs::read_dir(node.join("slaves"))
                .map(|rd| rd.flatten().any(|slave| walk(&slave.path(), depth + 1)))
                .unwrap_or(false)
        }
        walk(&sys.join(device), 0)
    }

    fn active_units<'a>(units: impl Iterator<Item = &'a str>) -> Vec<String> {
        if !command_exists("systemctl") {
            return Vec::new();
        }
        let units: Vec<&str> = units.collect();
        let mut c = cmd("systemctl");
        c.arg("is-active").args(&units);
        // One line per unit, in order: "active", "inactive", "unknown"…
        match capture_for(c, Duration::from_secs(15)) {
            Ok(out) => units
                .iter()
                .zip(out.stdout.lines())
                .filter(|(_, state)| state.trim() == "active")
                .map(|(unit, _)| unit.to_string())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn firewall() -> Finding {
        const LABEL: &str = "Firewall";
        let active = active_units(["firewalld", "ufw", "nftables"].into_iter());
        let has = |name: &str| active.iter().any(|a| a == name);
        // ufw's unit stays "active" when the firewall itself is switched off.
        let ufw_on = has("ufw")
            && std::fs::read_to_string("/etc/ufw/ufw.conf").is_ok_and(|conf| conf.lines().any(|l| l.trim().eq_ignore_ascii_case("ENABLED=yes")));
        let on: Vec<&str> = [("firewalld", has("firewalld")), ("ufw", ufw_on), ("nftables", has("nftables"))]
            .into_iter()
            .filter(|(_, yes)| *yes)
            .map(|(name, _)| name)
            .collect();
        if on.is_empty() {
            Finding::warn(LABEL, "no firewall is on").with_detail("Looked for firewalld, ufw and an nftables service.")
        } else {
            Finding::ok(LABEL, format!("{} is on", on.join(" and ")))
        }
    }

    /// Members of the named groups, from `/etc/group` text, without repeats.
    pub(super) fn group_members(etc_group: &str, groups: &[&str]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for line in etc_group.lines() {
            let mut parts = line.split(':');
            let (Some(name), Some(members)) = (parts.next(), parts.nth(2)) else { continue };
            if !groups.contains(&name) {
                continue;
            }
            for m in members.split(',').map(str::trim).filter(|m| !m.is_empty()) {
                if !out.iter().any(|o| o == m) {
                    out.push(m.to_string());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site<'a>(settings: &'a SecuritySettings, portable: bool, user: Option<&'a str>) -> Site<'a> {
        Site { settings, definitions_age_days: crate::profile::Thresholds::default().definitions_age_days, portable: Some(portable), user, hostname: "WS-1" }
    }

    /// What the script prints on a healthy managed laptop.
    const HEALTHY: &str = r#"{"Encryption":{"Drive":"C:","State":"on","Detail":"XtsAes256"},
        "Defender":{"Antivirus":true,"RealTime":true,"Mode":"Normal","Tamper":true,"SignatureVersion":"1.421.33.0","SignatureAgeDays":1},
        "DefenderError":"","Products":[{"Name":"Windows Defender","State":397568}],"Firewalls":[],
        "Firewall":[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":true},{"Name":"Public","Enabled":true}],"FirewallError":"",
        "Active":"DomainAuthenticated","SecureBoot":1,"Firmware":2,"Tpm":{"Name":"Trusted Platform Module 2.0","Status":"OK"},"Uac":1,
        "Admins":[{"Name":"WS-1\\Administrator","Kind":"User"},{"Name":"CORP\\Domain Admins","Kind":"Group"}],"AdminsError":"",
        "BuiltinAdminEnabled":false,"RunningAs":{"Name":"CORP\\jparker","Admin":false},
        "Sensors":[{"Name":"Sense","Display":"Windows Defender Advanced Threat Protection Service","Running":false}]}"#;

    fn by<'a>(findings: &'a [Finding], label: &str) -> &'a Finding {
        findings.iter().find(|f| f.label == label).unwrap_or_else(|| panic!("no {label} in {findings:?}"))
    }

    #[test]
    fn a_healthy_laptop_has_no_gaps() {
        let p: Posture = serde_json::from_str(HEALTHY).unwrap();
        let settings = SecuritySettings::default();
        let findings = windows_findings(&p, &site(&settings, true, Some(r"CORP\jparker")));
        assert_eq!(summary(&findings), "No gaps found", "{findings:#?}");
        assert_eq!(by(&findings, "Disk encryption").value, "C: BitLocker is on (XtsAes256)");
        assert_eq!(by(&findings, "Antivirus").value, "Microsoft Defender: real-time protection on · tamper protection on");
        assert_eq!(by(&findings, "Antivirus definitions").value, "version 1.421.33.0 · updated yesterday");
        assert_eq!(by(&findings, "Firewall").value, "Windows Firewall is on for Domain, Private and Public");
        assert_eq!(by(&findings, "Firewall").detail.as_deref(), Some("In use now: Domain."));
        assert_eq!(by(&findings, "TPM").value, "Trusted Platform Module 2.0");
        assert_eq!(by(&findings, "Administrators of this PC").value, r"2: Administrator, CORP\Domain Admins");
        assert!(!findings.iter().any(|f| f.label.starts_with("EDR")), "a stopped Sense service is the normal state");
    }

    #[test]
    fn grades_encryption_by_form_factor_and_policy() {
        let default = SecuritySettings::default();
        let sev = |settings: &SecuritySettings, portable| encryption_finding("C:", "off", "", "BitLocker", &site(settings, portable, None)).severity;
        assert_eq!(sev(&default, true), Severity::Warning, "an unencrypted laptop");
        assert_eq!(sev(&default, false), Severity::Info, "a desktop is only noted");
        let required = SecuritySettings { require_encryption: Some(true), ..SecuritySettings::default() };
        assert_eq!(sev(&required, false), Severity::Critical);
        let waived = SecuritySettings { require_encryption: Some(false), ..SecuritySettings::default() };
        assert_eq!(sev(&waived, true), Severity::Info);
        let s = site(&default, true, None);
        assert_eq!(encryption_finding("C:", "suspended", "", "BitLocker", &s).severity, Severity::Warning);
        assert_eq!(encryption_finding("C:", "unknown", "Access denied", "BitLocker", &s).severity, Severity::Info);
    }

    #[test]
    fn grades_antivirus() {
        let band = crate::profile::Thresholds::default().definitions_age_days;
        let with = |json: &str| antivirus_findings(&serde_json::from_str::<Posture>(json).unwrap(), band);

        let off = with(r#"{"Defender":{"Antivirus":true,"RealTime":false,"Mode":"Normal","SignatureVersion":"1.1","SignatureAgeDays":9}}"#);
        assert_eq!(off[0].severity, Severity::Critical);
        assert_eq!(off[0].value, "Microsoft Defender: real-time protection is off");
        assert_eq!(off[1].severity, Severity::Critical, "9 days is past the 7-day limit");
        assert_eq!(off[1].metric.as_ref().unwrap().value, 9.0);

        let never = with(r#"{"Defender":{"Antivirus":true,"RealTime":true,"Mode":"Normal","SignatureAgeDays":4294967295}}"#);
        assert_eq!(never[1].value, "never updated");

        // CrowdStrike registered and on (0x41000); Defender passive beside it.
        let third = with(r#"{"Defender":{"Antivirus":false,"RealTime":false,"Mode":"Passive Mode","SignatureAgeDays":2},
            "Products":[{"Name":"Windows Defender","State":393472},{"Name":"CrowdStrike Falcon Sensor","State":266240}]}"#);
        assert_eq!(third[0].severity, Severity::Ok);
        assert_eq!(third[0].value, "CrowdStrike Falcon Sensor: on");
        assert_eq!(third[0].detail.as_deref(), Some("Microsoft Defender: passive mode"));
        assert_eq!(third[1].value, "up to date");

        let stale = with(r#"{"Products":{"Name":"Sophos Anti-Virus","State":266256}}"#);
        assert_eq!(stale[1].severity, Severity::Warning);

        let passive_alone = with(r#"{"Defender":{"Antivirus":false,"RealTime":false,"Mode":"Passive Mode","SignatureAgeDays":2}}"#);
        assert_eq!(passive_alone[0].severity, Severity::Critical);
        assert!(passive_alone[0].value.contains("passive mode"));

        let third_off = with(r#"{"Products":[{"Name":"Norton 360","State":262144}],"DefenderError":"0x800106ba"}"#);
        assert_eq!(third_off[0].value, "Norton 360: installed, but reporting as off");

        let none = with(r#"{"DefenderError":"The service has not been started."}"#);
        assert_eq!(none[0].severity, Severity::Warning);
        assert!(none[0].detail.as_deref().unwrap().contains("has not been started"));
    }

    #[test]
    fn grades_the_firewall_by_the_profile_in_use() {
        let with = |json: &str| firewall_finding(&serde_json::from_str::<Posture>(json).unwrap());
        let public_off = r#"[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":true},{"Name":"Public","Enabled":false}]"#;
        let in_use = with(&format!(r#"{{"Firewall":{public_off},"Active":["Public"]}}"#));
        assert_eq!(in_use.severity, Severity::Critical);
        assert_eq!(in_use.value, "Windows Firewall is off for the Public profile");
        let elsewhere = with(&format!(r#"{{"Firewall":{public_off},"Active":["DomainAuthenticated"]}}"#));
        assert_eq!(elsewhere.severity, Severity::Warning);
        let replaced = with(&format!(r#"{{"Firewall":{public_off},"Active":["Public"],"Firewalls":[{{"Name":"ESET Firewall","State":266240}}]}}"#));
        assert_eq!(replaced.severity, Severity::Info);
        assert!(replaced.value.ends_with("ESET Firewall is registered as the firewall"));
        let unreadable = with(r#"{"FirewallError":"Access is denied."}"#);
        assert_eq!(unreadable.severity, Severity::Info);
        assert!(unreadable.value.contains("Access is denied."));
        assert_eq!(join_and(&["a", "b", "c"]), "a, b and c");
    }

    #[test]
    fn flags_an_admin_user_only_when_the_site_says_so() {
        let mut p: Posture = serde_json::from_str(HEALTHY).unwrap();
        p.running_as = Some(RunningAs { name: r"corp\JParker".into(), admin: true });
        p.builtin_admin_enabled = Some(true);
        let relaxed = SecuritySettings::default();
        let f = windows_findings(&p, &site(&relaxed, true, Some(r"CORP\jparker")));
        let admins = by(&f, "Administrators of this PC");
        assert_eq!(admins.severity, Severity::Info);
        assert_eq!(
            admins.detail.as_deref(),
            Some(r"The signed-in user (CORP\jparker) is an administrator of this PC. The built-in Administrator account is enabled.")
        );
        let strict = SecuritySettings { user_may_be_admin: false, ..SecuritySettings::default() };
        let f = windows_findings(&p, &site(&strict, true, Some(r"CORP\jparker")));
        assert_eq!(by(&f, "Administrators of this PC").severity, Severity::Warning);

        // Elevated as a technician: the signed-in user is judged by the list.
        p.running_as = Some(RunningAs { name: r"CORP\tech-admin".into(), admin: true });
        let f = windows_findings(&p, &site(&strict, true, Some(r"CORP\jparker")));
        assert_eq!(by(&f, "Administrators of this PC").severity, Severity::Info, "jparker isn't a direct member");
        p.admins.push(Admin { name: r"CORP\jparker".into(), kind: "User".into() });
        let f = windows_findings(&p, &site(&strict, true, Some(r"CORP\jparker")));
        assert_eq!(by(&f, "Administrators of this PC").severity, Severity::Warning);
    }

    #[test]
    fn reports_the_rest_of_the_posture() {
        assert_eq!(secure_boot_finding(Some(false), false).severity, Severity::Warning);
        assert!(secure_boot_finding(None, true).value.contains("legacy BIOS"));
        assert_eq!(tpm_finding(&[]).severity, Severity::Info);
        assert_eq!(tpm_finding(&[("Trusted Platform Module 2.0".into(), "Error".into())]).severity, Severity::Warning);
        assert_eq!(uac_finding(Some(0)).unwrap().severity, Severity::Warning);
        assert!(uac_finding(None).is_none());
        let sensors = sensor_findings(&[
            Sensor { name: "CSFalconService".into(), display: "CrowdStrike Falcon Sensor Service".into(), running: true },
            Sensor { name: "SentinelAgent".into(), display: "Sentinel Agent".into(), running: false },
            Sensor { name: "Sense".into(), display: "x".into(), running: false },
        ]);
        assert_eq!(sensors.len(), 2);
        assert_eq!((sensors[0].label.as_str(), sensors[0].severity), ("EDR sensor (CrowdStrike Falcon)", Severity::Ok));
        assert_eq!(sensors[1].severity, Severity::Warning);
        // An empty answer still makes a report, with nothing claimed.
        let settings = SecuritySettings::default();
        let empty = windows_findings(&Posture::default(), &site(&settings, false, None));
        assert!(empty.iter().all(|f| f.severity != Severity::Ok || f.label == "x"), "{empty:#?}");
        assert_eq!(summary(&empty), "1 to look at: antivirus");
    }

    #[cfg(not(windows))]
    #[test]
    fn linux_facts_are_read_from_plain_files() {
        let mounts = "22 28 0:21 / /proc rw - proc proc rw\n29 1 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg-root rw\n31 29 259:1 / /boot rw - ext4 /dev/nvme0n1p1 rw\n";
        assert_eq!(imp::root_device_in(mounts).as_deref(), Some("253:1"));
        assert_eq!(imp::root_device_in("29 1 0:25 /@ / rw - btrfs /dev/sda2 rw\n"), None, "a subvolume has no device number");

        // LVM on LUKS: 253:1 (LVM) sits on 253:0 (CRYPT), which sits on a partition.
        let sys = std::env::temp_dir().join(format!("itriage-posture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sys);
        let mk = |rel: &str, text: Option<&str>| {
            let path = sys.join(rel);
            match text {
                Some(t) => {
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, t).unwrap();
                }
                None => std::fs::create_dir_all(path).unwrap(),
            }
        };
        mk("253:1/dm/uuid", Some("LVM-abc\n"));
        mk("253:1/slaves/dm-0/dm/uuid", Some("CRYPT-LUKS2-0123-nvme0n1p3_crypt\n"));
        mk("253:1/slaves/dm-0/slaves/nvme0n1p3", None);
        mk("259:2", None);
        assert!(imp::encrypted(&sys, "253:1"));
        assert!(!imp::encrypted(&sys, "259:2"), "a plain partition");
        let _ = std::fs::remove_dir_all(&sys);

        let groups = "root:x:0:\nsudo:x:27:jparker,ansible\nwheel:x:10:jparker\nusers:x:100:guest\n";
        assert_eq!(imp::group_members(groups, &["sudo", "wheel", "admin"]), ["jparker", "ansible"]);
    }
}
