//! BitLocker on the system drive: reading its state, and suspending it for
//! one restart before a BIOS or firmware update.
//!
//! A firmware update changes what the TPM measures at boot. With BitLocker
//! protection on, the next start-up then asks for the 48-digit recovery key,
//! which the person at the PC rarely has. Suspending protection until the
//! next restart is the supported way round that: the drive stays encrypted,
//! and protection comes back by itself after the restart.
//!
//! The scripts are fixed text (see [`crate::win::ps`]); what they print is
//! read by the plain functions here, which are tested on any OS.

use crate::fixes::Row;
use crate::model::{Finding, Severity};

/// BitLocker's state on one drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protection {
    /// Encrypted and protected: a firmware change will ask for the key.
    On,
    /// Encrypted, protection suspended.
    Suspended,
    /// Not encrypted.
    Off,
    /// Encrypting or decrypting right now.
    Changing,
    /// Couldn't be read, and why.
    Unknown(String),
}

/// Reports the system drive's state, changing nothing. The BitLocker module
/// answers when ITriage is elevated; otherwise Explorer's own property is
/// read, which a standard user may see.
pub const STATUS: &str = r#"
$ErrorActionPreference = 'Stop'
$drive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive
$state = 'unknown'
$detail = ''
try {
  $v = Get-BitLockerVolume -MountPoint $drive
  $p = [string]$v.ProtectionStatus
  $s = [string]$v.VolumeStatus
  if ($p -eq 'On') { $state = 'on' }
  elseif ($s -eq 'FullyDecrypted') { $state = 'off' }
  elseif ($s -eq 'FullyEncrypted') { $state = 'suspended' }
  else { $state = 'changing' }
  $detail = $s + ' / ' + [string]$v.EncryptionMethod
} catch {
  try {
    $code = [int](New-Object -ComObject Shell.Application).NameSpace($drive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
    if ($code -eq 1 -or $code -eq 6) { $state = 'on' }
    elseif ($code -eq 2) { $state = 'off' }
    elseif ($code -eq 5) { $state = 'suspended' }
    elseif ($code -eq 3 -or $code -eq 4) { $state = 'changing' }
    else { $detail = 'Windows reports protection state ' + $code }
  } catch { $detail = $_.Exception.Message }
}
'ITRIAGE-ROWS ' + (ConvertTo-Json -InputObject @([pscustomobject]@{ Item = $drive; Status = $state; Detail = $detail }) -Compress)
"#;

/// Suspends protection on the system drive until the next restart, when
/// it's on. Reports `Changed`, `Already` (nothing to do), `Skipped` (no
/// BitLocker on this edition) or `Failed`.
pub const SUSPEND: &str = r#"
$ErrorActionPreference = 'Stop'
$drive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive
$row = $null
if (-not (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
  $row = [pscustomobject]@{ Item = $drive; Status = 'Skipped'; Detail = 'this edition of Windows has no BitLocker to suspend' }
} else {
  try {
    $v = Get-BitLockerVolume -MountPoint $drive
    if ([string]$v.ProtectionStatus -eq 'On') {
      Suspend-BitLocker -MountPoint $drive -RebootCount 1 | Out-Null
      $after = Get-BitLockerVolume -MountPoint $drive
      if ([string]$after.ProtectionStatus -eq 'On') { throw 'Protection is still on after suspending it.' }
      $row = [pscustomobject]@{ Item = $drive; Status = 'Changed'; Detail = 'protection suspended until the next restart' }
    } elseif ([string]$v.VolumeStatus -eq 'FullyDecrypted') {
      $row = [pscustomobject]@{ Item = $drive; Status = 'Already'; Detail = 'not encrypted, so there is nothing to suspend' }
    } else {
      $row = [pscustomobject]@{ Item = $drive; Status = 'Already'; Detail = 'protection is already off or suspended' }
    }
  } catch { $row = [pscustomobject]@{ Item = $drive; Status = 'Failed'; Detail = $_.Exception.Message } }
}
'ITRIAGE-ROWS ' + (ConvertTo-Json -InputObject @($row) -Compress)
"#;

/// What [`STATUS`] printed, as a drive and its state.
pub fn read_status(rows: Option<&[Row]>) -> (String, Protection) {
    let Some(row) = rows.and_then(|r| r.first()) else {
        return (String::new(), Protection::Unknown("PowerShell gave no answer".into()));
    };
    let state = match row.status.as_str() {
        "on" => Protection::On,
        "off" => Protection::Off,
        "suspended" => Protection::Suspended,
        "changing" => Protection::Changing,
        _ => Protection::Unknown(if row.detail.trim().is_empty() {
            "Windows wouldn't say (it needs administrator rights on some PCs)".into()
        } else {
            row.detail.trim().to_string()
        }),
    };
    (row.item.clone(), state)
}

/// What suspending did, and whether a firmware update may go ahead.
#[derive(Debug, Clone)]
pub struct Suspended {
    pub finding: Finding,
    /// False only when protection is on and couldn't be suspended.
    pub safe_to_flash: bool,
}

/// What [`SUSPEND`] printed, as the row for the report.
pub fn read_suspend(rows: Option<&[Row]>) -> Suspended {
    const LABEL: &str = "BitLocker";
    let Some(row) = rows.and_then(|r| r.first()) else {
        // No answer at all: nothing says protection is on, so don't block
        // the update, but say it wasn't checked.
        return Suspended {
            finding: Finding::info(LABEL, "couldn't be checked: PowerShell gave no answer"),
            safe_to_flash: true,
        };
    };
    // The drive already ends in a colon ("C:").
    let on = if row.item.is_empty() { String::new() } else { format!("{} ", row.item) };
    let (severity, safe) = match row.status.as_str() {
        "Changed" | "Already" => (Severity::Ok, true),
        "Skipped" => (Severity::Info, true),
        _ => (Severity::Critical, false),
    };
    let mut finding = Finding::new(LABEL, format!("{on}{}", row.detail), severity);
    if !safe {
        finding = finding.with_detail(
            "Nothing was installed. With protection on, a BIOS or firmware update makes the next start-up ask for the \
             BitLocker recovery key. Suspend BitLocker by hand, or have the key ready and set [updates] \
             suspend_bitlocker = false in the site profile, then run this again.",
        );
    }
    Suspended { finding, safe_to_flash: safe }
}

/// The preview's line: what a real run would do about BitLocker.
pub fn would_suspend(drive: &str, state: &Protection) -> Finding {
    let on = if drive.is_empty() { String::new() } else { format!("{drive} ") };
    match state {
        Protection::On => Finding::info("Would suspend BitLocker", format!("{on}protection is on; it would be suspended until the next restart")),
        Protection::Suspended => Finding::info("BitLocker", format!("{on}protection is already suspended")),
        Protection::Off => Finding::info("BitLocker", format!("{on}not encrypted")),
        Protection::Changing => Finding::warn("BitLocker", format!("{on}encrypting or decrypting right now: let that finish first")),
        Protection::Unknown(why) => Finding::info("BitLocker", format!("{on}state not readable ({why}); a real run checks again as administrator")),
    }
}

#[cfg(windows)]
pub fn status(ctx: &crate::module::RunContext) -> (String, Protection) {
    match crate::win::ps::run(STATUS, ctx, std::time::Duration::from_secs(60)) {
        Ok(out) => read_status(crate::fixes::rows(&out.stdout).as_deref()),
        Err(e) => (String::new(), Protection::Unknown(e)),
    }
}

#[cfg(windows)]
pub fn suspend(ctx: &crate::module::RunContext) -> Suspended {
    match crate::win::ps::run(SUSPEND, ctx, std::time::Duration::from_secs(120)) {
        Ok(out) => read_suspend(crate::fixes::rows(&out.stdout).as_deref()),
        Err(e) => Suspended { finding: Finding::info("BitLocker", format!("couldn't be checked: {e}")), safe_to_flash: true },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(json: &str) -> Vec<Row> {
        crate::fixes::rows(&format!("noise\nITRIAGE-ROWS {json}\n")).unwrap()
    }

    #[test]
    fn reads_the_state() {
        let on = rows(r#"[{"Item":"C:","Status":"on","Detail":"FullyEncrypted / XtsAes256"}]"#);
        assert_eq!(read_status(Some(&on)), ("C:".into(), Protection::On));
        let off = rows(r#"[{"Item":"C:","Status":"off","Detail":""}]"#);
        assert_eq!(read_status(Some(&off)).1, Protection::Off);
        let unknown = rows(r#"[{"Item":"C:","Status":"unknown","Detail":"Access denied"}]"#);
        assert_eq!(read_status(Some(&unknown)).1, Protection::Unknown("Access denied".into()));
        assert!(matches!(read_status(None).1, Protection::Unknown(_)));
        assert_eq!(would_suspend("C:", &Protection::On).label, "Would suspend BitLocker");
        assert_eq!(would_suspend("C:", &Protection::Changing).severity, Severity::Warning);
    }

    #[test]
    fn only_a_failed_suspend_stops_the_update() {
        let done = read_suspend(Some(&rows(r#"[{"Item":"C:","Status":"Changed","Detail":"protection suspended until the next restart"}]"#)));
        assert!(done.safe_to_flash);
        assert_eq!(done.finding.value, "C: protection suspended until the next restart");
        assert!(read_suspend(Some(&rows(r#"[{"Item":"C:","Status":"Already","Detail":"not encrypted, so there is nothing to suspend"}]"#))).safe_to_flash);
        assert!(read_suspend(Some(&rows(r#"[{"Item":"C:","Status":"Skipped","Detail":"this edition of Windows has no BitLocker to suspend"}]"#))).safe_to_flash);
        let failed = read_suspend(Some(&rows(r#"[{"Item":"C:","Status":"Failed","Detail":"Access is denied."}]"#)));
        assert!(!failed.safe_to_flash);
        assert_eq!(failed.finding.severity, Severity::Critical);
        assert!(failed.finding.detail.unwrap().contains("recovery key"));
        assert!(read_suspend(None).safe_to_flash, "no answer isn't evidence that protection is on");
    }
}
