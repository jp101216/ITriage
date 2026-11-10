//! Undo for the tune-up's TCP and adapter power step (`fix.tcp`).
//!
//! That step changes two settings that stay changed: TCP receive
//! autotuning (set to normal) and each adapter's sleep settings (turned
//! off). Before it changes them, what they were is saved here; the
//! `revert-tuneup` fix puts them back.
//!
//! The rest of the tune-up has nothing to put back: flushed caches refill
//! by themselves, and a network stack reset can't be undone, which is why
//! that step refuses to run when it would lose a static address.
//!
//! The saved file is read back as data and checked before anything acts on
//! it: the autotuning level must be one of Windows' five, and an adapter
//! name can't be a wildcard. The script that restores adapter settings is
//! fixed text; the names reach it through an environment variable.

use crate::model::Finding;
use crate::parse::psjson::{list, or_default};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What `fix.tcp` is about to change, as it stands now.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const TUNING_READ: &str = r#"
$ErrorActionPreference = 'Stop'
$level = ''
try { $level = [string](Get-NetTCPSetting -SettingName Internet).AutoTuningLevelLocal } catch {}
if (-not $level) { try { $level = [string](Get-NetTCPSetting | Where-Object { $_.AutoTuningLevelLocal } | Select-Object -First 1).AutoTuningLevelLocal } catch {} }
$adapters = @()
foreach ($a in @(Get-NetAdapter -Physical)) {
  try {
    $pm = Get-NetAdapterPowerManagement -Name $a.Name
    $adapters += [pscustomobject]@{ Name = [string]$a.Name; DeviceSleepOnDisconnect = [string]$pm.DeviceSleepOnDisconnect; SelectiveSuspend = [string]$pm.SelectiveSuspend }
  } catch {}
}
Send-ITriage ([pscustomobject]@{ AutoTuning = $level; Adapters = $adapters })
"#;

/// Turns back on the adapter sleep settings named in `$env:ITRIAGE_UNDO`
/// (JSON, checked before it gets here), with the adapter restart deferred.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const ADAPTERS_RESTORE: &str = r#"
$ErrorActionPreference = 'Stop'
$rows = @()
$want = ConvertFrom-Json -InputObject $env:ITRIAGE_UNDO
foreach ($w in @($want.Adapters)) {
  $name = [string]$w.Name
  try {
    $pm = Get-NetAdapterPowerManagement -Name $name
    $changes = @{}
    foreach ($p in 'DeviceSleepOnDisconnect', 'SelectiveSuspend') {
      if ($w.$p -eq $true -and [string]$pm.$p -in @('Disabled', '1')) { $changes[$p] = $true }
    }
    if ($changes.Count -gt 0) {
      Enable-NetAdapterPowerManagement -InputObject $pm @changes -NoRestart -Confirm:$false | Out-Null
      $verified = Get-NetAdapterPowerManagement -Name $name
      foreach ($p in $changes.Keys) { if ([string]$verified.$p -notin @('Enabled', '2')) { throw "The $p setting could not be verified." } }
      $rows += [pscustomobject]@{ Item = $name; Status = 'Changed'; Detail = (($changes.Keys) -join ', ') + ' turned back on (applies at the next adapter restart)' }
    } else { $rows += [pscustomobject]@{ Item = $name; Status = 'Already'; Detail = 'already as it was' } }
  } catch { $rows += [pscustomobject]@{ Item = $name; Status = 'Failed'; Detail = $_.Exception.Message } }
}
'ITRIAGE-ROWS ' + (ConvertTo-Json -InputObject @($rows) -Compress)
"#;

/// The settings `fix.tcp` changes, as PowerShell reports them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Tuning {
    /// Normal, Disabled, Restricted, HighlyRestricted or Experimental.
    #[serde(deserialize_with = "or_default")]
    pub auto_tuning: String,
    #[serde(deserialize_with = "list")]
    pub adapters: Vec<AdapterPower>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct AdapterPower {
    #[serde(deserialize_with = "or_default")]
    pub name: String,
    /// Enabled, Disabled or Unsupported.
    #[serde(deserialize_with = "or_default")]
    pub device_sleep_on_disconnect: String,
    #[serde(deserialize_with = "or_default")]
    pub selective_suspend: String,
}

/// A [`Tuning`] with when it was saved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// RFC 3339 UTC.
    pub saved: String,
    #[serde(default)]
    pub tool_version: String,
    pub before: Tuning,
}

fn on(setting: &str) -> bool {
    matches!(setting.trim().to_ascii_lowercase().as_str(), "enabled" | "2")
}

/// The word netsh takes for an autotuning level, if it's one Windows has.
pub fn netsh_level(level: &str) -> Option<&'static str> {
    match level.trim().to_ascii_lowercase().as_str() {
        "normal" => Some("normal"),
        "disabled" => Some("disabled"),
        "restricted" => Some("restricted"),
        "highlyrestricted" => Some("highlyrestricted"),
        "experimental" => Some("experimental"),
        _ => None,
    }
}

/// An adapter name that names one adapter: no wildcards, no control characters.
pub fn valid_adapter_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 256 && !name.chars().any(|c| c.is_control() || "*?[]`$\"'".contains(c))
}

impl Tuning {
    /// Would `fix.tcp` change anything from here?
    pub fn would_change(&self) -> bool {
        netsh_level(&self.auto_tuning).is_some_and(|l| l != "normal")
            || self.adapters.iter().any(|a| on(&a.device_sleep_on_disconnect) || on(&a.selective_suspend))
    }

    /// The autotuning level to put back, when it wasn't already normal.
    pub fn level_to_restore(&self) -> Option<&'static str> {
        netsh_level(&self.auto_tuning).filter(|l| *l != "normal")
    }

    /// The adapters with a sleep setting to turn back on, as the JSON the
    /// restore script reads. `None` when there are none.
    pub fn adapters_to_restore(&self) -> Option<String> {
        let adapters: Vec<serde_json::Value> = self
            .adapters
            .iter()
            .filter(|a| valid_adapter_name(&a.name) && (on(&a.device_sleep_on_disconnect) || on(&a.selective_suspend)))
            .map(|a| {
                serde_json::json!({
                    "Name": a.name,
                    "DeviceSleepOnDisconnect": on(&a.device_sleep_on_disconnect),
                    "SelectiveSuspend": on(&a.selective_suspend),
                })
            })
            .collect();
        (!adapters.is_empty()).then(|| serde_json::json!({ "Adapters": adapters }).to_string())
    }

    /// What it would put back, in words.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(level) = self.level_to_restore() {
            parts.push(format!("TCP receive autotuning to {level}"));
        }
        for a in self.adapters.iter().filter(|a| valid_adapter_name(&a.name)) {
            let settings: Vec<&str> = [("DeviceSleepOnDisconnect", &a.device_sleep_on_disconnect), ("SelectiveSuspend", &a.selective_suspend)]
                .into_iter()
                .filter(|(_, v)| on(v))
                .map(|(name, _)| name)
                .collect();
            if !settings.is_empty() {
                parts.push(format!("{} on {}", settings.join(" and "), a.name));
            }
        }
        parts.join("; ")
    }
}

fn file() -> Option<PathBuf> {
    crate::paths::state_dir().map(|d| d.join("undo-tuneup.json"))
}

pub fn load() -> Option<Snapshot> {
    load_from(&file()?)
}

fn load_from(path: &std::path::Path) -> Option<Snapshot> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Keep `before` as what to go back to, unless it's the already-tuned
/// state: running the tune-up twice mustn't replace the real "before" with
/// the result of the first run. Returns what is now saved, if anything.
pub fn remember(before: &Tuning) -> Option<Snapshot> {
    remember_in(&file()?, before)
}

fn remember_in(path: &std::path::Path, before: &Tuning) -> Option<Snapshot> {
    if !before.would_change() {
        return load_from(path);
    }
    let snapshot = Snapshot {
        saved: crate::parse::time::epoch_to_rfc3339(crate::util::now_epoch()),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        before: before.clone(),
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(path, serde_json::to_string_pretty(&snapshot).ok()?).ok()?;
    Some(snapshot)
}

/// The row a `fix.tcp` card ends with when there's something to go back to.
pub fn offer_finding(snapshot: &Snapshot) -> Option<Finding> {
    let what = snapshot.before.describe();
    if what.is_empty() {
        return None;
    }
    Some(
        Finding::info("Undo", format!("the settings from {} are saved", snapshot.saved.replace('T', " ").replace('Z', " UTC")))
            .with_detail(format!("Revert would set {what}."))
            .with_action(crate::actions::offer("revert-tuneup", None)),
    )
}

/// Put back what the tune-up changed.
pub fn revert() -> Result<String, String> {
    imp::revert()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::fixes::{step, OnError};
    use crate::module::RunContext;
    use std::time::Duration;

    /// The settings as they are now. Used by `fix.tcp` before it changes them.
    pub fn read(ctx: &RunContext) -> Result<Tuning, String> {
        let out = crate::win::ps::run(TUNING_READ, ctx, Duration::from_secs(90))?;
        crate::fixes::json(&out.stdout)
    }

    pub fn revert() -> Result<String, String> {
        crate::util::require_admin()?;
        let path = file().ok_or("There's no place to keep undo information on this system.")?;
        let snapshot = load_from(&path).ok_or("Nothing to undo: no tune-up settings are saved for this account. They're saved the first time TCP autotuning & NIC power changes something.")?;
        let before = &snapshot.before;
        if before.describe().is_empty() {
            return Err("Nothing to undo: the saved settings are the same as the tuned ones.".into());
        }
        let ctx = RunContext::silent();
        let mut done = Vec::new();
        let mut failed = Vec::new();
        if let Some(level) = before.level_to_restore() {
            let arg = format!("autotuninglevel={level}");
            let s = step(&ctx, "TCP receive autotuning", "netsh", &["int", "tcp", "set", "global", &arg], &[0], OnError::Fail, Duration::from_secs(60));
            if s.ok {
                done.push(format!("TCP receive autotuning set back to {level}"));
            } else {
                failed.push(format!("TCP receive autotuning: {}", s.finding.value));
            }
        }
        if let Some(json) = before.adapters_to_restore() {
            match crate::win::ps::run_with(ADAPTERS_RESTORE, &[("ITRIAGE_UNDO", &json)], &ctx, Duration::from_secs(120)) {
                Ok(out) => match crate::fixes::rows(&out.stdout) {
                    Some(rows) => {
                        for r in rows {
                            match r.status.as_str() {
                                "Failed" => failed.push(format!("{}: {}", r.item, r.detail)),
                                _ => done.push(format!("{}: {}", r.item, r.detail)),
                            }
                        }
                    }
                    None => failed.push(format!("adapter settings: PowerShell gave no result ({})", crate::util::exit_label(out.code))),
                },
                Err(e) => failed.push(format!("adapter settings: {e}")),
            }
        }
        if failed.is_empty() {
            // Put back in full: there's nothing left to undo.
            let _ = std::fs::remove_file(&path);
            Ok(format!("Put back the settings from before the tune-up. {}.", done.join("; ")))
        } else {
            Err(format!(
                "Not everything could be put back. {}{}. The saved settings are kept, so this can be tried again.",
                if done.is_empty() { String::new() } else { format!("Done: {}. ", done.join("; ")) },
                format_args!("Failed: {}", failed.join("; "))
            ))
        }
    }
}

#[cfg(windows)]
pub use imp::read;

#[cfg(not(windows))]
mod imp {
    pub fn revert() -> Result<String, String> {
        Err("The tune-up's TCP and adapter power step is Windows-only, so there's nothing to put back here.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuning(json: &str) -> Tuning {
        serde_json::from_str(json).unwrap()
    }

    const BEFORE: &str = r#"{"AutoTuning":"Restricted","Adapters":[
        {"Name":"Ethernet","DeviceSleepOnDisconnect":"Enabled","SelectiveSuspend":"Disabled"},
        {"Name":"Wi-Fi","DeviceSleepOnDisconnect":"Unsupported","SelectiveSuspend":"Enabled"},
        {"Name":"Dock","DeviceSleepOnDisconnect":"Disabled","SelectiveSuspend":"Unsupported"}]}"#;
    const TUNED: &str = r#"{"AutoTuning":"Normal","Adapters":{"Name":"Ethernet","DeviceSleepOnDisconnect":"Disabled","SelectiveSuspend":"Disabled"}}"#;

    #[test]
    fn knows_what_to_put_back() {
        let before = tuning(BEFORE);
        assert!(before.would_change());
        assert_eq!(before.level_to_restore(), Some("restricted"));
        assert_eq!(before.describe(), "TCP receive autotuning to restricted; DeviceSleepOnDisconnect on Ethernet; SelectiveSuspend on Wi-Fi");
        let request: serde_json::Value = serde_json::from_str(&before.adapters_to_restore().unwrap()).unwrap();
        assert_eq!(
            request,
            serde_json::json!({ "Adapters": [
                { "Name": "Ethernet", "DeviceSleepOnDisconnect": true, "SelectiveSuspend": false },
                { "Name": "Wi-Fi", "DeviceSleepOnDisconnect": false, "SelectiveSuspend": true },
            ] }),
            "only adapters with something to turn back on"
        );
        let tuned = tuning(TUNED);
        assert!(!tuned.would_change() && tuned.level_to_restore().is_none() && tuned.adapters_to_restore().is_none());
        assert_eq!(tuned.describe(), "");
    }

    #[test]
    fn a_saved_file_cant_ask_for_anything_else() {
        assert_eq!(netsh_level("HighlyRestricted"), Some("highlyrestricted"));
        for bad in ["", "normal & calc", "max", "normal\n"] {
            assert!(netsh_level(bad).is_none() || bad == "normal\n", "{bad:?}");
        }
        assert_eq!(netsh_level("normal & calc"), None);
        assert!(valid_adapter_name("Ethernet 2") && valid_adapter_name("Wi-Fi") && valid_adapter_name("vEthernet (Default Switch)"));
        for bad in ["*", "Ether*", "Wi-Fi?", "[a-z]", "", "a\nb", "$(x)", "a`b", "a\"b"] {
            assert!(!valid_adapter_name(bad), "{bad:?}");
        }
        // A tampered snapshot: a made-up level and a wildcard adapter.
        let odd = tuning(r#"{"AutoTuning":"normal; shutdown /r","Adapters":[{"Name":"*","DeviceSleepOnDisconnect":"Enabled","SelectiveSuspend":"Enabled"}]}"#);
        assert_eq!(odd.level_to_restore(), None);
        assert_eq!(odd.adapters_to_restore(), None);
        assert_eq!(odd.describe(), "");
    }

    /// Read-only, so it runs for real wherever the tests do.
    #[cfg(windows)]
    #[test]
    fn reads_this_pcs_settings() {
        let now = read(&crate::module::RunContext::silent()).expect("the script answers");
        assert!(now.auto_tuning.is_empty() || netsh_level(&now.auto_tuning).is_some(), "an autotuning level Windows has: {now:?}");
        assert!(now.adapters.iter().all(|a| !a.name.is_empty()), "{now:?}");
        // Whatever it found, the request built from it is well-formed.
        if let Some(json) = now.adapters_to_restore() {
            assert!(serde_json::from_str::<serde_json::Value>(&json).unwrap()["Adapters"].is_array());
        }
    }

    #[test]
    fn a_second_tune_up_keeps_the_first_before() {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-undo-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("undo-tuneup.json");
        assert!(remember_in(&path, &tuning(TUNED)).is_none(), "nothing would change, and nothing was saved before");
        let first = remember_in(&path, &tuning(BEFORE)).expect("saved");
        assert_eq!(first.before.auto_tuning, "Restricted");
        // The tune-up runs again: the state is now the tuned one.
        let again = remember_in(&path, &tuning(TUNED)).expect("the earlier snapshot is still offered");
        assert_eq!(again, first);
        assert_eq!(load_from(&path).unwrap().before, tuning(BEFORE));
        let offer = offer_finding(&first).unwrap();
        assert_eq!(offer.action.as_ref().unwrap().id, "revert-tuneup");
        assert!(offer.detail.as_deref().unwrap().starts_with("Revert would set TCP receive autotuning to restricted"));
        assert!(offer_finding(&Snapshot { saved: String::new(), tool_version: String::new(), before: tuning(TUNED) }).is_none());
        std::fs::write(&path, "not json").unwrap();
        assert!(load_from(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
