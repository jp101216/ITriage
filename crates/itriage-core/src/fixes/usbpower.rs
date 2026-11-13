//! `keep-usb-awake` and its undo, `restore-usb-power`.
//!
//! Turning USB selective suspend off in the active power plan stops Windows
//! powering down an idle USB device: the barcode scanner or badge reader
//! that "drops out" after sitting unused. It's an opt-in fix (the site
//! profile's `fixes` list has to name it), because it costs some battery.
//!
//! Before it changes anything, what the plan had is saved, the way the
//! tune-up's undo works; `restore-usb-power` puts it back. The saved file is
//! read back as data and checked: a plan GUID and values of 0 or 1 only.

use crate::model::Finding;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Saved {
    pub saved: String,
    pub tool_version: String,
    /// The power plan's GUID, `xxxxxxxx-xxxx-…`.
    pub scheme: String,
    pub ac: u32,
    pub dc: u32,
}

impl Saved {
    /// Only a plan GUID and on/off values are acted on.
    pub fn valid(&self) -> bool {
        crate::actions::valid_update_id(self.scheme.trim_matches(['{', '}'])) && self.ac <= 1 && self.dc <= 1
    }

    pub fn describe(&self) -> String {
        let word = |v: u32| if v == 1 { "on" } else { "off" };
        format!("selective suspend {} plugged in, {} on battery", word(self.ac), word(self.dc))
    }
}

fn file() -> Option<PathBuf> {
    crate::paths::state_dir().map(|d| d.join("undo-usb-power.json"))
}

pub fn load() -> Option<Saved> {
    load_from(&file()?)
}

fn load_from(path: &std::path::Path) -> Option<Saved> {
    serde_json::from_str::<Saved>(&std::fs::read_to_string(path).ok()?).ok().filter(Saved::valid)
}

/// Keep what the plan had, unless something is already saved: running the
/// fix twice mustn't replace the real "before" with the result of the first.
#[cfg_attr(not(windows), allow(dead_code))]
fn remember_in(path: &std::path::Path, scheme: &str, ac: u32, dc: u32) -> Result<Saved, String> {
    if let Some(saved) = load_from(path) {
        return Ok(saved);
    }
    let saved = Saved {
        saved: crate::parse::time::epoch_to_rfc3339(crate::util::now_epoch()),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        scheme: scheme.to_string(),
        ac,
        dc,
    };
    if !saved.valid() {
        return Err("The power plan's settings couldn't be read in a form that can be put back, so nothing was changed.".into());
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let text = serde_json::to_string_pretty(&saved).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("Couldn't save the current settings to put back later ({e}), so nothing was changed."))?;
    Ok(saved)
}

/// The row that offers putting the saved settings back.
pub fn offer_finding(saved: &Saved) -> Finding {
    Finding::info("USB power undo", format!("the settings from {} are saved", saved.saved.replace('T', " ").replace('Z', " UTC")))
        .with_detail(format!("Restore would set {} in the power plan they came from.", saved.describe()))
        .with_action(crate::actions::offer("restore-usb-power", None))
}

#[cfg(windows)]
pub use imp::{keep_awake, preview, restore};

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::win::usbpower::{guid_text, selective_suspend, set_by_policy, set_selective_suspend};

    fn guid(text: &str) -> Option<windows::core::GUID> {
        let hex: String = text.trim_matches(['{', '}']).chars().filter(|c| *c != '-').collect();
        (hex.len() == 32).then(|| u128::from_str_radix(&hex, 16).ok()).flatten().map(windows::core::GUID::from_u128)
    }

    pub fn preview() -> String {
        match selective_suspend() {
            Err(e) => format!("couldn't read the power plan ({e}). Nothing was changed."),
            Ok(s) => {
                let word = |v: Option<u32>| match v {
                    Some(1) => "on",
                    Some(0) => "off",
                    _ => "unknown",
                };
                let policy = if set_by_policy() { " A policy sets this value, so Windows would put it back." } else { "" };
                format!(
                    "would turn USB selective suspend off in the active power plan (now {} plugged in, {} on battery) and save those values for Restore USB power.{policy} Nothing was changed.",
                    word(s.ac),
                    word(s.dc)
                )
            }
        }
    }

    pub fn keep_awake() -> Result<String, String> {
        crate::util::require_admin()?;
        if set_by_policy() {
            return Err("USB selective suspend is set by Group Policy or MDM on this PC, so a change here would be undone. Change it in the policy instead.".into());
        }
        let now = selective_suspend()?;
        if now.ac == Some(0) && now.dc == Some(0) {
            return Ok("USB selective suspend is already off in the active power plan. Nothing was changed.".into());
        }
        let path = file().ok_or("There's no place to keep undo information on this system.")?;
        let saved = remember_in(&path, &guid_text(&now.scheme), now.ac.unwrap_or(1), now.dc.unwrap_or(1))?;
        set_selective_suspend(&now.scheme, 0, 0)?;
        let after = selective_suspend()?;
        if after.ac != Some(0) || after.dc != Some(0) {
            return Err("The power plan didn't keep the change; a power policy may be resetting it.".into());
        }
        Ok(format!(
            "Turned USB selective suspend off in the active power plan (it was {}). USB devices stay powered while idle; Restore USB power puts the old settings back.",
            saved.describe()
        ))
    }

    pub fn restore() -> Result<String, String> {
        crate::util::require_admin()?;
        let path = file().ok_or("There's no place to keep undo information on this system.")?;
        let saved = load_from(&path).ok_or("Nothing to restore: Keep USB devices awake hasn't changed this PC's power plan.")?;
        let scheme = guid(&saved.scheme).ok_or("The saved power plan isn't a valid identifier.")?;
        set_selective_suspend(&scheme, saved.ac, saved.dc)?;
        let _ = std::fs::remove_file(&path);
        Ok(format!("Put back {} in the power plan.", saved.describe()))
    }
}

#[cfg(not(windows))]
pub fn keep_awake() -> Result<String, String> {
    Err("Keep USB devices awake changes a Windows power plan. On Linux, USB autosuspend is a kernel setting (usbcore.autosuspend).".into())
}

#[cfg(not(windows))]
pub fn restore() -> Result<String, String> {
    Err("There's no Windows power plan to restore here.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_plan_guid_and_on_off_values_are_kept() {
        let dir = std::env::temp_dir().join(format!("itriage-usb-undo-{}", std::process::id()));
        let path = dir.join("undo-usb-power.json");
        let _ = std::fs::remove_file(&path);
        let first = remember_in(&path, "381b4222-f694-41f0-9685-ff5bb260df2e", 1, 1).unwrap();
        assert_eq!(first.describe(), "selective suspend on plugged in, on on battery");
        let second = remember_in(&path, "381b4222-f694-41f0-9685-ff5bb260df2e", 0, 0).unwrap();
        assert_eq!(second, first, "a second run keeps the first before");
        assert_eq!(offer_finding(&first).action.unwrap().id, "restore-usb-power");

        std::fs::write(&path, r#"{"saved":"x","tool_version":"0","scheme":"381b4222-f694-41f0-9685-ff5bb260df2e & calc","ac":1,"dc":1}"#).unwrap();
        assert!(load_from(&path).is_none(), "a tampered plan id isn't acted on");
        std::fs::write(&path, r#"{"saved":"x","tool_version":"0","scheme":"381b4222-f694-41f0-9685-ff5bb260df2e","ac":7,"dc":1}"#).unwrap();
        assert!(load_from(&path).is_none(), "nor a value that isn't on or off");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(remember_in(&path, "not a guid", 1, 1).is_err());
    }
}
