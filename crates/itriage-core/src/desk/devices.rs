//! Devices & peripherals. Read-only.
//!
//! Windows: every present device with a Device Manager problem code, the
//! peripherals a clinical workstation leans on (microphones for dictation,
//! cameras, smart-card and badge readers), and the site profile's required
//! devices, and USB power saving (selective suspend in the power plan and
//! each required device's own settings), the usual reason a scanner or
//! badge reader drops out after sitting idle. Linux: USB peripherals and the
//! profile's required devices.

use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
use crate::profile::DeviceReq;

pub struct Devices;

impl TriageModule for Devices {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Devices with driver problems (the Code 43s), microphones, cameras and card readers, plus devices the site profile requires."
        } else {
            "USB peripherals, plus devices the site profile requires."
        };
        ModuleInfo::new("desk.devices", "Devices & peripherals", Category::Workstation, description)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::check(ctx.profile())
    }
}

/// A required device on USB: its label, its name, and its own power values.
pub type DevicePower = (String, String, Vec<(String, u32)>);

/// USB power saving as Windows has it. Plain data, so the rows are tested
/// on any OS.
#[derive(Debug, Clone, Default)]
pub struct UsbPower {
    /// Selective suspend in the active power plan: plugged in, on battery.
    pub ac: Option<u32>,
    pub dc: Option<u32>,
    pub by_policy: bool,
    /// Required devices found on USB: label, device name, its own values.
    pub devices: Vec<DevicePower>,
    /// The profile lists `keep-usb-awake` (an opt-in fix).
    pub fix_allowed: bool,
}

fn on_off(v: u32) -> &'static str {
    if v == 0 {
        "off"
    } else {
        "on"
    }
}

pub fn usb_power_findings(p: &UsbPower, saved: Option<&crate::fixes::usbpower::Saved>) -> Vec<Finding> {
    let mut out = Vec::new();
    if p.ac.is_some() || p.dc.is_some() {
        let side = |v: Option<u32>, when: &str| v.map(|v| format!("{} {when}", on_off(v)));
        let words = [side(p.ac, "plugged in"), side(p.dc, "on battery")].into_iter().flatten().collect::<Vec<_>>().join(" · ");
        let on = p.ac == Some(1) || p.dc == Some(1);
        let mut detail = String::from("Windows powers down an idle USB device to save energy. When a scanner or badge reader stops responding after sitting idle and works again once replugged, this is the usual cause; a Record capture marks each drop.");
        if p.by_policy {
            detail.push_str(" A policy (Group Policy or MDM) sets this value, so change it there.");
        }
        let mut row = Finding::info("USB selective suspend", words).with_detail(detail);
        if on && p.fix_allowed && !p.by_policy && saved.is_none() {
            row = row.with_action(crate::actions::offer("keep-usb-awake", None));
        }
        out.push(row);
    }
    for (label, name, values) in &p.devices {
        if values.is_empty() {
            continue;
        }
        let words: Vec<String> = values
            .iter()
            .map(|(k, v)| {
                let what = match k.as_str() {
                    "SelectiveSuspendEnabled" => "selective suspend",
                    "EnhancedPowerManagementEnabled" => "enhanced power management",
                    "AllowIdleIrpInD3" => "idle power-down (D3)",
                    other => other,
                };
                format!("{what} {}", on_off(*v))
            })
            .collect();
        out.push(Finding::info(format!("{label}: USB power"), words.join(" · ")).with_detail(format!("{name}'s own settings, from its driver (Device Parameters).")));
    }
    if let Some(saved) = saved {
        out.push(crate::fixes::usbpower::offer_finding(saved));
    }
    out
}

/// Profile requirements matched against device names (case-insensitive substring).
fn required(reqs: &[DeviceReq], names: &[String]) -> Vec<Finding> {
    reqs.iter()
        .map(|r| {
            let want = r.pattern.to_lowercase();
            match names.iter().find(|n| n.to_lowercase().contains(&want)) {
                Some(n) => Finding::ok(r.label.clone(), format!("detected: {n}")),
                None => Finding::warn(r.label.clone(), "not detected").with_detail(
                    "Check the cable and try another USB port. A docking station may need reconnecting.",
                ),
            }
        })
        .collect()
}

/// "a, b, c +2 more"
fn list(names: &[String], max: usize) -> String {
    let mut s = names.iter().take(max).cloned().collect::<Vec<_>>().join(", ");
    if names.len() > max {
        s.push_str(&format!(" +{} more", names.len() - max));
    }
    s
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::model::Severity;
    use crate::parse::devices::{problem_severity, problem_text};
    use crate::util::plural;
    use crate::win::devices::present;

    pub fn check(profile: &crate::profile::Profile) -> Result<Output, String> {
        let reqs = &profile.require.device;
        let devices = present()?;
        let mut findings = Vec::new();

        let mut faulty: Vec<_> = devices.iter().filter_map(|d| d.problem.map(|code| (d, code))).collect();
        faulty.sort_by_key(|(_, code)| std::cmp::Reverse(problem_severity(*code).rank()));
        let broken = faulty
            .iter()
            .filter(|(_, code)| problem_severity(*code).rank() >= Severity::Warning.rank())
            .count();
        for (d, code) in &faulty {
            let name = if d.name.is_empty() { "Unnamed device" } else { d.name.as_str() };
            let label = if d.class.is_empty() { name.to_string() } else { format!("{name} ({})", d.class) };
            findings.push(Finding::new(label, format!("Code {code}: {}", problem_text(*code)), problem_severity(*code)));
        }

        let names: Vec<String> = devices.iter().map(|d| d.name.clone()).collect();
        findings.extend(required(reqs, &names));

        let working = |pred: &dyn Fn(&crate::win::devices::Device) -> bool| -> Vec<String> {
            let mut v: Vec<String> = devices
                .iter()
                .filter(|d| d.problem.is_none() && pred(d))
                .map(|d| d.name.clone())
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let mics = working(&|d| d.class.eq_ignore_ascii_case("AudioEndpoint") && d.name.to_lowercase().contains("microphone"));
        let cameras = working(&|d| d.class.eq_ignore_ascii_case("Camera") || d.class.eq_ignore_ascii_case("Image"));
        let readers = working(&|d| d.class.eq_ignore_ascii_case("SmartCardReader"));
        for (label, found) in [("Microphones", mics), ("Cameras", cameras), ("Smart card readers", readers)] {
            if !found.is_empty() {
                findings.push(Finding::info(label, list(&found, 4)));
            }
        }

        let mut power = UsbPower { fix_allowed: profile.fix_allowed("keep-usb-awake", None), ..UsbPower::default() };
        if let Ok(suspend) = crate::win::usbpower::selective_suspend() {
            (power.ac, power.dc) = (suspend.ac, suspend.dc);
            power.by_policy = crate::win::usbpower::set_by_policy();
        }
        for r in reqs {
            let want = r.pattern.to_lowercase();
            if want.trim().is_empty() {
                continue;
            }
            if let Some(d) = devices.iter().find(|d| d.name.to_lowercase().contains(&want) && d.usb.is_some()) {
                let values = crate::win::usbpower::device_values(d.usb.as_deref().unwrap_or_default());
                power.devices.push((r.label.clone(), d.name.clone(), values));
            }
        }
        findings.extend(usb_power_findings(&power, crate::fixes::usbpower::load().as_ref()));

        let summary = if broken == 0 {
            format!("{} devices, none reporting problems", devices.len())
        } else {
            format!("{} devices · {broken} with driver problem{}", devices.len(), plural(broken))
        };
        if findings.is_empty() {
            findings.push(Finding::ok("Device Manager", "no problems reported"));
        }
        Ok(Output::new(summary, findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::path::Path;

    /// USB device names from sysfs, skipping hubs and host controllers.
    fn usb_devices() -> Vec<String> {
        let mut out: Vec<String> = usb_devices_with_paths().into_iter().map(|(_, name)| name).collect();
        out.sort();
        out.dedup();
        out
    }

    /// The same, each with its device path as kernel uevents name it
    /// (`/devices/pci0000:00/…/usb1/1-2`), for the recording's drop watch.
    pub fn usb_devices_with_paths() -> Vec<(String, String)> {
        let read = |dir: &Path, f: &str| {
            std::fs::read_to_string(dir.join(f))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") else { return out };
        for e in entries.flatten() {
            let dir = e.path();
            if read(&dir, "bDeviceClass").as_deref() == Some("09") {
                continue; // hub
            }
            let Some(product) = read(&dir, "product") else { continue };
            if product.to_lowercase().contains("host controller") {
                continue;
            }
            let name = match read(&dir, "manufacturer") {
                Some(m) if !product.to_lowercase().contains(&m.to_lowercase()) => format!("{m} {product}"),
                _ => product,
            };
            let path = std::fs::canonicalize(&dir)
                .ok()
                .and_then(|p| p.to_str().and_then(|p| p.strip_prefix("/sys")).map(str::to_string))
                .unwrap_or_else(|| dir.display().to_string());
            out.push((path, name));
        }
        out
    }

    pub fn check(profile: &crate::profile::Profile) -> Result<Output, String> {
        let reqs = &profile.require.device;
        let usb = usb_devices();
        let mut findings = required(reqs, &usb);
        if usb.is_empty() {
            findings.push(Finding::info("USB peripherals", "none found"));
        } else {
            findings.push(Finding::info("USB peripherals", list(&usb, 8)));
        }
        let summary = format!("{} USB peripheral{}", usb.len(), crate::util::plural(usb.len()));
        Ok(Output::new(summary, findings))
    }
}

#[cfg(not(windows))]
pub use imp::usb_devices_with_paths;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_required_devices() {
        let reqs = vec![
            DeviceReq { label: "Badge reader".into(), pattern: "pcprox".into() },
            DeviceReq { label: "Dictation mic".into(), pattern: "PowerMic".into() },
        ];
        let names = vec!["RFIDeas pcProx USB".to_string(), "HID Keyboard Device".to_string()];
        let f = required(&reqs, &names);
        assert_eq!(f[0].severity, crate::model::Severity::Ok);
        assert_eq!(f[1].severity, crate::model::Severity::Warning);
        assert_eq!(list(&["a".into(), "b".into(), "c".into()], 2), "a, b +1 more");
    }

    #[test]
    fn usb_power_rows_and_the_opt_in_fix() {
        let p = UsbPower {
            ac: Some(1),
            dc: Some(0),
            devices: vec![
                ("Scanner".into(), "Honeywell Xenon 1950g".into(), vec![("SelectiveSuspendEnabled".into(), 1), ("AllowIdleIrpInD3".into(), 1)]),
                ("Badge reader".into(), "RFIDeas pcProx USB".into(), vec![]),
            ],
            ..UsbPower::default()
        };
        let rows = usb_power_findings(&p, None);
        assert_eq!(rows[0].value, "on plugged in · off on battery");
        assert!(rows[0].action.is_none(), "not offered unless the profile lists it");
        assert_eq!(rows[1].label, "Scanner: USB power");
        assert_eq!(rows[1].value, "selective suspend on · idle power-down (D3) on");
        assert_eq!(rows.len(), 2, "a device with no values of its own adds no row");

        let allowed = usb_power_findings(&UsbPower { fix_allowed: true, ..p.clone() }, None);
        assert_eq!(allowed[0].action.as_ref().unwrap().id, "keep-usb-awake");
        let by_policy = usb_power_findings(&UsbPower { fix_allowed: true, by_policy: true, ..p.clone() }, None);
        assert!(by_policy[0].action.is_none() && by_policy[0].detail.as_deref().unwrap().contains("policy"));
        let off = usb_power_findings(&UsbPower { fix_allowed: true, ac: Some(0), dc: Some(0), ..p.clone() }, None);
        assert!(off[0].action.is_none(), "nothing to turn off");

        let saved = crate::fixes::usbpower::Saved { saved: "2026-11-12T20:00:00Z".into(), tool_version: "0.10.0".into(), scheme: "381b4222-f694-41f0-9685-ff5bb260df2e".into(), ac: 1, dc: 1 };
        let undo = usb_power_findings(&UsbPower { fix_allowed: true, ac: Some(0), dc: Some(0), ..p }, Some(&saved));
        assert_eq!(undo.last().unwrap().action.as_ref().unwrap().id, "restore-usb-power");
    }
}
