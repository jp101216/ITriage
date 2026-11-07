//! Devices & peripherals. Read-only.
//!
//! Windows: every present device with a Device Manager problem code, the
//! peripherals a clinical workstation leans on (microphones for dictation,
//! cameras, smart-card and badge readers), and the site profile's required
//! devices. Linux: USB peripherals and the profile's required devices.

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
        imp::check(&ctx.profile().require.device)
    }
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

    pub fn check(reqs: &[DeviceReq]) -> Result<Output, String> {
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

    /// USB devices from sysfs, skipping hubs and host controllers.
    fn usb_devices() -> Vec<String> {
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
            out.push(name);
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn check(reqs: &[DeviceReq]) -> Result<Output, String> {
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
}
