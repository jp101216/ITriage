//! Battery health. Read-only.
//!
//! Charge and power source, then wear: how much of its design capacity each
//! battery still holds. Workstations on wheels and laptops that die mid-round
//! usually have a battery under about 60%.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::battery::Battery;

pub struct BatteryHealth;

impl TriageModule for BatteryHealth {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.battery",
            "Battery health",
            Category::Workstation,
            "Charge, power source, and battery wear (capacity left vs. design, cycle count). Flags batteries under 80%.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let (power, batteries, note) = imp::read(ctx)?;
        let Some(mut findings) = power else {
            return Ok(Output::new(
                "No battery (desktop or AC-only device)",
                vec![Finding::info("Battery", "none present")],
            ));
        };
        let mut worst: Option<f64> = None;
        for b in &batteries {
            findings.extend(battery_findings(b));
            if let Some(h) = b.health_pct() {
                worst = Some(worst.map_or(h, |w: f64| w.min(h)));
            }
        }
        if let Some(n) = note {
            findings.push(Finding::info("Wear report", n));
        }
        let summary = match worst {
            Some(h) if h < 60.0 => format!("Battery worn out: {h:.0}% of design capacity left"),
            Some(h) if h < 80.0 => format!("Battery wearing: {h:.0}% of design capacity left"),
            Some(h) => format!("Battery healthy ({h:.0}% of design capacity)"),
            None => "Battery present; wear not reported".to_string(),
        };
        Ok(Output::new(summary, findings))
    }
}

/// Health below 80% is worth planning a replacement; below 60% it won't
/// last a shift.
pub fn health_grade(pct: f64) -> Severity {
    if pct < 60.0 {
        Severity::Critical
    } else if pct < 80.0 {
        Severity::Warning
    } else {
        Severity::Ok
    }
}

fn battery_findings(b: &Battery) -> Vec<Finding> {
    let mut out = Vec::new();
    match b.health_pct() {
        Some(h) => {
            let mut f = Finding::new(
                format!("Health ({})", b.name),
                format!("{:.0}% of design · {}", h.min(100.0), b.capacity_text()),
                health_grade(h),
            );
            if h < 80.0 {
                f = f.with_detail("Plan a battery replacement; runtime is noticeably shorter than new.");
            }
            out.push(f);
        }
        None => out.push(Finding::info(format!("Health ({})", b.name), "capacity not reported")),
    }
    if let Some(c) = b.cycles {
        out.push(Finding::info(format!("Charge cycles ({})", b.name), c.to_string()));
    }
    out
}

/// Charge and power source as findings.
fn power_findings(on_ac: Option<bool>, percent: Option<u8>, charging: Option<&str>) -> Vec<Finding> {
    let source = match on_ac {
        Some(true) => "on AC power",
        Some(false) => "on battery",
        None => "power source unknown",
    };
    let value = match (percent, charging) {
        (Some(p), Some(state)) => format!("{p}% · {source} · {state}"),
        (Some(p), None) => format!("{p}% · {source}"),
        (None, _) => source.to_string(),
    };
    let severity = match (percent, on_ac) {
        (Some(p), Some(false)) if p <= 15 => Severity::Warning,
        _ => Severity::Ok,
    };
    vec![Finding::new("Charge", value, severity)]
}

type Reading = (Option<Vec<Finding>>, Vec<Battery>, Option<String>);

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::battery::powercfg_xml;
    use crate::util::{capture, cmd, exit_label};

    pub fn read(ctx: &RunContext) -> Result<Reading, String> {
        let Some((on_ac, percent, has_battery)) = crate::win::domain::power() else {
            return Err("Windows didn't report the power status.".into());
        };
        if !has_battery {
            return Ok((None, Vec::new(), None));
        }
        let power = power_findings(on_ac, percent, None);

        ctx.log("Running powercfg /batteryreport…");
        let path = std::env::temp_dir().join(format!("itriage-battery-{}.xml", std::process::id()));
        let mut c = cmd("powercfg");
        c.arg("/batteryreport").arg("/xml").arg("/output").arg(&path);
        let (batteries, note) = match capture(c) {
            Ok(out) if out.success() => {
                let xml = read_report(&path);
                let _ = std::fs::remove_file(&path);
                match xml {
                    Some(x) => (powercfg_xml(&x), None),
                    None => (Vec::new(), Some("powercfg wrote no report".to_string())),
                }
            }
            Ok(out) => (Vec::new(), Some(format!("powercfg failed ({})", exit_label(out.code)))),
            Err(e) => (Vec::new(), Some(e)),
        };
        Ok((Some(power), batteries, note))
    }

    /// powercfg writes UTF-8, but older builds wrote UTF-16; handle both.
    fn read_report(path: &std::path::Path) -> Option<String> {
        let bytes = std::fs::read(path).ok()?;
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let wide: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            Some(String::from_utf16_lossy(&wide))
        } else {
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::battery::sysfs_battery;
    use std::path::Path;

    fn read_file(dir: &Path, f: &str) -> Option<String> {
        std::fs::read_to_string(dir.join(f))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn read(_ctx: &RunContext) -> Result<Reading, String> {
        let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else {
            return Ok((None, Vec::new(), None));
        };
        let mut on_ac = None;
        let mut batteries = Vec::new();
        let mut charge: Option<(u8, String)> = None;
        for e in entries.flatten() {
            let dir = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            match read_file(&dir, "type").as_deref() {
                Some("Mains") => {
                    if let Some(online) = read_file(&dir, "online") {
                        on_ac = Some(on_ac.unwrap_or(false) || online == "1");
                    }
                }
                Some("Battery") if read_file(&dir, "scope").as_deref() != Some("Device") => {
                    if let Some(b) = sysfs_battery(&name, |f| read_file(&dir, f)) {
                        batteries.push(b);
                    }
                    if charge.is_none() {
                        if let Some(p) = read_file(&dir, "capacity").and_then(|v| v.parse().ok()) {
                            charge = Some((p, read_file(&dir, "status").unwrap_or_default().to_lowercase()));
                        }
                    }
                }
                _ => {}
            }
        }
        if batteries.is_empty() && charge.is_none() {
            return Ok((None, Vec::new(), None));
        }
        let (percent, status) = match &charge {
            Some((p, s)) => (Some(*p), Some(s.as_str()).filter(|s| !s.is_empty())),
            None => (None, None),
        };
        Ok((Some(power_findings(on_ac, percent, status)), batteries, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grades_battery_wear() {
        assert_eq!(health_grade(92.0), Severity::Ok);
        assert_eq!(health_grade(76.4), Severity::Warning);
        assert_eq!(health_grade(55.0), Severity::Critical);
        let low = power_findings(Some(false), Some(9), Some("discharging"));
        assert_eq!(low[0].severity, Severity::Warning);
        assert_eq!(low[0].value, "9% · on battery · discharging");
    }
}
