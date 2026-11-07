//! Battery wear: design capacity vs what the battery holds now. Sources are
//! `powercfg /batteryreport /xml` on Windows and sysfs on Linux.

/// One battery's capacity figures, in the source's own unit (mWh on
/// Windows; µWh or µAh in sysfs).
#[derive(Debug, Clone, PartialEq)]
pub struct Battery {
    pub name: String,
    pub design: u64,
    pub full: u64,
    pub cycles: Option<u32>,
    /// "Wh" or "Ah": what `design`/`full` measure once scaled by `scale`.
    pub unit: &'static str,
    /// Divide `design`/`full` by this to get `unit`.
    pub scale: f64,
}

impl Battery {
    /// Full-charge capacity as a percentage of design capacity.
    pub fn health_pct(&self) -> Option<f64> {
        (self.design > 0 && self.full > 0).then(|| self.full as f64 * 100.0 / self.design as f64)
    }

    /// "46.2 of 57.0 Wh".
    pub fn capacity_text(&self) -> String {
        format!(
            "{:.1} of {:.1} {}",
            self.full as f64 / self.scale,
            self.design as f64 / self.scale,
            self.unit
        )
    }
}

/// Batteries in a `powercfg /batteryreport /xml` report.
pub fn powercfg_xml(xml: &str) -> Vec<Battery> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = find_open(rest, "Battery") {
        let after = &rest[start..];
        let Some(end) = after.find("</Battery>") else { break };
        let block = &after[..end];
        let design = tag(block, "DesignCapacity").and_then(|v| v.parse().ok()).unwrap_or(0);
        let full = tag(block, "FullChargeCapacity").and_then(|v| v.parse().ok()).unwrap_or(0);
        let name = [tag(block, "Manufacturer"), tag(block, "Id")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        out.push(Battery {
            name: if name.is_empty() { "Battery".into() } else { name },
            design,
            full,
            cycles: tag(block, "CycleCount").and_then(|v| v.parse().ok()).filter(|&c| c > 0),
            unit: "Wh",
            scale: 1000.0,
        });
        rest = &after[end + "</Battery>".len()..];
    }
    out
}

/// Position of `<name>` or `<name ...>`, but not `<nameSuffix>`.
fn find_open(s: &str, name: &str) -> Option<usize> {
    let needle = format!("<{name}");
    let mut from = 0;
    while let Some(i) = s[from..].find(&needle) {
        let at = from + i;
        let next = s[at + needle.len()..].chars().next();
        if matches!(next, Some('>') | Some(' ')) {
            return Some(at);
        }
        from = at + needle.len();
    }
    None
}

/// Text of the first `<name>text</name>` in `block`, trimmed; `None` when
/// missing, empty or self-closing.
fn tag<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    let text = block[start..end].trim();
    (!text.is_empty()).then_some(text)
}

/// A sysfs power_supply battery. `read` returns a file's trimmed contents
/// (e.g. `read("energy_full")`).
pub fn sysfs_battery(name: &str, read: impl Fn(&str) -> Option<String>) -> Option<Battery> {
    let num = |f: &str| read(f).and_then(|v| v.trim().parse::<u64>().ok());
    let (design, full, unit) = match (num("energy_full_design"), num("energy_full")) {
        (Some(d), Some(f)) => (d, f, "Wh"),
        _ => (num("charge_full_design")?, num("charge_full")?, "Ah"),
    };
    let label = [read("manufacturer"), read("model_name")]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Some(Battery {
        name: if label.is_empty() { name.to_string() } else { label },
        design,
        full,
        cycles: num("cycle_count").map(|c| c as u32).filter(|&c| c > 0),
        unit,
        scale: 1_000_000.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const REPORT: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<BatteryReport xmlns="http://schemas.microsoft.com/battery/2012">
  <Batteries>
    <Battery>
      <Id>DELL 7FHXW37</Id>
      <Manufacturer>SMP</Manufacturer>
      <ManufactureDate />
      <Chemistry>LiP</Chemistry>
      <DesignCapacity>63000</DesignCapacity>
      <FullChargeCapacity>48104</FullChargeCapacity>
      <CycleCount>311</CycleCount>
    </Battery>
    <Battery>
      <Id>Secondary</Id>
      <DesignCapacity>40000</DesignCapacity>
      <FullChargeCapacity>39000</FullChargeCapacity>
      <CycleCount>0</CycleCount>
    </Battery>
  </Batteries>
</BatteryReport>"#;

    #[test]
    fn parses_powercfg_report() {
        let b = powercfg_xml(REPORT);
        assert_eq!(b.len(), 2, "<Batteries> isn't mistaken for a battery");
        assert_eq!(b[0].name, "SMP DELL 7FHXW37");
        assert_eq!(b[0].cycles, Some(311));
        assert!((b[0].health_pct().unwrap() - 76.36).abs() < 0.01);
        assert_eq!(b[0].capacity_text(), "48.1 of 63.0 Wh");
        assert_eq!(b[1].cycles, None, "0 means the battery doesn't report cycles");
        assert!(powercfg_xml("<BatteryReport><Batteries /></BatteryReport>").is_empty());
    }

    #[test]
    fn reads_sysfs_energy_or_charge() {
        let files: HashMap<&str, &str> = [
            ("energy_full_design", "57000000"),
            ("energy_full", "51300000"),
            ("cycle_count", "88"),
            ("manufacturer", "LGC"),
            ("model_name", "5B10W13930"),
        ]
        .into();
        let b = sysfs_battery("BAT0", |f| files.get(f).map(|s| s.to_string())).unwrap();
        assert_eq!(b.name, "LGC 5B10W13930");
        assert!((b.health_pct().unwrap() - 90.0).abs() < 0.01);
        assert_eq!(b.capacity_text(), "51.3 of 57.0 Wh");

        let charge: HashMap<&str, &str> = [("charge_full_design", "4400000"), ("charge_full", "2640000")].into();
        let b = sysfs_battery("BAT1", |f| charge.get(f).map(|s| s.to_string())).unwrap();
        assert_eq!(b.name, "BAT1");
        assert_eq!(b.unit, "Ah");
        assert!((b.health_pct().unwrap() - 60.0).abs() < 0.01);

        assert!(sysfs_battery("BAT2", |_| None).is_none());
    }
}
