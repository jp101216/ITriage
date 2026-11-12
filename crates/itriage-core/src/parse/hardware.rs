//! Throttling and hardware errors, from events (Windows) and sysfs (Linux).
//!
//! Windows field names are from the Kernel-Processor-Power and WHEA-Logger
//! event manifests (dumped from Windows Server 2025, November 2026). Event
//! 37 says the firmware limited a processor's speed and for how long
//! (`CapDurationInSeconds`) since the last report. WHEA-Logger 17 is a
//! corrected PCI Express error, 18 a fatal machine check, 19 a corrected
//! machine check and 47 a corrected memory error; their messages say
//! "A corrected hardware error has occurred" for all but 18.

use crate::parse::blocks::field;
use crate::parse::evtxml::{parse_system, payload};
use crate::parse::time::iso8601_utc_to_epoch;

/// One "speed limited by firmware" report.
#[derive(Debug, Clone, PartialEq)]
pub struct SpeedCap {
    pub epoch: u64,
    pub processor: String,
    pub seconds: u64,
}

pub fn speed_cap(xml: &str) -> Option<SpeedCap> {
    let system = parse_system(xml)?;
    if system.event_id != 37 || !system.provider.to_ascii_lowercase().contains("processor-power") {
        return None;
    }
    let data = payload(xml);
    Some(SpeedCap {
        epoch: iso8601_utc_to_epoch(system.time_created.as_deref()?)?,
        processor: match (field(&data, &["Group"]), field(&data, &["Number"])) {
            (Some(g), Some(n)) => format!("{g}:{n}"),
            (None, Some(n)) => n.to_string(),
            _ => String::new(),
        },
        seconds: field(&data, &["CapDurationInSeconds"]).and_then(|s| s.parse().ok()).unwrap_or(0),
    })
}

/// The kinds of WHEA report, worst first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HwError {
    FatalMachineCheck,
    CorrectedMemory,
    CorrectedMachineCheck,
    CorrectedPcie,
}

impl HwError {
    pub fn label(self) -> &'static str {
        match self {
            HwError::FatalMachineCheck => "Fatal processor errors (machine check)",
            HwError::CorrectedMemory => "Corrected memory errors",
            HwError::CorrectedMachineCheck => "Corrected processor errors (machine check)",
            HwError::CorrectedPcie => "Corrected PCI Express errors",
        }
    }
}

/// A WHEA-Logger event's kind and the device it names, if any.
pub fn whea(xml: &str) -> Option<(u64, HwError, String)> {
    let system = parse_system(xml)?;
    if !system.provider.to_ascii_lowercase().contains("whea") {
        return None;
    }
    let kind = match system.event_id {
        17 => HwError::CorrectedPcie,
        18 => HwError::FatalMachineCheck,
        19 => HwError::CorrectedMachineCheck,
        47 => HwError::CorrectedMemory,
        _ => return None,
    };
    let data = payload(xml);
    // PCIe errors name the device; machine checks the processor (APIC id)
    // and bank; memory errors the module when the firmware knows it.
    let what = match kind {
        HwError::CorrectedPcie => match (field(&data, &["PrimaryDeviceName"]), field(&data, &["VendorID"]), field(&data, &["DeviceID"])) {
            (Some(name), _, _) => name.to_string(),
            (None, Some(v), Some(d)) => format!("PCI device {v}:{d}"),
            _ => String::new(),
        },
        HwError::CorrectedMachineCheck | HwError::FatalMachineCheck => match (field(&data, &["ApicId"]), field(&data, &["MCABank"])) {
            (Some(apic), Some(bank)) => format!("processor {apic}, bank {bank}"),
            (Some(apic), None) => format!("processor {apic}"),
            _ => String::new(),
        },
        HwError::CorrectedMemory => field(&data, &["FRUText"]).filter(|t| !t.is_empty()).map(str::to_string).unwrap_or_default(),
    };
    Some((iso8601_utc_to_epoch(system.time_created.as_deref()?)?, kind, what))
}

/// Average current clock as a percentage of the maximum, across the CPUs
/// that report both (`scaling_cur_freq` / `cpuinfo_max_freq`, in kHz).
pub fn clock_pct(pairs: &[(u64, u64)]) -> Option<f64> {
    let usable: Vec<f64> = pairs.iter().filter(|(_, max)| *max > 0).map(|(cur, max)| *cur as f64 / *max as f64 * 100.0).collect();
    (!usable.is_empty()).then(|| (usable.iter().sum::<f64>() / usable.len() as f64).min(100.0))
}

/// How hard a corrected-error count is to ignore. A handful of corrected
/// PCIe errors is common (link power saving); machine checks and memory
/// errors are not.
pub fn severity(kind: HwError, count: usize) -> crate::model::Severity {
    use crate::model::Severity;
    match kind {
        HwError::FatalMachineCheck => Severity::Critical,
        HwError::CorrectedMemory | HwError::CorrectedMachineCheck if count >= 10 => Severity::Critical,
        HwError::CorrectedMemory | HwError::CorrectedMachineCheck => Severity::Warning,
        HwError::CorrectedPcie if count >= 25 => Severity::Warning,
        HwError::CorrectedPcie => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(provider: &str, id: u32, data: &[(&str, &str)]) -> String {
        let fields: String = data.iter().map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>")).collect();
        format!("<Event><System><Provider Name='{provider}'/><EventID>{id}</EventID><Version>0</Version><Level>3</Level><TimeCreated SystemTime='2026-11-12T13:00:00.0000000Z'/><Channel>System</Channel></System><EventData>{fields}</EventData></Event>")
    }

    #[test]
    fn reads_firmware_speed_caps() {
        let cap = speed_cap(&event("Microsoft-Windows-Kernel-Processor-Power", 37, &[("Group", "0"), ("Number", "3"), ("CapDurationInSeconds", "1834"), ("PpcChanges", "4"), ("TpcChanges", "0"), ("PccChanges", "0")])).unwrap();
        assert_eq!((cap.processor.as_str(), cap.seconds), ("0:3", 1834));
        assert!(speed_cap(&event("Microsoft-Windows-Kernel-Processor-Power", 55, &[])).is_none(), "55 is the processor's capabilities, not a cap");
    }

    #[test]
    fn sorts_whea_reports_by_kind() {
        let pcie = whea(&event("Microsoft-Windows-WHEA-Logger", 17, &[("ErrorSource", "4"), ("VendorID", "0x8086"), ("DeviceID", "0x7ab8"), ("PrimaryDeviceName", "PCI\\VEN_8086&DEV_7AB8")])).unwrap();
        assert_eq!((pcie.1, pcie.2.as_str()), (HwError::CorrectedPcie, "PCI\\VEN_8086&DEV_7AB8"));
        let mce = whea(&event("Microsoft-Windows-WHEA-Logger", 19, &[("ApicId", "6"), ("MCABank", "1")])).unwrap();
        assert_eq!((mce.1, mce.2.as_str()), (HwError::CorrectedMachineCheck, "processor 6, bank 1"));
        assert_eq!(whea(&event("Microsoft-Windows-WHEA-Logger", 18, &[])).unwrap().1, HwError::FatalMachineCheck);
        assert_eq!(whea(&event("Microsoft-Windows-WHEA-Logger", 47, &[("FRUText", "DIMM_A1")])).unwrap().2, "DIMM_A1");
        assert!(whea(&event("Microsoft-Windows-WHEA-Logger", 1, &[])).is_none());
        use crate::model::Severity;
        assert_eq!(severity(HwError::CorrectedPcie, 3), Severity::Info);
        assert_eq!(severity(HwError::CorrectedPcie, 40), Severity::Warning);
        assert_eq!(severity(HwError::CorrectedMemory, 1), Severity::Warning);
        assert_eq!(severity(HwError::FatalMachineCheck, 1), Severity::Critical);
    }

    #[test]
    fn averages_the_clock_over_cpus_that_report_it() {
        assert_eq!(clock_pct(&[(1_200_000, 3_000_000), (1_800_000, 3_000_000), (5, 0)]), Some(50.0));
        assert_eq!(clock_pct(&[(4_000_000, 3_000_000)]), Some(100.0), "turbo reads as full speed");
        assert_eq!(clock_pct(&[]), None);
    }
}
