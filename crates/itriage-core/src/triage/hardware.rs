//! Throttling and hardware errors. Read-only.
//!
//! A "slow" docked laptop is often held back rather than overloaded: the
//! firmware caps the processor's speed because of heat or a charger that
//! can't supply enough power, so it shows 100% busy while running at 40% of
//! its clock. This reads the processor's clock against its maximum right
//! now, the firmware's speed-limit reports (Windows event 37) and the
//! kernel's thermal-throttle counters (Linux), and corrected or fatal
//! hardware errors (WHEA on Windows, EDAC on Linux).
//!
//! Virtual machines rarely report any of this; missing data is a gap, not
//! a clean bill of health.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::hardware::{severity, HwError, SpeedCap};
use crate::util::{ago, human_duration, plural};

pub struct Hardware;

impl TriageModule for Hardware {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Whether the processor is running below its rated speed (firmware or heat limits), and corrected or fatal hardware errors in the last 30 days (WHEA)."
        } else {
            "Whether the processor is running below its rated speed or being thermally throttled, and memory errors the kernel has counted (EDAC)."
        };
        ModuleInfo::new("system.hardware", "Throttling & hardware errors", Category::System, description)
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        imp::check()
    }
}

/// The clock right now, judged against how busy the processor is: a low
/// clock at idle is power saving, a low clock while busy is a limit.
pub fn clock_finding(clock_pct: Option<f64>, cpu_pct: f64) -> Finding {
    match clock_pct {
        None => Finding::info("Processor clock", "not reported on this machine (common in virtual machines)"),
        Some(clock) => {
            let busy = cpu_pct >= 50.0;
            let value = format!("{clock:.0}% of its maximum · processor {cpu_pct:.0}% busy");
            let f = if busy && clock < 60.0 {
                Finding::warn("Processor clock", value).with_detail(
                    "Busy and running well below its rated speed: firmware or heat is holding it back. The program using the processor isn't the whole story; check the charger, the dock and the vents.",
                )
            } else if busy && clock < 80.0 {
                Finding::info("Processor clock", value).with_detail("Somewhat below its rated speed while busy. On battery or a power-saving plan this can be normal.")
            } else {
                Finding::ok("Processor clock", value)
            };
            f.with_metric(clock, "% of max clock", false)
        }
    }
}

/// The firmware's speed-limit reports over the last seven days.
pub fn speed_caps(caps: &[SpeedCap], now: u64, on_ac: Option<bool>) -> Finding {
    if caps.is_empty() {
        return Finding::ok("Firmware speed limits (7 days)", "none reported");
    }
    let total: u64 = caps.iter().map(|c| c.seconds).sum();
    let last = caps.iter().map(|c| c.epoch).max().unwrap_or(now);
    let value = format!(
        "{} report{} · limited for {} in total · last {}",
        caps.len(),
        plural(caps.len()),
        human_duration(total),
        ago(now.saturating_sub(last))
    );
    // A minute here and there is power management; tens of minutes is a
    // PC that spends its day slowed down.
    let severity = if total >= 1800 || caps.len() >= 20 {
        Severity::Warning
    } else {
        Severity::Info
    };
    let hint = match on_ac {
        Some(true) if severity == Severity::Warning => " It's on mains power and still being limited: check the adapter's wattage against what the laptop needs, and the dock.",
        Some(false) => " It's on battery right now, where some limiting is by design.",
        _ => "",
    };
    Finding::new("Firmware speed limits (7 days)", value, severity)
        .with_detail(format!("Windows event 37: the firmware capped the processor's speed, usually for heat or power.{hint}"))
        .with_metric(total as f64 / 60.0, "min", true)
}

/// One row per kind of hardware error, worst first.
pub fn hardware_errors(errors: &[(u64, HwError, String)], now: u64) -> Vec<Finding> {
    let mut kinds: Vec<HwError> = errors.iter().map(|(_, k, _)| *k).collect();
    kinds.sort();
    kinds.dedup();
    if kinds.is_empty() {
        return vec![Finding::ok("Hardware errors (30 days)", "none reported")];
    }
    kinds
        .into_iter()
        .map(|kind| {
            let of_kind: Vec<&(u64, HwError, String)> = errors.iter().filter(|(_, k, _)| *k == kind).collect();
            let last = of_kind.iter().map(|(t, _, _)| *t).max().unwrap_or(now);
            let mut devices: Vec<&str> = of_kind.iter().map(|(_, _, d)| d.as_str()).filter(|d| !d.is_empty()).collect();
            devices.sort();
            devices.dedup();
            let detail = match kind {
                HwError::FatalMachineCheck => "The processor reported an error it couldn't correct; these usually end in a blue screen. Run the manufacturer's diagnostics.",
                HwError::CorrectedMemory => "Memory corrected an error. Repeats point at a failing memory module: run a memory test.",
                HwError::CorrectedMachineCheck => "The processor corrected an internal error. Repeats point at the processor, its cooling or its power.",
                HwError::CorrectedPcie => "A PCI Express link corrected an error. A few are common with link power saving; many point at the device, its slot or the dock.",
            };
            let named = if devices.is_empty() { String::new() } else { format!(" Reported by: {}.", devices.iter().take(4).copied().collect::<Vec<_>>().join("; ")) };
            Finding::new(kind.label(), format!("{} in 30 days · last {}", of_kind.len(), ago(now.saturating_sub(last))), severity(kind, of_kind.len()))
                .with_detail(format!("{detail}{named}"))
                .with_metric(of_kind.len() as f64, "errors", true)
        })
        .collect()
}

/// Linux: how often the kernel has throttled the processor for heat since
/// it started (core and package counters summed across CPUs).
pub fn thermal_finding(core: Option<u64>, package: Option<u64>) -> Finding {
    match (core, package) {
        (None, None) => Finding::info("Thermal throttling since start", "not reported on this machine"),
        (core, package) => {
            let (c, p) = (core.unwrap_or(0), package.unwrap_or(0));
            let value = format!("{c} core and {p} package event{}", plural((c + p) as usize));
            let f = if p >= 100 || c >= 1000 {
                Finding::warn("Thermal throttling since start", value).with_detail("The processor keeps hitting its temperature limit. Check the vents and fan; on a laptop, a hard surface helps.")
            } else if c + p > 0 {
                Finding::info("Thermal throttling since start", value)
            } else {
                Finding::ok("Thermal throttling since start", "none")
            };
            f.with_metric((c + p) as f64, "events", true)
        }
    }
}

/// Linux EDAC: memory errors the controller counted since start.
pub fn edac_finding(corrected: Option<u64>, uncorrected: Option<u64>) -> Option<Finding> {
    let (ce, ue) = (corrected?, uncorrected.unwrap_or(0));
    Some(if ue > 0 {
        Finding::crit("Memory errors since start", format!("{ue} uncorrected · {ce} corrected")).with_detail("Uncorrected memory errors corrupt data. Replace the memory module.")
    } else if ce > 0 {
        Finding::warn("Memory errors since start", format!("{ce} corrected")).with_detail("Memory corrected errors. Repeats point at a failing module: run a memory test.")
    } else {
        Finding::ok("Memory errors since start", "none")
    })
}

/// "3 of 4 checks" summary words.
fn summarise(findings: &[Finding]) -> String {
    let attention = findings.iter().filter(|f| f.severity.rank() >= Severity::Warning.rank()).count();
    match attention {
        0 => "No throttling or hardware errors that need attention".to_string(),
        n => format!("{n} hardware finding{} need{} attention", plural(n), if n == 1 { "s" } else { "" }),
    }
}

/// CPU load over a second, for judging the clock.
fn cpu_now() -> f64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(std::time::Duration::from_millis(500)));
    sys.refresh_cpu_usage();
    f64::from(sys.global_cpu_usage())
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::hardware::{speed_cap, whea};
    use crate::util::now_epoch;

    pub fn check() -> Result<Output, String> {
        let now = now_epoch();
        let mut findings = Vec::new();
        let counter = crate::win::pdh::Counter::open(crate::win::pdh::CLOCK_PCT).ok();
        let cpu = cpu_now();
        let clock = counter.as_ref().and_then(|c| c.read());
        findings.push(clock_finding(clock, cpu));

        const CAPS: &str = "*[System[Provider[@Name='Microsoft-Windows-Kernel-Processor-Power'] and EventID=37 and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
        const WHEA: &str = "*[System[Provider[@Name='Microsoft-Windows-WHEA-Logger'] and (EventID=17 or EventID=18 or EventID=19 or EventID=47) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]";
        match crate::win::eventlog::query_xml("System", CAPS, 500) {
            Ok(rows) => {
                let caps: Vec<_> = rows.iter().filter_map(|x| speed_cap(x)).collect();
                findings.push(speed_caps(&caps, now, crate::host::on_ac_power()));
            }
            Err(e) => findings.push(Finding::info("Firmware speed limits (7 days)", format!("couldn't read the System log: {e}"))),
        }
        match crate::win::eventlog::query_xml("System", WHEA, 500) {
            Ok(rows) => {
                let errors: Vec<_> = rows.iter().filter_map(|x| whea(x)).collect();
                findings.extend(hardware_errors(&errors, now));
            }
            Err(e) => findings.push(Finding::info("Hardware errors (30 days)", format!("couldn't read the System log: {e}"))),
        }
        Ok(Output::new(summarise(&findings), findings))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::path::Path;

    fn number(path: &Path) -> Option<u64> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    /// Sum of a counter over every CPU that has it; package counters are
    /// the same on every CPU of a package, so each package counts once.
    fn throttle_counts() -> (Option<u64>, Option<u64>) {
        let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") else { return (None, None) };
        let (mut core, mut package) = (None::<u64>, std::collections::BTreeMap::<String, u64>::new());
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.strip_prefix("cpu").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) {
                continue;
            }
            let dir = e.path().join("thermal_throttle");
            if let Some(c) = number(&dir.join("core_throttle_count")) {
                core = Some(core.unwrap_or(0) + c);
            }
            if let Some(p) = number(&dir.join("package_throttle_count")) {
                let id = std::fs::read_to_string(e.path().join("topology/physical_package_id")).unwrap_or_default();
                package.insert(id.trim().to_string(), p);
            }
        }
        (core, (!package.is_empty()).then(|| package.values().sum()))
    }

    fn edac() -> (Option<u64>, Option<u64>) {
        let Ok(entries) = std::fs::read_dir("/sys/devices/system/edac/mc") else { return (None, None) };
        let (mut ce, mut ue) = (None::<u64>, None::<u64>);
        for e in entries.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("mc")) {
            if let Some(c) = number(&e.path().join("ce_count")) {
                ce = Some(ce.unwrap_or(0) + c);
            }
            if let Some(u) = number(&e.path().join("ue_count")) {
                ue = Some(ue.unwrap_or(0) + u);
            }
        }
        (ce, ue)
    }

    pub fn check() -> Result<Output, String> {
        let cpu = cpu_now();
        let mut findings = vec![clock_finding(crate::telemetry::linux_clock_pct(), cpu)];
        let (core, package) = throttle_counts();
        findings.push(thermal_finding(core, package));
        let (ce, ue) = edac();
        findings.push(edac_finding(ce, ue).unwrap_or_else(|| Finding::info("Memory errors since start", "not reported (no EDAC memory controller driver loaded)")));
        Ok(Output::new(summarise(&findings), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_low_clock_only_matters_when_the_processor_is_busy() {
        assert_eq!(clock_finding(Some(41.0), 96.0).severity, Severity::Warning);
        assert_eq!(clock_finding(Some(41.0), 3.0).severity, Severity::Ok, "idle cores clock down to save power");
        assert_eq!(clock_finding(Some(70.0), 80.0).severity, Severity::Info);
        let f = clock_finding(Some(99.0), 90.0);
        assert_eq!((f.severity, f.metric.as_ref().unwrap().higher_is_worse), (Severity::Ok, false));
        assert!(clock_finding(None, 90.0).value.contains("virtual machines"));
    }

    #[test]
    fn speed_limits_add_up_and_name_the_charger_on_mains() {
        let now = 1_794_600_000;
        let caps: Vec<SpeedCap> = (0..4).map(|i| SpeedCap { epoch: now - i * 3_600, processor: "0:0".into(), seconds: 600 }).collect();
        let f = speed_caps(&caps, now, Some(true));
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.value, "4 reports · limited for 40m in total · last just now");
        assert!(f.detail.as_deref().unwrap().contains("adapter's wattage"));
        assert_eq!(f.metric.as_ref().unwrap().value, 40.0);
        let brief = speed_caps(&caps[..1], now, Some(false));
        assert_eq!(brief.severity, Severity::Info);
        assert!(brief.detail.as_deref().unwrap().contains("on battery"));
        assert_eq!(speed_caps(&[], now, None).severity, Severity::Ok);
    }

    #[test]
    fn hardware_errors_are_one_row_per_kind_worst_first() {
        let now = 1_794_600_000;
        let rows = hardware_errors(
            &[
                (now - 60, HwError::CorrectedPcie, "PCI\\VEN_8086&DEV_7AB8".into()),
                (now - 120, HwError::CorrectedPcie, "PCI\\VEN_8086&DEV_7AB8".into()),
                (now - 7_200, HwError::CorrectedMemory, "DIMM_A1".into()),
            ],
            now,
        );
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].label.as_str(), rows[0].severity), ("Corrected memory errors", Severity::Warning));
        assert_eq!(rows[1].value, "2 in 30 days · last 1m ago");
        assert!(rows[1].detail.as_deref().unwrap().ends_with("Reported by: PCI\\VEN_8086&DEV_7AB8."));
        assert_eq!(hardware_errors(&[], now)[0].severity, Severity::Ok);
    }

    #[test]
    fn linux_counters_are_graded() {
        assert_eq!(thermal_finding(Some(0), Some(0)).severity, Severity::Ok);
        assert_eq!(thermal_finding(Some(12), Some(3)).severity, Severity::Info);
        assert_eq!(thermal_finding(Some(12), Some(250)).severity, Severity::Warning);
        assert_eq!(thermal_finding(None, None).severity, Severity::Info);
        assert_eq!(edac_finding(Some(4), Some(1)).unwrap().severity, Severity::Critical);
        assert_eq!(edac_finding(Some(4), Some(0)).unwrap().severity, Severity::Warning);
        assert!(edac_finding(None, None).is_none());
    }
}
