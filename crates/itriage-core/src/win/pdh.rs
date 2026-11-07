//! Performance counters through PDH. English counter paths
//! (PdhAddEnglishCounterW) so it works on every display language.

use std::time::Duration;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue, PdhOpenQueryW,
    PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY,
};

struct Query(PDH_HQUERY);

impl Drop for Query {
    fn drop(&mut self) {
        // SAFETY: a query handle PDH opened, closed once.
        unsafe {
            PdhCloseQuery(self.0);
        }
    }
}

fn check(what: &str, rc: u32) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{what} (PDH 0x{rc:08X})"))
    }
}

/// Average milliseconds per disk transfer and the disk queue length across
/// all physical disks (`\PhysicalDisk(_Total)`), sampled over `interval`:
/// what Invoke-NetTriage reads from Win32_PerfFormattedData_PerfDisk_PhysicalDisk.
pub fn disk_latency(interval: Duration) -> Result<(f64, f64), String> {
    // SAFETY: handles are owned by `Query` and closed on every path; the
    // counter values are plain out-parameters.
    unsafe {
        let mut query = PDH_HQUERY::default();
        check("performance counters unavailable", PdhOpenQueryW(PCWSTR::null(), 0, &mut query))?;
        let query = Query(query);
        let mut latency = PDH_HCOUNTER::default();
        let mut queue = PDH_HCOUNTER::default();
        check(
            "no disk latency counter",
            PdhAddEnglishCounterW(query.0, &HSTRING::from(r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer"), 0, &mut latency),
        )?;
        check(
            "no disk queue counter",
            PdhAddEnglishCounterW(query.0, &HSTRING::from(r"\PhysicalDisk(_Total)\Current Disk Queue Length"), 0, &mut queue),
        )?;
        // Rate counters need two samples.
        check("sampling disk counters", PdhCollectQueryData(query.0))?;
        std::thread::sleep(interval);
        check("sampling disk counters", PdhCollectQueryData(query.0))?;
        let read = |counter: PDH_HCOUNTER| -> Result<f64, String> {
            let mut value = PDH_FMT_COUNTERVALUE::default();
            check("reading a disk counter", PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, None, &mut value))?;
            Ok(value.Anonymous.doubleValue)
        };
        Ok((read(latency)? * 1000.0, read(queue)?))
    }
}
