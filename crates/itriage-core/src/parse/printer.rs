//! Printer state: Windows spooler status flags, and CUPS `lpstat` output.

use std::collections::HashMap;

// PRINTER_STATUS_* (winspool.h), stable since NT 4.
const PAUSED: u32 = 0x1;
const ERROR: u32 = 0x2;
const PENDING_DELETION: u32 = 0x4;
const PAPER_JAM: u32 = 0x8;
const PAPER_OUT: u32 = 0x10;
const MANUAL_FEED: u32 = 0x20;
const PAPER_PROBLEM: u32 = 0x40;
const OFFLINE: u32 = 0x80;
const OUTPUT_BIN_FULL: u32 = 0x800;
const NOT_AVAILABLE: u32 = 0x1000;
const TONER_LOW: u32 = 0x20000;
const NO_TONER: u32 = 0x40000;
const USER_INTERVENTION: u32 = 0x10_0000;
const OUT_OF_MEMORY: u32 = 0x20_0000;
const DOOR_OPEN: u32 = 0x40_0000;
const SERVER_UNKNOWN: u32 = 0x80_0000;
const POWER_SAVE: u32 = 0x100_0000;
/// PRINTER_ATTRIBUTE_WORK_OFFLINE: "Use Printer Offline", set by hand or by
/// the port monitor when the device stops answering.
const ATTR_WORK_OFFLINE: u32 = 0x400;

/// What a Windows printer's status flags mean: problems that stop printing
/// (worst first), then softer notes.
pub fn windows_status(status: u32, attributes: u32) -> (Vec<&'static str>, Vec<&'static str>) {
    let problems_table: [(u32, &str); 14] = [
        (ERROR, "in an error state"),
        (PAPER_JAM, "paper jam"),
        (PAPER_OUT, "out of paper"),
        (PAPER_PROBLEM, "paper problem"),
        (NO_TONER, "out of toner"),
        (DOOR_OPEN, "door open"),
        (USER_INTERVENTION, "needs attention at the printer"),
        (OUTPUT_BIN_FULL, "output tray full"),
        (OUT_OF_MEMORY, "printer out of memory"),
        (OFFLINE, "offline"),
        (NOT_AVAILABLE, "not available"),
        (SERVER_UNKNOWN, "print server unknown"),
        (PAUSED, "paused"),
        (PENDING_DELETION, "being deleted"),
    ];
    let mut problems: Vec<&str> = problems_table
        .iter()
        .filter(|(flag, _)| status & flag != 0)
        .map(|(_, text)| *text)
        .collect();
    if attributes & ATTR_WORK_OFFLINE != 0 && status & OFFLINE == 0 {
        problems.push("set to Use Printer Offline");
    }
    let notes_table: [(u32, &str); 3] = [
        (TONER_LOW, "toner low"),
        (MANUAL_FEED, "waiting for manual feed"),
        (POWER_SAVE, "power saving"),
    ];
    let notes = notes_table
        .iter()
        .filter(|(flag, _)| status & flag != 0)
        .map(|(_, text)| *text)
        .collect();
    (problems, notes)
}

/// Software printers that never jam: PDF/XPS writers, OneNote, fax.
pub fn is_virtual(name: &str, port: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let p = port.to_ascii_lowercase();
    ["print to pdf", "xps document writer", "onenote", "fax", "adobe pdf", "pdf24", "cutepdf"]
        .iter()
        .any(|v| n.contains(v))
        || ["portprompt:", "nul:", "shrfax:", "xpsport:", "file:"].iter().any(|v| p.starts_with(v))
}

/// Label/wristband printers (Zebra and friends), which clinical areas
/// depend on for specimen and patient labels.
pub fn is_label_printer(name: &str, driver: &str) -> bool {
    let s = format!("{name} {driver}").to_ascii_lowercase();
    ["zdesigner", "zebra", " zpl", "dymo", "sato", "intermec", "datamax"]
        .iter()
        .any(|v| s.contains(v))
}

/// One CUPS queue from `lpstat -p`.
#[derive(Debug, Clone, PartialEq)]
pub struct CupsPrinter {
    pub name: String,
    pub enabled: bool,
    pub printing: bool,
    /// Tab-indented lines under the queue: "Paused", "reason unknown"…
    pub reason: Option<String>,
}

/// `LC_ALL=C lpstat -p`.
pub fn cups_printers(out: &str) -> Vec<CupsPrinter> {
    let mut list: Vec<CupsPrinter> = Vec::new();
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("printer ") {
            let Some((name, state)) = rest.split_once(' ') else { continue };
            list.push(CupsPrinter {
                name: name.to_string(),
                enabled: !state.starts_with("disabled") && !state.contains("disabled since"),
                printing: state.starts_with("now printing"),
                reason: None,
            });
        } else if line.starts_with(['\t', ' ']) && !line.trim().is_empty() {
            if let Some(p) = list.last_mut() {
                let text = line.trim();
                p.reason = Some(match p.reason.take() {
                    Some(r) => format!("{r}; {text}"),
                    None => text.to_string(),
                });
            }
        }
    }
    list
}

/// `LC_ALL=C lpstat -d`.
pub fn cups_default(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("system default destination:"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Queued jobs per printer, from `LC_ALL=C lpstat -o` ("Queue-123 user size date").
pub fn cups_job_counts(out: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for line in out.lines() {
        let Some(job) = line.split_whitespace().next() else { continue };
        if let Some((queue, id)) = job.rsplit_once('-') {
            if !queue.is_empty() && id.chars().all(|c| c.is_ascii_digit()) {
                *counts.entry(queue.to_string()).or_insert(0) += 1;
            }
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_windows_status_flags() {
        let (p, n) = windows_status(PAPER_JAM | TONER_LOW, 0);
        assert_eq!(p, vec!["paper jam"]);
        assert_eq!(n, vec!["toner low"]);
        let (p, _) = windows_status(0, ATTR_WORK_OFFLINE);
        assert_eq!(p, vec!["set to Use Printer Offline"]);
        let (p, _) = windows_status(OFFLINE, ATTR_WORK_OFFLINE);
        assert_eq!(p, vec!["offline"], "offline isn't reported twice");
        assert_eq!(windows_status(0, 0), (vec![], vec![]));
    }

    #[test]
    fn spots_virtual_and_label_printers() {
        assert!(is_virtual("Microsoft Print to PDF", "PORTPROMPT:"));
        assert!(is_virtual("Some Writer", "nul:"));
        assert!(!is_virtual("Ward 4 LaserJet", "IP_10.1.2.3"));
        assert!(is_label_printer("Specimen labels", "ZDesigner ZD421-203dpi ZPL"));
        assert!(!is_label_printer("HP LaserJet M404", "HP Universal Printing PCL 6"));
    }

    const LPSTAT_P: &str = "printer HP_LaserJet_M404 is idle.  enabled since Thu 05 Nov 2026 09:12:44 AM EST
printer Zebra_ZD420 disabled since Thu 05 Nov 2026 08:01:02 AM EST -
\tPaused
printer Ward4_Color now printing Ward4_Color-118.  enabled since Thu 05 Nov 2026 10:20:00 AM EST
\tWaiting for printer to become available.
";

    #[test]
    fn parses_lpstat() {
        let p = cups_printers(LPSTAT_P);
        assert_eq!(p.len(), 3);
        assert!(p[0].enabled && !p[0].printing && p[0].reason.is_none());
        assert!(!p[1].enabled);
        assert_eq!(p[1].reason.as_deref(), Some("Paused"));
        assert!(p[2].enabled && p[2].printing);

        assert_eq!(cups_default("system default destination: HP_LaserJet_M404\n").as_deref(), Some("HP_LaserJet_M404"));
        assert_eq!(cups_default("no system default destination\n"), None);

        let jobs = cups_job_counts(
            "HP_LaserJet_M404-1021   jparker   18432   Thu 05 Nov 2026 10:31:07 AM EST
Ward4-Color-118         nurse1   102400   Thu 05 Nov 2026 10:20:00 AM EST
Ward4-Color-119         nurse1   1024   Thu 05 Nov 2026 10:21:00 AM EST
",
        );
        assert_eq!(jobs["HP_LaserJet_M404"], 1);
        assert_eq!(jobs["Ward4-Color"], 2, "queue names may contain dashes");
    }
}
