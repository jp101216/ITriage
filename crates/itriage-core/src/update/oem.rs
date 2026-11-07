//! OEM driver/BIOS/firmware tools, and how to drive each one unattended.
//!
//! Table-driven so it's easy to tune: each entry says how to recognise the
//! manufacturer, where the tool is installed, which arguments make it run
//! silently without rebooting, and what its exit codes mean.
//!
//! The flags and exit codes come from each vendor's command-line reference.
//! They haven't been tested on hardware yet, so check them on a real Dell, HP
//! or Lenovo before relying on them.

use crate::model::Severity;
use std::path::{Path, PathBuf};

pub struct OemTool {
    /// Display name of the tool.
    pub tool: &'static str,
    /// Does this tool cover a given (lowercased) SMBIOS manufacturer string?
    matches: fn(&str) -> bool,
    locate: fn() -> Option<PathBuf>,
    /// Arguments for an unattended, no-reboot install; logs go in `work`.
    args: fn(&Path) -> Vec<String>,
    exit_codes: &'static [(i32, Severity, &'static str)],
    /// Shown when the manufacturer matches but the tool isn't installed.
    pub get_it: &'static str,
}

impl OemTool {
    pub fn locate(&self) -> Option<PathBuf> {
        (self.locate)()
    }
    pub fn args(&self, work: &Path) -> Vec<String> {
        (self.args)(work)
    }
    /// What an exit code means, per the vendor's documentation.
    pub fn meaning(&self, code: Option<i32>) -> (Severity, String) {
        match code.and_then(|c| self.exit_codes.iter().find(|(k, _, _)| *k == c)) {
            Some((_, severity, text)) => (*severity, (*text).to_string()),
            None => (
                Severity::Warning,
                "finished with an exit code this version of itriage doesn't recognise; check the tool's log".into(),
            ),
        }
    }
}

const DELL: OemTool = OemTool {
    tool: "Dell Command | Update",
    matches: |m| m.contains("dell"),
    locate: || {
        first_file(&[
            program_files("ProgramFiles", r"Dell\CommandUpdate\dcu-cli.exe"),
            program_files("ProgramFiles(x86)", r"Dell\CommandUpdate\dcu-cli.exe"),
        ])
    },
    args: |work| {
        vec![
            "/applyUpdates".into(),
            "-silent".into(),
            "-reboot=disable".into(),
            format!("-outputLog={}", work.join("dcu-apply.log").display()),
        ]
    },
    exit_codes: &[
        (0, Severity::Ok, "updates applied"),
        (1, Severity::Warning, "updates applied; restart required"),
        (3, Severity::Info, "this isn't a Dell system"),
        (4, Severity::Critical, "not running as administrator"),
        (5, Severity::Warning, "a restart is pending from an earlier update; restart, then run this again"),
        (6, Severity::Warning, "Dell Command | Update is already running"),
        (500, Severity::Ok, "no updates available; drivers and BIOS are current"),
    ],
    get_it: "install Dell Command | Update from Dell's support site to get BIOS and firmware updates",
};

const HP: OemTool = OemTool {
    tool: "HP Image Assistant",
    matches: |m| m.starts_with("hp") || m.contains("hewlett"),
    locate: locate_hpia,
    args: |work| {
        vec![
            "/Operation:Analyze".into(),
            "/Action:Install".into(),
            "/Selection:All".into(),
            "/Category:BIOS,Drivers,Firmware".into(),
            "/Silent".into(),
            format!("/ReportFolder:{}", work.join("hpia-report").display()),
            format!("/SoftpaqDownloadFolder:{}", work.join("hpia-softpaqs").display()),
        ]
    },
    exit_codes: &[
        (0, Severity::Ok, "updates applied"),
        (256, Severity::Ok, "no recommendations; drivers and BIOS are current"),
        (257, Severity::Ok, "nothing was selected to install"),
        (3010, Severity::Warning, "updates applied; restart required"),
        (3020, Severity::Critical, "one or more SoftPaq installs failed; see the HPIA report"),
    ],
    get_it: "download HP Image Assistant (HPIA) from HP's support site to get BIOS and firmware updates",
};

const LENOVO: OemTool = OemTool {
    tool: "Lenovo Thin Installer",
    matches: |m| m.contains("lenovo"),
    locate: || {
        first_file(&[
            program_files("ProgramFiles(x86)", r"Lenovo\ThinInstaller\ThinInstaller.exe"),
            program_files("ProgramFiles", r"Lenovo\ThinInstaller\ThinInstaller.exe"),
        ])
    },
    args: |_| {
        ["/CM", "-search", "A", "-action", "INSTALL", "-noicon", "-includerebootpackages", "1,3,4", "-noreboot"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    },
    exit_codes: &[(0, Severity::Ok, "completed")],
    get_it: "install Lenovo Thin Installer for unattended BIOS and firmware updates",
};

static TOOLS: [OemTool; 3] = [DELL, HP, LENOVO];

/// The OEM tool for this manufacturer, if we know one.
pub fn for_manufacturer(manufacturer: &str) -> Option<&'static OemTool> {
    let m = manufacturer.trim().to_ascii_lowercase();
    TOOLS.iter().find(|t| (t.matches)(&m))
}

/// `%ProgramData%\itriage`, for vendor logs and downloaded packages.
pub fn work_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let dir = base.join("itriage");
    std::fs::create_dir_all(&dir).map_err(|e| format!("can't create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn program_files(var: &str, rel: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(|base| PathBuf::from(base).join(rel))
}

fn first_file(candidates: &[Option<PathBuf>]) -> Option<PathBuf> {
    candidates.iter().flatten().find(|p| p.is_file()).cloned()
}

/// HPIA has no fixed install location: it's a self-extracting SoftPaq that
/// lands in `C:\SWSetup\SP<number>\` by default, or wherever IT put it.
fn locate_hpia() -> Option<PathBuf> {
    const EXE: &str = "HPImageAssistant.exe";
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let root = PathBuf::from(format!("{drive}\\"));
    let direct = [
        program_files("ProgramFiles", &format!(r"HP\HPIA\{EXE}")),
        Some(root.join("HP").join("HPIA").join(EXE)),
    ];
    if let Some(p) = first_file(&direct) {
        return Some(p);
    }
    if let Ok(entries) = std::fs::read_dir(root.join("SWSetup")) {
        for entry in entries.flatten() {
            let candidate = entry.path().join(EXE);
            if entry.file_name().to_string_lossy().starts_with("SP") && candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    crate::util::find_in_path("HPImageAssistant")
}
