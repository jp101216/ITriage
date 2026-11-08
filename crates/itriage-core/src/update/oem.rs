//! OEM driver/BIOS/firmware tools: which one a machine should use, and how
//! to drive the ones that can run unattended.
//!
//! Routing is Invoke-UpdateSystem's: ten manufacturers, matched against the
//! SMBIOS manufacturer first, then the model, then the motherboard (so a
//! custom build on an ASUS board still routes to MyASUS). Dell, HP and Lenovo
//! tools run silently here; for the rest itriage says where to get the tool
//! and leaves the flash to it, as the script does. itriage never flashes a
//! BIOS itself.
//!
//! The runner flags and exit codes come from each vendor's command-line
//! reference. They haven't been tested on hardware yet, so check them on a
//! real Dell, HP or Lenovo before relying on them.

// Routing and the tool table are shared (the fixes validate against them);
// running the tools is Windows-only.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::model::Severity;
use crate::parse::smbios::Identity;
use std::path::{Path, PathBuf};

pub struct OemTool {
    /// Display name of the tool.
    pub tool: &'static str,
    locate: fn() -> Option<PathBuf>,
    /// Arguments for an unattended, no-reboot install; logs go in `work`.
    args: fn(&Path) -> Vec<String>,
    exit_codes: &'static [(i32, Severity, &'static str)],
    /// Exit codes that mean "done; restart to finish".
    restart_codes: &'static [i32],
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
    pub fn needs_restart(&self, code: Option<i32>) -> bool {
        code.is_some_and(|c| self.restart_codes.contains(&c))
    }
    /// What an exit code means, per the vendor's documentation.
    pub fn meaning(&self, code: Option<i32>) -> (Severity, String) {
        match code.and_then(|c| self.exit_codes.iter().find(|(k, _, _)| *k == c)) {
            Some((_, severity, text)) => (*severity, (*text).to_string()),
            None => (
                Severity::Warning,
                "finished with an exit code this version of ITriage doesn't recognise; check the tool's log".into(),
            ),
        }
    }
}

const DELL: OemTool = OemTool {
    tool: "Dell Command | Update",
    locate: || {
        first_file(&[
            program_files("ProgramFiles", r"Dell\CommandUpdate\dcu-cli.exe"),
            program_files("ProgramFiles(x86)", r"Dell\CommandUpdate\dcu-cli.exe"),
        ])
        .or_else(|| crate::util::find_in_path("dcu-cli"))
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
    restart_codes: &[1, 5],
    get_it: "install Dell Command | Update from Dell's support site to get BIOS and firmware updates",
};

const HP: OemTool = OemTool {
    tool: "HP Image Assistant",
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
    restart_codes: &[3010],
    get_it: "download HP Image Assistant (HPIA) from HP's support site to get BIOS and firmware updates",
};

const LENOVO: OemTool = OemTool {
    tool: "Lenovo Thin Installer",
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
    restart_codes: &[],
    get_it: "install Lenovo Thin Installer for unattended BIOS and firmware updates",
};

/// How a manufacturer's BIOS and firmware get updated.
pub enum Via {
    /// A tool itriage can run unattended.
    Runner(&'static OemTool),
    /// Firmware arrives through Windows Update (Surface).
    WindowsUpdate,
    /// The vendor's own app does it; itriage says where to get it.
    Manual,
}

/// One row of Invoke-UpdateSystem's OEM table.
pub struct Route {
    pub name: &'static str,
    /// Installable with `winget install --id …`.
    pub winget_id: Option<&'static str>,
    /// What to search for in the Store or on the vendor's site.
    pub search_name: &'static str,
    pub via: Via,
    pub note: Option<&'static str>,
    matches: fn(&str) -> bool,
}

/// Whether the routed tool is on this machine.
pub enum ToolState {
    /// Installed and runnable unattended.
    Ready(PathBuf),
    /// Installed, but it has to be opened (Lenovo System Update).
    Installed(&'static str),
    Missing,
}

/// "hp" as a word, so it doesn't match inside other names.
fn has_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == word)
}

static ROUTES: [Route; 10] = [
    Route {
        name: "Dell Command | Update",
        winget_id: Some("Dell.CommandUpdate"),
        search_name: "Dell Command Update",
        via: Via::Runner(&DELL),
        note: None,
        matches: |m| m.contains("dell"),
    },
    Route {
        name: "Lenovo System Update",
        winget_id: Some("Lenovo.SystemUpdate"),
        search_name: "Lenovo System Update",
        via: Via::Runner(&LENOVO),
        note: Some("ITriage runs Lenovo Thin Installer unattended when it's installed; Lenovo System Update has to be opened."),
        matches: |m| m.contains("lenovo"),
    },
    Route {
        name: "HP Image Assistant",
        winget_id: Some("HP.ImageAssistant"),
        search_name: "HP Image Assistant",
        via: Via::Runner(&HP),
        note: Some("HP Image Assistant is the business tool. On a consumer HP PC, HP Support Assistant may be the right one instead."),
        matches: |m| has_word(m, "hp") || m.contains("hewlett"),
    },
    Route {
        name: "Surface (via Windows Update)",
        winget_id: None,
        search_name: "Surface firmware",
        via: Via::WindowsUpdate,
        note: Some("Surface firmware arrives through Windows Update; no separate tool is needed."),
        matches: |m| m.contains("microsoft") || m.contains("surface"),
    },
    Route { name: "MyASUS", winget_id: None, search_name: "MyASUS", via: Via::Manual, note: None, matches: |m| m.contains("asus") },
    Route {
        name: "MSI Center",
        winget_id: None,
        search_name: "MSI Center",
        via: Via::Manual,
        note: None,
        matches: |m| has_word(m, "msi") || m.contains("micro-star"),
    },
    Route {
        name: "GIGABYTE Control Center",
        winget_id: None,
        search_name: "GIGABYTE Control Center",
        via: Via::Manual,
        note: None,
        matches: |m| m.contains("gigabyte"),
    },
    Route {
        name: "ASRock (manual)",
        winget_id: None,
        search_name: "ASRock BIOS",
        via: Via::Manual,
        note: Some("ASRock boards are updated from ASRock's support page, or with Instant Flash in the firmware setup."),
        matches: |m| m.contains("asrock"),
    },
    Route { name: "Acer Care Center", winget_id: None, search_name: "Acer Care Center", via: Via::Manual, note: None, matches: |m| m.contains("acer") },
    Route { name: "Samsung Update", winget_id: None, search_name: "Samsung Update", via: Via::Manual, note: None, matches: |m| m.contains("samsung") },
];

/// Invoke-UpdateSystem's routing: the manufacturer, then the model, then the
/// motherboard, each against every row in order. Returns the route and which
/// field matched.
pub fn route(id: &Identity) -> Option<(&'static Route, &'static str)> {
    let fields = [
        ("manufacturer", id.manufacturer.clone()),
        ("model", id.model.clone()),
        ("motherboard", id.motherboard()),
    ];
    for (field, value) in fields {
        let Some(v) = value else { continue };
        let v = v.to_ascii_lowercase();
        if let Some(r) = ROUTES.iter().find(|r| (r.matches)(&v)) {
            return Some((r, field));
        }
    }
    None
}

impl Route {
    pub fn state(&self) -> ToolState {
        match &self.via {
            Via::Runner(tool) => match tool.locate() {
                Some(path) => ToolState::Ready(path),
                None if self.winget_id == Some("Lenovo.SystemUpdate") && lenovo_system_update().is_some() => {
                    ToolState::Installed("Lenovo System Update")
                }
                None => ToolState::Missing,
            },
            _ => ToolState::Missing,
        }
    }
}

fn lenovo_system_update() -> Option<PathBuf> {
    first_file(&[
        program_files("ProgramFiles(x86)", r"Lenovo\System Update\tvsu.exe"),
        program_files("ProgramFiles", r"Lenovo\System Update\tvsu.exe"),
    ])
}

/// The tool name behind a winget id, for the three itriage will install.
pub fn tool_name(winget_id: &str) -> Option<&'static str> {
    ROUTES.iter().find(|r| r.winget_id == Some(winget_id)).map(|r| r.name)
}

/// Install a routed OEM tool with winget, the way Invoke-UpdateSystem does.
#[cfg(windows)]
pub fn install_tool(winget_id: &str, ctx: &crate::module::RunContext) -> Result<String, String> {
    let name = tool_name(winget_id).ok_or_else(|| format!("`{winget_id}` isn't one of the OEM tools ITriage installs."))?;
    let route = ROUTES.iter().find(|r| r.winget_id == Some(winget_id)).expect("tool_name found it");
    if !crate::update::winget::available() {
        return Err("winget isn't available; install App Installer from the Microsoft Store first.".into());
    }
    let mut c = crate::util::cmd("winget");
    c.args([
        "install",
        "--id",
        winget_id,
        "--accept-source-agreements",
        "--accept-package-agreements",
        "-e",
        "--disable-interactivity",
    ]);
    let out = crate::util::stream(c, ctx, std::time::Duration::from_secs(30 * 60))?;
    if out.success() {
        Ok(format!("{name} installed. Run Install drivers & firmware to use it."))
    } else {
        Err(format!(
            "winget couldn't install {name} ({}). Try: winget search \"{}\" to confirm the package id.",
            crate::util::exit_label(out.code),
            route.search_name
        ))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(maker: Option<&str>, model: Option<&str>, board: Option<&str>) -> Identity {
        Identity {
            manufacturer: maker.map(str::to_string),
            model: model.map(str::to_string),
            board_maker: board.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn routes_like_invoke_update_system() {
        let name = |i: &Identity| route(i).map(|(r, f)| (r.name, f));
        assert_eq!(name(&id(Some("Dell Inc."), None, None)), Some(("Dell Command | Update", "manufacturer")));
        assert_eq!(name(&id(Some("HP"), None, None)).unwrap().0, "HP Image Assistant");
        assert_eq!(name(&id(Some("Hewlett-Packard"), None, None)).unwrap().0, "HP Image Assistant");
        assert_eq!(name(&id(Some("LENOVO"), None, None)).unwrap().0, "Lenovo System Update");
        assert_eq!(name(&id(Some("Microsoft Corporation"), Some("Surface Laptop 6"), None)).unwrap().0, "Surface (via Windows Update)");
        assert_eq!(name(&id(Some("Micro-Star International Co., Ltd."), None, None)).unwrap().0, "MSI Center");
        // A custom build: nothing in the maker or model, the board decides.
        assert_eq!(name(&id(None, None, Some("ASUSTeK COMPUTER INC."))), Some(("MyASUS", "motherboard")));
        assert_eq!(name(&id(None, None, Some("ASRock"))).unwrap().0, "ASRock (manual)");
        assert_eq!(name(&id(Some("VMware, Inc."), Some("VMware7,1"), None)), None);
        // "hp" only as a word.
        assert_eq!(name(&id(Some("Shopify Hardware"), None, None)), None);
    }

    #[test]
    fn only_three_tools_install_through_winget() {
        assert_eq!(tool_name("Dell.CommandUpdate"), Some("Dell Command | Update"));
        assert_eq!(tool_name("Lenovo.SystemUpdate"), Some("Lenovo System Update"));
        assert_eq!(tool_name("HP.ImageAssistant"), Some("HP Image Assistant"));
        assert_eq!(tool_name("Malware.Thing"), None);
        let runs = |m: &str| matches!(route(&id(Some(m), None, None)), Some((Route { via: Via::Runner(_), .. }, _)));
        assert!(runs("Dell Inc."));
        assert!(!runs("ASUSTeK COMPUTER INC."), "MyASUS can't run unattended");
        assert!(DELL.needs_restart(Some(1)) && !DELL.needs_restart(Some(0)));
    }
}
