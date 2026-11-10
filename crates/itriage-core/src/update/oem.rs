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
//!
//! These tools run with administrator rights, so one is only started from a
//! place a standard user couldn't have written to (see [`crate::trust`]).
//! `C:\Program Files` qualifies. HP Image Assistant's default
//! `C:\SWSetup\SP…` doesn't, because Windows lets every signed-in user
//! write to folders made at the top of `C:\`; there ITriage says where the
//! tool is and why it won't start it.

// Routing and the tool table are shared (the fixes validate against them);
// running the tools is Windows-only.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::model::Severity;
use crate::parse::smbios::Identity;
use std::path::{Path, PathBuf};

pub struct OemTool {
    /// Display name of the tool.
    pub tool: &'static str,
    /// Every place the tool's program might be, likeliest first.
    candidates: fn() -> Vec<PathBuf>,
    /// Arguments for an unattended, no-reboot install; logs go in `work`.
    args: fn(&Path) -> Vec<String>,
    exit_codes: &'static [(i32, Severity, &'static str)],
    /// Exit codes that mean "done; restart to finish".
    restart_codes: &'static [i32],
    /// Shown when the manufacturer matches but the tool isn't installed.
    pub get_it: &'static str,
    /// The tool's exit code doesn't say whether a restart is needed.
    pub restart_unreported: bool,
}

/// Where a tool's program was found.
pub enum Located {
    /// In a place only administrators can write to.
    Trusted(PathBuf),
    /// Somewhere a standard user could have put it, and why.
    Untrusted(PathBuf, String),
    Missing,
}

impl OemTool {
    /// The first copy that's safe to run elevated; failing that, the first
    /// copy there is, with what's wrong with where it is.
    pub fn locate(&self) -> Located {
        let mut rejected = None;
        for path in (self.candidates)().into_iter().filter(|p| p.is_file()) {
            match trusted(&path) {
                Ok(()) => return Located::Trusted(path),
                Err(why) => {
                    rejected.get_or_insert((path, why));
                }
            }
        }
        match rejected {
            Some((path, why)) => Located::Untrusted(path, why),
            None => Located::Missing,
        }
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
    candidates: || {
        let mut found = in_program_files(r"Dell\CommandUpdate\dcu-cli.exe", false);
        found.extend(crate::util::find_in_path("dcu-cli"));
        found
    },
    args: |work| {
        vec![
            "/applyUpdates".into(),
            "-silent".into(),
            "-reboot=disable".into(),
            // Dell's own BitLocker handling, on top of ITriage's (it's the
            // tool's default; said out loud here).
            "-autoSuspendBitLocker=enable".into(),
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
    restart_unreported: false,
};

const HP: OemTool = OemTool {
    tool: "HP Image Assistant",
    candidates: hpia_candidates,
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
    restart_unreported: false,
};

const LENOVO: OemTool = OemTool {
    tool: "Lenovo Thin Installer",
    candidates: || in_program_files(r"Lenovo\ThinInstaller\ThinInstaller.exe", true),
    args: |_| {
        ["/CM", "-search", "A", "-action", "INSTALL", "-noicon", "-includerebootpackages", "1,3,4", "-noreboot"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    },
    exit_codes: &[(0, Severity::Ok, "completed")],
    restart_codes: &[],
    get_it: "install Lenovo Thin Installer for unattended BIOS and firmware updates",
    // Run with -noreboot, it exits 0 whether or not a package it installed
    // needs a restart.
    restart_unreported: true,
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
    /// Installed where a standard user could have replaced it, so an
    /// elevated ITriage won't start it. The path, and what's wrong with it.
    Untrusted(PathBuf, String),
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
                Located::Trusted(path) => ToolState::Ready(path),
                Located::Untrusted(path, why) => ToolState::Untrusted(path, why),
                Located::Missing if self.winget_id == Some("Lenovo.SystemUpdate") && lenovo_system_update().is_some() => {
                    ToolState::Installed("Lenovo System Update")
                }
                Located::Missing => ToolState::Missing,
            },
            _ => ToolState::Missing,
        }
    }
}

fn lenovo_system_update() -> Option<PathBuf> {
    in_program_files(r"Lenovo\System Update\tvsu.exe", true).into_iter().find(|p| p.is_file())
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

/// A fresh folder for one run of a vendor tool: its logs, reports and the
/// packages it downloads and then runs as an administrator. So nobody else
/// may write there, before or during the run: the folder is new, under a
/// parent nobody else can rename, and locked to administrators before the
/// tool is given its path.
#[cfg(windows)]
pub fn work_dir() -> Result<PathBuf, String> {
    use crate::win::dirs::{program_data, windows};
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let name = format!("work-{:x}-{:x}", crate::util::now_epoch(), (stamp as u64) ^ (u64::from(std::process::id()) << 32));
    let mut problem = String::from("no folder could be created");
    // The usual place, unless a user got there first and owns it.
    for base in [program_data().join("itriage"), windows().join("Temp")] {
        if let Err(e) = std::fs::create_dir_all(&base) {
            problem = format!("can't create {}: {e}", base.display());
            continue;
        }
        if let Err(why) = crate::trust::folder_base(&base) {
            problem = why;
            continue;
        }
        let dir = base.join(&name);
        if let Err(e) = std::fs::create_dir(&dir) {
            problem = format!("can't create {}: {e}", dir.display());
            continue;
        }
        crate::win::trust::admins_only(&dir)?;
        // Anything that slipped in between creating it and locking it.
        let empty = std::fs::read_dir(&dir).map(|mut d| d.next().is_none()).unwrap_or(false);
        if !empty {
            return Err(format!("{} wasn't empty after it was created; not using it.", dir.display()));
        }
        return Ok(dir);
    }
    Err(format!("No safe folder for the tool's files: {problem}."))
}

/// May an elevated ITriage start this program?
#[cfg(windows)]
fn trusted(path: &Path) -> Result<(), String> {
    crate::trust::program(path)
}

#[cfg(not(windows))]
fn trusted(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// `rel` under Program Files and Program Files (x86), in that order unless
/// `x86_first`. Asked of Windows, not read from the environment.
#[cfg(windows)]
fn in_program_files(rel: &str, x86_first: bool) -> Vec<PathBuf> {
    use crate::win::dirs::{program_files, program_files_x86};
    let mut bases = vec![program_files(), program_files_x86()];
    if x86_first {
        bases.reverse();
    }
    bases.into_iter().flatten().map(|b| b.join(rel)).collect()
}

#[cfg(not(windows))]
fn in_program_files(_rel: &str, _x86_first: bool) -> Vec<PathBuf> {
    Vec::new()
}

/// HPIA has no fixed install location: it's a self-extracting SoftPaq that
/// lands in `C:\SWSetup\SP<number>\` by default, or wherever IT put it.
/// Program Files comes first, as the only one of these a standard user
/// can't write to.
#[cfg(windows)]
fn hpia_candidates() -> Vec<PathBuf> {
    const EXE: &str = "HPImageAssistant.exe";
    let root = PathBuf::from(format!("{}\\", crate::win::dirs::system_drive()));
    let mut found = in_program_files(&format!(r"HP\HPIA\{EXE}"), false);
    found.push(root.join("HP").join("HPIA").join(EXE));
    if let Ok(entries) = std::fs::read_dir(root.join("SWSetup")) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("SP") {
                found.push(entry.path().join(EXE));
            }
        }
    }
    found.extend(crate::util::find_in_path("HPImageAssistant"));
    found
}

#[cfg(not(windows))]
fn hpia_candidates() -> Vec<PathBuf> {
    Vec::new()
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
