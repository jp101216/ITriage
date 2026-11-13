//! What's using the space on the system drive. Read-only.
//!
//! "The disk is full" is the start of the question. This adds up the places
//! that fill a workstation: each person's profile and the folders inside
//! it, the leftovers Windows keeps (an old installation, update downloads,
//! memory dumps, the Recycle Bin), temp folders, and the page and
//! hibernation files.
//!
//! It names folders, never files (three system files apart), and reads
//! sizes only: nothing is opened. It doesn't follow links or leave the
//! drive, cloud files that aren't downloaded count as nothing, and it stops
//! at a time limit and says what it didn't reach.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::human_bytes;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long the whole check may read the disk for.
const BUDGET: Duration = Duration::from_secs(25);
/// Rows shown: the biggest places, then one line for the rest.
const MAX_ROWS: usize = 14;
/// A folder inside a profile is named when it holds at least this much.
const WORTH_NAMING: u64 = 1 << 30;
const GB: u64 = 1 << 30;

pub struct StorageBreakdown;

impl TriageModule for StorageBreakdown {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "system.storage",
            "What's using the space",
            Category::System,
            "The biggest places on the system drive: each profile and its folders, old Windows installations, update downloads, memory dumps, the Recycle Bin, temp folders and the page file. Names folders, not files.",
        )
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let plan = plan();
        if !plan.root.exists() {
            return Err(format!("{} isn't there to measure.", plan.root.display()));
        }
        ctx.log(format!("Adding up folders on {} (up to {} s)…", plan.root.display(), BUDGET.as_secs()));
        let deadline = Instant::now() + BUDGET;
        let cancelled = || ctx.cancelled();
        let mut places = Vec::new();
        let mut skipped = Vec::new();
        for file in &plan.files {
            if let Some(bytes) = file_size(file) {
                places.push(Place::new(file, bytes, Kind::of(file)));
            }
        }
        // In order of how often the answer is there: the leftovers that can
        // simply be cleared, then people's own files, and the installed
        // software last, with whatever time is left.
        let whole = |folders: &[PathBuf], places: &mut Vec<Place>, skipped: &mut Vec<String>| {
            for folder in folders {
                if !folder.is_dir() {
                    continue;
                }
                if Instant::now() >= deadline || cancelled() {
                    skipped.push(folder.display().to_string());
                    continue;
                }
                if let Some(size) = measure(folder, deadline, &cancelled) {
                    places.push(Place::from(folder, size, Kind::of(folder)));
                }
            }
        };
        whole(&plan.leftovers, &mut places, &mut skipped);
        for home in &plan.profiles {
            if Instant::now() >= deadline || cancelled() {
                skipped.push(home.display().to_string());
                continue;
            }
            ctx.log(format!("Measuring {}…", home.display()));
            places.extend(profile(home, deadline, &cancelled));
        }
        whole(&plan.software, &mut places, &mut skipped);
        let (used, total) = drive_space(&plan.root);
        Ok(output(&plan.root, places, &skipped, used, total, ctx.cancelled()))
    }
}

/// What a place is, for the advice that goes with it.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Profile,
    Downloads,
    OldWindows,
    RecycleBin,
    Temp,
    UpdateDownloads,
    Dumps,
    PageFile,
    Hibernation,
    Logs,
    Cache,
    Other,
}

impl Kind {
    fn of(path: &Path) -> Kind {
        let text = path.to_string_lossy().to_ascii_lowercase().replace('\\', "/");
        let name = text.rsplit('/').find(|p| !p.is_empty()).unwrap_or_default().to_string();
        if name == "windows.old" {
            Kind::OldWindows
        } else if name == "$recycle.bin" || text.ends_with("/.local/share/trash") {
            Kind::RecycleBin
        } else if text.ends_with("/softwaredistribution/download") || text.ends_with("/var/cache/apt/archives") {
            Kind::UpdateDownloads
        } else if matches!(name.as_str(), "memory.dmp" | "minidump" | "livekernelreports") || text.ends_with("/var/crash") || text.ends_with("/var/lib/systemd/coredump") {
            Kind::Dumps
        } else if matches!(name.as_str(), "pagefile.sys" | "swapfile.sys" | "swapfile" | "swap.img") {
            Kind::PageFile
        } else if name == "hiberfil.sys" {
            Kind::Hibernation
        } else if matches!(name.as_str(), "temp" | "tmp") {
            Kind::Temp
        } else if name == "downloads" {
            Kind::Downloads
        } else if name == "logs" || text.ends_with("/var/log") {
            Kind::Logs
        } else if matches!(name.as_str(), ".cache" | "cache") || text.ends_with("/var/cache") {
            Kind::Cache
        } else {
            Kind::Other
        }
    }

    /// What can be done about this place, when something can. With the
    /// size at which it is worth a warning rather than a note.
    fn advice(self) -> Option<(&'static str, u64)> {
        Some(match self {
            Kind::OldWindows => ("The previous Windows installation, kept after an upgrade. Disk Cleanup (Clean up system files → Previous Windows installations) removes it; there's no going back to the old version afterwards.", GB),
            Kind::RecycleBin => ("Deleted files that still take space. Empty Recycle Bin (in the Tune-up checks) clears it.", 5 * GB),
            Kind::Temp => ("Temporary files. Clear temp files (in the Tune-up checks) removes the ones nothing is using.", 5 * GB),
            Kind::UpdateDownloads => ("Update files already downloaded. Clear temp files (in the Tune-up checks) removes the ones that have been installed.", 5 * GB),
            Kind::Dumps => ("Memory dumps from crashes. Keep the newest if the crash is still being looked into; the rest can go.", 2 * GB),
            Kind::Hibernation => ("Holds memory while the PC hibernates, and is as big as the memory in use. Turning hibernation off (powercfg /h off) removes it, and Fast Startup with it.", u64::MAX),
            Kind::PageFile if cfg!(windows) => ("Virtual memory. Windows sizes it; it shrinks after a restart when memory pressure has passed.", u64::MAX),
            Kind::PageFile => ("Swap space: memory kept on disk. Its size is set when it is created.", u64::MAX),
            Kind::Downloads => ("Installers and files saved from the web: the first place to look with the person whose PC it is.", 20 * GB),
            Kind::Logs | Kind::Cache | Kind::Profile | Kind::Other => return None,
        })
    }
}

/// One measured place.
#[derive(Debug, Clone, PartialEq)]
struct Place {
    path: PathBuf,
    bytes: u64,
    kind: Kind,
    /// Folders inside it that couldn't be read (no permission).
    unread: u64,
    /// The time ran out inside it: it holds at least `bytes`.
    partial: bool,
}

impl Place {
    fn new(path: &Path, bytes: u64, kind: Kind) -> Place {
        Place { path: path.to_path_buf(), bytes, kind, unread: 0, partial: false }
    }
    fn from(path: &Path, size: Size, kind: Kind) -> Place {
        Place { path: path.to_path_buf(), bytes: size.bytes, kind, unread: size.unread, partial: size.partial }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Size {
    pub(crate) bytes: u64,
    pub(crate) files: u64,
    pub(crate) unread: u64,
    pub(crate) partial: bool,
}

/// Where to look on this system.
struct Plan {
    root: PathBuf,
    /// Single files that are worth a row.
    files: Vec<PathBuf>,
    /// Leftovers and logs, one figure each: quick to add up, and where the
    /// space that can simply be cleared is.
    leftovers: Vec<PathBuf>,
    /// Home folders, measured folder by folder.
    profiles: Vec<PathBuf>,
    /// Installed software and its data, one figure each: slow to add up, so
    /// last.
    software: Vec<PathBuf>,
}

#[cfg(windows)]
fn plan() -> Plan {
    let drive = std::env::var("SystemDrive").ok().filter(|d| d.len() == 2 && d.ends_with(':')).unwrap_or_else(|| "C:".into());
    let root = PathBuf::from(format!("{drive}\\"));
    let at = |rest: &str| root.join(rest);
    let mut profiles: Vec<PathBuf> = std::fs::read_dir(at("Users"))
        .map(|dir| {
            dir.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink()))
                .map(|e| e.path())
                .filter(|p| {
                    let name = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                    !matches!(name.as_str(), "default" | "default user" | "all users" | "public")
                })
                .collect()
        })
        .unwrap_or_default();
    profiles.sort();
    Plan {
        files: vec![at("pagefile.sys"), at("hiberfil.sys"), at("swapfile.sys"), at("Windows\\MEMORY.DMP")],
        leftovers: vec![
            at("Windows.old"),
            at("$Recycle.Bin"),
            at("Windows\\Temp"),
            at("Windows\\SoftwareDistribution\\Download"),
            at("Windows\\Minidump"),
            at("Windows\\LiveKernelReports"),
            at("Windows\\Logs"),
            at("Users\\Public"),
        ],
        software: vec![at("ProgramData"), at("Program Files"), at("Program Files (x86)")],
        profiles,
        root,
    }
}

#[cfg(not(windows))]
fn plan() -> Plan {
    let mut profiles: Vec<PathBuf> = std::fs::read_dir("/home")
        .map(|dir| dir.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()).collect())
        .unwrap_or_default();
    profiles.sort();
    if Path::new("/root").is_dir() {
        profiles.push(PathBuf::from("/root"));
    }
    Plan {
        root: PathBuf::from("/"),
        files: vec![PathBuf::from("/swapfile"), PathBuf::from("/swap.img")],
        leftovers: ["/var/log", "/var/cache", "/var/tmp", "/tmp", "/var/crash", "/var/lib/systemd/coredump"].iter().map(PathBuf::from).collect(),
        software: ["/var/lib/docker", "/var/lib/snapd", "/var/lib/flatpak", "/opt", "/usr"].iter().map(PathBuf::from).collect(),
        profiles,
    }
}

/// Space in use and the size of the volume `root` is on.
fn drive_space(root: &Path) -> (u64, u64) {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disks
        .iter()
        .filter(|d| root.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| (d.total_space().saturating_sub(d.available_space()), d.total_space()))
        .unwrap_or((0, 0))
}

/// The space a file takes, or `None` when it isn't there (or can't be asked).
fn file_size(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    meta.is_file().then(|| on_disk(&meta))
}

/// The space a file really takes. A cloud file that hasn't been downloaded
/// reports its full size and takes none; a sparse file on Linux likewise.
#[cfg(windows)]
fn on_disk(meta: &std::fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    const OFFLINE: u32 = 0x1000;
    const RECALL_ON_OPEN: u32 = 0x0004_0000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    if meta.file_attributes() & (OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0 {
        0
    } else {
        meta.len()
    }
}

#[cfg(not(windows))]
fn on_disk(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks().saturating_mul(512)
}

/// The volume a folder is on, so the walk can stay on it.
#[cfg(not(windows))]
fn volume(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.dev()
}

/// On Windows another volume is reached through a mount point or a
/// junction, and neither is followed.
#[cfg(windows)]
fn volume(_: &std::fs::Metadata) -> u64 {
    0
}

/// Everything under `dir`, or `None` when it isn't a folder. Links aren't
/// followed and other volumes aren't entered. Stops at `deadline` (or when
/// `cancelled` says so) with what it has, marked partial.
pub(crate) fn measure(dir: &Path, deadline: Instant, cancelled: &dyn Fn() -> bool) -> Option<Size> {
    let top = std::fs::symlink_metadata(dir).ok()?;
    if !top.is_dir() || top.file_type().is_symlink() {
        return None;
    }
    let home = volume(&top);
    let mut size = Size::default();
    let mut pending = vec![dir.to_path_buf()];
    let mut seen = 0u32;
    while let Some(folder) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            size.unread += 1;
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen.is_multiple_of(512) && (Instant::now() >= deadline || cancelled()) {
                size.partial = true;
                return Some(size);
            }
            // The entry's own type: a link is a link, whatever it points at.
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_symlink() {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if kind.is_dir() {
                if volume(&meta) == home {
                    pending.push(entry.path());
                }
            } else if kind.is_file() {
                size.bytes += on_disk(&meta);
                size.files += 1;
            }
        }
    }
    Some(size)
}

/// One home folder: its total, and each folder directly inside it that's
/// big enough to name.
fn profile(home: &Path, deadline: Instant, cancelled: &dyn Fn() -> bool) -> Vec<Place> {
    let Ok(entries) = std::fs::read_dir(home) else {
        // Someone else's profile, without the rights to look inside.
        return vec![Place { path: home.to_path_buf(), bytes: 0, kind: Kind::Profile, unread: 1, partial: false }];
    };
    let mut whole = Place::new(home, 0, Kind::Profile);
    let mut inside = Vec::new();
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_file() {
            whole.bytes += entry.metadata().map(|m| on_disk(&m)).unwrap_or(0);
            continue;
        }
        if Instant::now() >= deadline || cancelled() {
            whole.partial = true;
            break;
        }
        let path = entry.path();
        // AppData is where the caches are: one level further in is more use
        // than one figure for all of it.
        let children: Vec<PathBuf> = if entry.file_name().eq_ignore_ascii_case("AppData") {
            ["Local", "LocalLow", "Roaming"].iter().map(|c| path.join(c)).collect()
        } else {
            vec![path]
        };
        for child in children {
            let Some(size) = measure(&child, deadline, cancelled) else { continue };
            whole.bytes += size.bytes;
            whole.unread += size.unread;
            whole.partial |= size.partial;
            if size.bytes >= WORTH_NAMING {
                inside.push(Place::from(&child, size, Kind::of(&child)));
            }
        }
    }
    let mut out = vec![whole];
    out.append(&mut inside);
    out
}

fn output(root: &Path, mut places: Vec<Place>, skipped: &[String], used: u64, total: u64, cancelled: bool) -> Output {
    places.retain(|p| p.bytes > 0 || p.unread > 0);
    places.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.path.cmp(&b.path)));
    let share = |bytes: u64| {
        let percent = if used > 0 { (bytes as f64 / used as f64 * 100.0).min(100.0) } else { 0.0 };
        // Under one percent, the size says it all.
        if percent >= 1.0 {
            format!(" · {percent:.0}% of what's in use")
        } else {
            String::new()
        }
    };
    let mut findings = Vec::new();
    if total > 0 {
        findings.push(Finding::info(
            format!("{} in use", root.display()),
            format!("{} of {} ({:.0}%)", human_bytes(used), human_bytes(total), used as f64 / total as f64 * 100.0),
        ));
    }
    let shown: Vec<&Place> = places.iter().filter(|p| p.bytes > 0).take(MAX_ROWS).collect();
    for place in &shown {
        let advice = place.kind.advice();
        let severity = match advice {
            Some((_, worth_a_warning)) if place.bytes >= worth_a_warning => Severity::Warning,
            _ => Severity::Info,
        };
        let label = if place.kind == Kind::Profile { format!("{} (whole profile)", place.path.display()) } else { place.path.display().to_string() };
        let mut notes: Vec<String> = advice.map(|(text, _)| text.to_string()).into_iter().collect();
        if place.partial {
            notes.push("The time limit ran out inside this folder: it holds at least this much.".into());
        }
        if place.unread > 0 {
            notes.push(format!(
                "{} folder{} inside couldn't be read without more rights, so the real figure is higher.",
                place.unread,
                if place.unread == 1 { "" } else { "s" }
            ));
        }
        let value = format!("{}{}{}", if place.partial { "at least " } else { "" }, human_bytes(place.bytes), share(place.bytes));
        let mut finding = Finding::new(label, value, severity);
        if !notes.is_empty() {
            finding = finding.with_detail(notes.join(" "));
        }
        findings.push(finding);
    }
    let rest: Vec<&Place> = places.iter().filter(|p| p.bytes > 0).skip(MAX_ROWS).collect();
    if !rest.is_empty() {
        findings.push(Finding::info(
            "Smaller places",
            format!("{} more, {} between them", rest.len(), human_bytes(rest.iter().map(|p| p.bytes).sum())),
        ));
    }
    let closed: Vec<String> = places.iter().filter(|p| p.bytes == 0 && p.unread > 0).map(|p| p.path.display().to_string()).collect();
    if !closed.is_empty() {
        findings.push(
            Finding::info("Couldn't look inside", closed.join(", ")).with_detail(if cfg!(windows) {
                "Run ITriage as administrator to measure other people's profiles and the system folders."
            } else {
                "Run ITriage as root (sudo) to measure other people's home folders and the system folders."
            }),
        );
    }
    if !skipped.is_empty() {
        findings.push(Finding::info(
            "Not measured",
            format!("{} ({})", skipped.join(", "), if cancelled { "the run was stopped" } else { "the time limit ran out" }),
        ));
    }
    findings.push(Finding::info(
        "What this counts",
        "Folders are added up file by file; profiles appear whole and again by folder, so rows overlap. Links aren't followed, other drives aren't entered, and cloud files that aren't downloaded count as nothing. The Windows folder itself and installed apps' own data aren't broken down.",
    ));
    let biggest = shown.iter().find(|p| p.kind != Kind::Profile).or(shown.first());
    let summary = match biggest {
        Some(p) => format!("Biggest: {} · {}", p.path.display(), human_bytes(p.bytes)),
        None => "Nothing measurable was found".to_string(),
    };
    Output::new(summary, findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str) -> PathBuf {
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-storage-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, bytes: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    const NEVER: fn() -> bool = || false;

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn adds_up_a_folder_without_following_links() {
        let dir = tree("measure");
        write(&dir.join("a/one.bin"), 100_000);
        write(&dir.join("a/deep/er/two.bin"), 50_000);
        write(&dir.join("elsewhere/big.bin"), 400_000);
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("a/link")).unwrap();
        let size = measure(&dir.join("a"), later(), &NEVER).unwrap();
        assert_eq!(size.files, 2, "the link to the big folder isn't followed");
        // Whole blocks on disk: at least the bytes written, and nowhere near the linked folder's.
        assert!((150_000..300_000).contains(&size.bytes), "{}", size.bytes);
        assert!(!size.partial && size.unread == 0);
        assert_eq!(measure(&dir.join("missing"), later(), &NEVER), None);
        assert_eq!(measure(&dir.join("a/one.bin"), later(), &NEVER), None, "a file isn't a folder");
        assert_eq!(file_size(&dir.join("a")), None);
        assert!(file_size(&dir.join("a/one.bin")).unwrap() >= 100_000);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stops_at_the_time_limit_with_what_it_has() {
        let dir = tree("budget");
        for i in 0..1_200 {
            write(&dir.join(format!("f{}/{i}.bin", i % 3)), 10);
        }
        let past = Instant::now() - Duration::from_secs(1);
        let size = measure(&dir, past, &NEVER).unwrap();
        assert!(size.partial && size.files < 1_200, "{size:?}");
        let stopped = measure(&dir, later(), &|| true).unwrap();
        assert!(stopped.partial, "a stopped run ends the walk too");
        assert!(!measure(&dir, later(), &NEVER).unwrap().partial);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_profile_is_measured_whole_and_by_folder() {
        let dir = tree("profile");
        let home = dir.join("jparker");
        write(&home.join("Downloads/setup.bin"), 300_000);
        write(&home.join("Documents/notes.bin"), 20_000);
        write(&home.join("AppData/Local/cache.bin"), 60_000);
        write(&home.join("ntuser.bin"), 5_000);
        let places = profile(&home, later(), &NEVER);
        // Nothing here reaches the size worth naming, so only the total comes back.
        assert_eq!(places.len(), 1);
        assert_eq!(places[0].kind, Kind::Profile);
        assert!(places[0].bytes >= 385_000, "{}", places[0].bytes);
        // A profile that can't be opened is reported, not silently counted as empty.
        let closed = profile(&dir.join("nobody-here"), later(), &NEVER);
        assert_eq!((closed[0].bytes, closed[0].unread), (0, 1));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn knows_what_each_place_is() {
        for (path, kind) in [
            ("C:\\Windows.old", Kind::OldWindows),
            ("C:\\$Recycle.Bin", Kind::RecycleBin),
            ("C:\\Windows\\SoftwareDistribution\\Download", Kind::UpdateDownloads),
            ("C:\\Windows\\MEMORY.DMP", Kind::Dumps),
            ("C:\\hiberfil.sys", Kind::Hibernation),
            ("C:\\pagefile.sys", Kind::PageFile),
            ("C:\\Windows\\Temp", Kind::Temp),
            ("C:\\Users\\jparker\\Downloads", Kind::Downloads),
            ("/home/jparker/.cache", Kind::Cache),
            ("/var/log", Kind::Logs),
            ("/var/crash", Kind::Dumps),
            ("/tmp", Kind::Temp),
            ("C:\\Program Files", Kind::Other),
        ] {
            assert_eq!(Kind::of(Path::new(path)), kind, "{path}");
        }
    }

    #[test]
    fn the_report_leads_with_the_biggest_and_says_what_to_do() {
        let place = |path: &str, gb: u64, kind: Kind| Place::new(Path::new(path), gb * GB, kind);
        let mut places = vec![
            place("C:\\Users\\jparker", 120, Kind::Profile),
            place("C:\\Users\\jparker\\Downloads", 48, Kind::Downloads),
            place("C:\\Windows.old", 24, Kind::OldWindows),
            place("C:\\hiberfil.sys", 13, Kind::Hibernation),
            place("C:\\Windows\\Temp", 2, Kind::Temp),
            Place { path: PathBuf::from("C:\\Users\\asmith"), bytes: 0, kind: Kind::Profile, unread: 1, partial: false },
        ];
        places.push(Place { partial: true, unread: 2, ..place("C:\\ProgramData", 9, Kind::Other) });
        let out = output(Path::new("C:\\"), places, &["C:\\Program Files".to_string()], 230 * GB, 256 * GB, false);
        assert_eq!(out.summary, "Biggest: C:\\Users\\jparker\\Downloads · 48.0 GB", "a folder is more use than a whole profile");
        let get = |label: &str| out.findings.iter().find(|f| f.label == label).unwrap_or_else(|| panic!("no {label}"));
        assert_eq!(get("C:\\ in use").value, "230.0 GB of 256.0 GB (90%)");
        assert_eq!(out.findings[1].label, "C:\\Users\\jparker (whole profile)");
        assert_eq!(out.findings[1].value, "120.0 GB · 52% of what's in use");
        let downloads = get("C:\\Users\\jparker\\Downloads");
        assert_eq!(downloads.severity, Severity::Warning);
        let old = get("C:\\Windows.old");
        assert_eq!(old.severity, Severity::Warning);
        assert!(old.detail.as_deref().unwrap().contains("Disk Cleanup"));
        assert_eq!(get("C:\\hiberfil.sys").severity, Severity::Info, "big by design");
        assert_eq!(get("C:\\Windows\\Temp").severity, Severity::Info, "2 GB of temp files isn't worth a warning");
        let data = get("C:\\ProgramData");
        assert!(data.value.starts_with("at least 9.0 GB"));
        assert!(data.detail.as_deref().unwrap().contains("2 folders inside couldn't be read"));
        assert_eq!(get("Couldn't look inside").value, "C:\\Users\\asmith");
        assert_eq!(get("Not measured").value, "C:\\Program Files (the time limit ran out)");
        // With more places than rows, the rest are one line.
        let many: Vec<Place> = (0..20).map(|i| place(&format!("C:\\Data\\{i:02}"), 20 - i, Kind::Other)).collect();
        let out = output(Path::new("C:\\"), many, &[], 0, 0, false);
        assert_eq!(out.findings.iter().filter(|f| f.label.starts_with("C:\\Data")).count(), MAX_ROWS);
        assert_eq!(out.findings.iter().find(|f| f.label == "Smaller places").unwrap().value, "6 more, 21.0 GB between them");
    }
}
