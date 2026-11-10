//! Clear temp files. MUTATING. Invoke-EndpointTuneUp's temp cleanup:
//!
//! * Windows: every profile's `AppData\Local\Temp` plus `C:\Windows\Temp`
//!   when elevated; just this account's temp folder otherwise.
//! * Linux: this account's own files in its temp directory.
//!
//! Only files whose creation *and* last-write times are older than the site
//! profile's minimum age (24 hours by default) are deleted, so installers and
//! apps that are running right now keep their files. Links and reparse
//! points are never followed, a folder is removed only once it's empty, and
//! files that are in use are skipped and counted, not treated as failures.
//! Free space on the system drive is reported before and after.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::{human_bytes, plural};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub struct ClearTemp;

/// What one folder's cleanup did (or would do, in a preview).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Counts {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Newer than the minimum age, so kept.
    pub recent: u64,
    /// Symlinks, junctions and other reparse points, never followed.
    pub links: u64,
    /// In use by a running program.
    pub locked: u64,
    /// Gone before we got to it.
    pub missing: u64,
    pub failed: u64,
    pub errors: Vec<String>,
}

impl TriageModule for ClearTemp {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Deletes temp files older than a day from every user profile and C:\\Windows\\Temp (only your own without admin). Skips files in use."
        } else {
            "Deletes your own temp files older than a day. Skips files in use."
        };
        ModuleInfo::new("fix.temp", "Clear temp files", Category::Fixes, description)
            .mutating()
            .warning("Permanently deletes temp files older than a day. Files in use are skipped.")
    }

    fn preview(&self, ctx: &RunContext) -> Result<Output, String> {
        run(ctx, true)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        run(ctx, false)
    }
}

fn run(ctx: &RunContext, dry_run: bool) -> Result<Output, String> {
    let hours = ctx.profile().cleanup.temp_min_age_hours;
    let cutoff = SystemTime::now() - Duration::from_secs(u64::from(hours) * 3600);
    let (targets, note) = targets();
    let free_before = free_space();
    let mut findings = Vec::new();
    let mut total = Counts::default();
    for dir in &targets {
        ctx.log(format!("{} {}", if dry_run { "Checking" } else { "Clearing" }, dir.display()));
        let c = clean(dir, cutoff, dry_run);
        findings.push(folder_finding(dir, &c, dry_run));
        total.files += c.files;
        total.dirs += c.dirs;
        total.bytes += c.bytes;
        total.failed += c.failed;
    }
    if let Some(n) = note {
        findings.push(Finding::info("Not included", n));
    }
    if targets.is_empty() {
        findings.push(Finding::info("Temp folders", "none found"));
    }
    let n = targets.len();
    let summary = if dry_run {
        format!(
            "Preview: would delete {} file{} ({}) from {n} folder{}. Nothing was changed.",
            total.files,
            plural(total.files as usize),
            human_bytes(total.bytes),
            plural(n)
        )
    } else {
        if let (Some((label, before)), Some((_, after))) = (free_before, free_space()) {
            findings.push(Finding::info(format!("Free space ({label})"), format!("{} → {}", human_bytes(before), human_bytes(after))));
        }
        format!("Freed {} from {n} temp folder{} ({} files removed)", human_bytes(total.bytes), plural(n), total.files)
    };
    Ok(Output::new(summary, findings))
}

fn folder_finding(dir: &Path, c: &Counts, dry_run: bool) -> Finding {
    let mut kept = Vec::new();
    if c.recent > 0 {
        kept.push(format!("{} recent kept", c.recent));
    }
    if c.locked > 0 {
        kept.push(format!("{} in use", c.locked));
    }
    if c.links > 0 {
        kept.push(format!("{} link{} skipped", c.links, plural(c.links as usize)));
    }
    if c.failed > 0 {
        kept.push(format!("{} failed", c.failed));
    }
    let verb = if dry_run { "would delete" } else { "deleted" };
    let mut value = format!("{verb} {} file{} ({})", c.files, plural(c.files as usize), human_bytes(c.bytes));
    if c.dirs > 0 {
        value.push_str(&format!(" and {} empty folder{}", c.dirs, plural(c.dirs as usize)));
    }
    if !kept.is_empty() {
        value.push_str(&format!(" · {}", kept.join(" · ")));
    }
    let severity = if c.failed > 0 { Severity::Warning } else if dry_run { Severity::Info } else { Severity::Ok };
    Finding::new(dir.display().to_string(), value, severity).with_detail(c.errors.join(" | "))
}

#[cfg(test)]
static TEST_TARGET: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// The folders to clean, and a note about any left out.
fn targets() -> (Vec<PathBuf>, Option<String>) {
    #[cfg(test)]
    if let Some(dir) = TEST_TARGET.lock().unwrap().clone() {
        return (vec![dir], None);
    }
    os_targets()
}

#[cfg(windows)]
fn os_targets() -> (Vec<PathBuf>, Option<String>) {
    if !crate::host::is_elevated() {
        return (
            vec![std::env::temp_dir()],
            Some("other profiles and C:\\Windows\\Temp need administrator rights".into()),
        );
    }
    let mut out = vec![crate::win::dirs::windows().join("Temp")];
    let drive = crate::fixes::maintenance::system_drive();
    if let Ok(users) = fs::read_dir(format!("{drive}\\Users")) {
        for u in users.flatten() {
            let temp = u.path().join(r"AppData\Local\Temp");
            if u.file_type().is_ok_and(|t| t.is_dir()) && temp.is_dir() {
                out.push(temp);
            }
        }
    }
    (out, None)
}

#[cfg(not(windows))]
fn os_targets() -> (Vec<PathBuf>, Option<String>) {
    if crate::host::is_elevated() {
        // As root, "our" files in a shared /tmp include system services'.
        return (
            Vec::new(),
            Some("skipped as root: the shared temp folder holds system services' files. Run ITriage as the user whose temp files should go".into()),
        );
    }
    (vec![std::env::temp_dir()], Some("other users' files and system folders are never touched".into()))
}

/// Free space on the system drive: label and bytes.
fn free_space() -> Option<(String, u64)> {
    let target = if cfg!(windows) {
        PathBuf::from(format!("{}\\", crate::fixes::maintenance::system_drive()))
    } else {
        std::env::temp_dir()
    };
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disks
        .iter()
        .filter(|d| target.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| (d.mount_point().display().to_string(), d.available_space()))
}

/// A symlink, junction or other reparse point: never followed or deleted.
fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// Only regular files and folders this account owns (Linux temp folders are
/// shared, and hold sockets and other users' files).
fn ours(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        (meta.is_file() || meta.is_dir()) && meta.uid() == me
    }
    #[cfg(not(unix))]
    {
        meta.is_file() || meta.is_dir()
    }
}

/// Created or changed after the cutoff.
pub fn is_recent(created: Option<SystemTime>, modified: Option<SystemTime>, cutoff: SystemTime) -> bool {
    created.is_some_and(|t| t > cutoff) || modified.is_some_and(|t| t > cutoff)
}

fn classify(e: &std::io::Error, path: &Path, c: &mut Counts) {
    match (e.kind(), e.raw_os_error()) {
        (std::io::ErrorKind::NotFound, _) => c.missing += 1,
        // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION: a program has it open.
        (_, Some(32 | 33)) if cfg!(windows) => c.locked += 1,
        _ => {
            c.failed += 1;
            if c.errors.len() < 20 {
                c.errors.push(format!("{} - {e}", path.display()));
            }
        }
    }
}

/// Clean one folder, depth first, keeping the folder itself.
pub fn clean(root: &Path, cutoff: SystemTime, dry_run: bool) -> Counts {
    struct Entry {
        path: PathBuf,
        /// The folder's own times from before its contents were cleaned.
        times: Option<(Option<SystemTime>, Option<SystemTime>)>,
        root: bool,
    }
    let mut c = Counts::default();
    let mut stack = vec![Entry { path: root.to_path_buf(), times: None, root: true }];
    while let Some(entry) = stack.pop() {
        let meta = match fs::symlink_metadata(&entry.path) {
            Ok(m) => m,
            Err(e) => {
                classify(&e, &entry.path, &mut c);
                continue;
            }
        };
        if is_link(&meta) {
            c.links += 1;
            continue;
        }
        if meta.is_dir() && entry.times.is_none() {
            // First visit: come back to the folder after its contents.
            let times = (meta.created().ok(), meta.modified().ok());
            let children = match fs::read_dir(&entry.path) {
                Ok(rd) => rd,
                Err(e) => {
                    classify(&e, &entry.path, &mut c);
                    continue;
                }
            };
            stack.push(Entry { path: entry.path.clone(), times: Some(times), root: entry.root });
            for child in children.flatten() {
                let path = child.path();
                // Top-level dot folders on Linux are the desktop's (.X11-unix,
                // .ICE-unix); systemd-private-* belong to running services.
                let name = child.file_name().to_string_lossy().into_owned();
                if cfg!(unix) && entry.root && (name.starts_with('.') || name.starts_with("systemd-private-") || name.starts_with("snap-private-tmp")) {
                    continue;
                }
                stack.push(Entry { path, times: None, root: false });
            }
            continue;
        }
        if entry.root || !ours(&meta) {
            continue;
        }
        let (created, modified) = entry.times.unwrap_or((meta.created().ok(), meta.modified().ok()));
        if is_recent(created, modified, cutoff) {
            c.recent += 1;
            continue;
        }
        if meta.is_dir() {
            // Only an empty folder goes, so anything new inside it stays.
            if dry_run || fs::read_dir(&entry.path).map(|mut rd| rd.next().is_some()).unwrap_or(true) {
                continue;
            }
            match fs::remove_dir(&entry.path) {
                Ok(()) => c.dirs += 1,
                Err(e) => classify(&e, &entry.path, &mut c),
            }
        } else if dry_run {
            c.files += 1;
            c.bytes += meta.len();
        } else {
            match fs::remove_file(&entry.path) {
                Ok(()) => {
                    c.files += 1;
                    c.bytes += meta.len();
                }
                Err(e) => classify(&e, &entry.path, &mut c),
            }
        }
    }
    c
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs::FileTimes;

    fn age(path: &Path, hours: u64) {
        let t = SystemTime::now() - Duration::from_secs(hours * 3600);
        fs::File::options().write(true).open(path).unwrap().set_times(FileTimes::new().set_modified(t)).unwrap();
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::current_dir().unwrap().join("target").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("nested")).unwrap();
        dir
    }

    #[test]
    fn keeps_recent_files_and_links() {
        let dir = scratch("itriage-temp-age");
        fs::write(dir.join("old.log"), vec![0u8; 2048]).unwrap();
        fs::write(dir.join("new.log"), vec![0u8; 10]).unwrap();
        fs::write(dir.join("nested").join("b.tmp"), vec![0u8; 1024]).unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("link")).unwrap();
        age(&dir.join("old.log"), 48);
        // A cutoff in the future makes everything old; one in the past keeps
        // what was just written. Creation times can't be backdated on Linux,
        // so the "old" file here is old only by its write time.
        let past = SystemTime::now() - Duration::from_secs(3600);
        let preview = clean(&dir, past, true);
        assert_eq!(preview.files, 0, "creation times are fresh, so nothing qualifies: {preview:?}");
        assert!(preview.recent >= 3);
        assert_eq!(preview.links, 1);

        let future = SystemTime::now() + Duration::from_secs(3600);
        let dry = clean(&dir, future, true);
        assert_eq!((dry.files, dry.bytes), (3, 3082));
        assert!(dir.join("old.log").exists(), "a preview deletes nothing");

        let done = clean(&dir, future, false);
        assert_eq!((done.files, done.bytes), (3, 3082));
        assert_eq!(done.dirs, 1, "the emptied nested folder goes too");
        assert!(dir.join("link").symlink_metadata().is_ok(), "links are left alone");
        assert!(fs::read_link(dir.join("link")).is_ok());
        assert!(dir.exists(), "the folder itself stays");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recency_needs_both_times_old() {
        let now = SystemTime::now();
        let old = now - Duration::from_secs(48 * 3600);
        let cutoff = now - Duration::from_secs(24 * 3600);
        assert!(!is_recent(Some(old), Some(old), cutoff));
        assert!(is_recent(Some(now), Some(old), cutoff));
        assert!(is_recent(Some(old), Some(now), cutoff));
        assert!(!is_recent(None, Some(old), cutoff));
    }

    #[test]
    fn the_module_clears_a_throwaway_temp_dir() {
        let dir = scratch("itriage-temp-module");
        fs::write(dir.join("a.log"), vec![0u8; 2048]).unwrap();
        *TEST_TARGET.lock().unwrap() = Some(dir.clone());
        let mut profile = crate::profile::Profile::default();
        profile.cleanup.temp_min_age_hours = 0;
        // Let the clock move past the files' times.
        std::thread::sleep(Duration::from_millis(20));
        let ctx = RunContext::silent().with_profile(&profile);
        let preview = ClearTemp.run(&RunContext::silent().with_profile(&profile).preview(true));
        let result = ClearTemp.run(&ctx);
        *TEST_TARGET.lock().unwrap() = None;
        assert!(preview.preview && preview.summary.starts_with("Preview: would delete 1 file"), "{}", preview.summary);
        assert!(result.error.is_none(), "{:?}", result.error);
        assert!(result.summary.starts_with("Freed 2.0 KB from 1 temp folder"), "{}", result.summary);
        assert!(!dir.join("a.log").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
