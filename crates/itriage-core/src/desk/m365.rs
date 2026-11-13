//! Outlook, Teams and OneDrive. Read-only, Windows only.
//!
//! The Tier 1 calls about Microsoft 365: an Outlook data file that's full,
//! an Office install on the wrong update channel or too old for the site,
//! Desktop and Documents moved into OneDrive while OneDrive isn't running
//! (so nothing is syncing), a Teams cache to clear, and the Entra sign-in
//! broker failing ("Need password" over and over).
//!
//! Everything is read for the person signed in at this PC, from their own
//! registry hive and profile folder, even when ITriage runs as another
//! account (an elevated technician sign-in reads its own HKCU otherwise).

use crate::model::{Category, Finding, KbLink, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::parse::office;
use crate::parse::time::epoch_to_rfc3339;
use crate::util::{ago, human_bytes, plural};

pub struct Microsoft365;

impl TriageModule for Microsoft365 {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "desk.m365",
            "Outlook, Teams & OneDrive",
            Category::Workstation,
            "Outlook data files against their size limit, the Microsoft 365 Apps version and update channel, Desktop and Documents in OneDrive without OneDrive running, the Teams cache, and Entra sign-in broker errors.",
        )
        .only("windows")
    }

    #[cfg(windows)]
    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let office_min = ctx
            .profile()
            .require
            .app
            .iter()
            .find(|a| {
                let n = a.name.to_ascii_lowercase();
                n.contains("microsoft 365") || n.contains("office")
            })
            .and_then(|a| a.min_version.clone().map(|v| (a.label.clone().unwrap_or_else(|| a.name.clone()), v)));
        let facts = imp::gather(office_min)?;
        let rows = findings(&facts, crate::util::now_epoch());
        let attention = rows.iter().filter(|f| f.severity.rank() >= Severity::Warning.rank()).count();
        Ok(Output::new(
            match attention {
                0 => "Outlook, Teams and OneDrive look healthy".to_string(),
                n => format!("{n} Microsoft 365 finding{} need{} attention", plural(n), if n == 1 { "s" } else { "" }),
            },
            rows,
        ))
    }

    #[cfg(not(windows))]
    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        Err("The Outlook, Teams and OneDrive checks are Windows-only.".into())
    }
}

/// What was found for the signed-in person. Plain data, so the grading is
/// tested on any OS.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Facts {
    pub user: String,
    /// Outlook data files: path and size.
    pub data_files: Vec<(String, u64)>,
    pub warn_mb: u64,
    pub max_mb: u64,
    pub limits_from_policy: bool,
    pub office_version: Option<String>,
    pub office_channel: Option<String>,
    pub office_platform: Option<String>,
    /// A required app that is Office, with its minimum version.
    pub office_min: Option<(String, String)>,
    /// The OneDrive for work folder, when OneDrive is set up.
    pub onedrive_folder: Option<String>,
    /// Desktop, Documents, Pictures: whether each is inside OneDrive.
    pub known_folders: Vec<(&'static str, bool)>,
    pub onedrive_running: bool,
    pub teams_cache: Option<u64>,
    pub teams_running: bool,
    pub classic_teams_left: bool,
    /// Entra (AAD) Operational errors in the last day: when and what.
    pub aad_errors: Vec<(u64, String)>,
    pub broker_present: bool,
    /// A client edition of Windows. The broker isn't expected on a server.
    pub workstation: bool,
}

const PRT_ARTICLE: &str = "https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-primary-refresh-token";

pub fn findings(f: &Facts, now: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    for (path, size) in &f.data_files {
        let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
        let (severity, words) = office::data_file(*size, f.warn_mb, f.max_mb);
        out.push(
            Finding::new(format!("Outlook data file: {name}"), words, severity)
                .with_detail(format!(
                    "{path} · limit {} MB, warning at {} MB ({})",
                    f.max_mb,
                    f.warn_mb,
                    if f.limits_from_policy { "set by policy" } else { "Outlook's defaults" }
                ))
                .with_metric(*size as f64 / 1_073_741_824.0, "GB", true),
        );
    }
    if let Some(version) = &f.office_version {
        let mut words = vec![version.clone()];
        words.extend(f.office_channel.clone());
        words.extend(f.office_platform.clone());
        let behind = f.office_min.as_ref().filter(|(_, min)| !crate::parse::version::meets(version, min));
        out.push(match behind {
            Some((label, min)) => Finding::warn("Microsoft 365 Apps", format!("{} · needs {min} or later", words.join(" · ")))
                .with_detail(format!("The site profile requires {label} {min}. Click-to-Run updates on its channel's schedule; a channel that's too slow keeps it behind.")),
            None => Finding::info("Microsoft 365 Apps", words.join(" · ")),
        });
    } else if !f.data_files.is_empty() {
        out.push(Finding::info("Microsoft 365 Apps", "no Click-to-Run install found (MSI or Store Office, or none)"));
    }
    match &f.onedrive_folder {
        None => out.push(Finding::info("OneDrive", "OneDrive for work isn't set up for this user")),
        Some(folder) => {
            let moved: Vec<&str> = f.known_folders.iter().filter(|(_, inside)| *inside).map(|(n, _)| *n).collect();
            if moved.is_empty() {
                out.push(Finding::info("OneDrive folder backup", "Desktop, Documents and Pictures stay on this PC").with_detail(format!("OneDrive folder: {folder}")));
            } else if !f.onedrive_running {
                out.push(
                    Finding::warn("OneDrive folder backup", format!("{} {} in OneDrive, but OneDrive isn't running", moved.join(", "), if moved.len() == 1 { "is" } else { "are" }))
                        .with_detail(format!("Nothing in them is syncing, so it isn't backed up and other devices don't see it. Start OneDrive from the Start menu and sign in. OneDrive folder: {folder}")),
                );
            } else {
                out.push(Finding::ok("OneDrive folder backup", format!("{} in OneDrive, and OneDrive is running", moved.join(", "))).with_detail(format!("OneDrive folder: {folder}")));
            }
        }
    }
    if let Some(size) = f.teams_cache {
        let mut row = Finding::info("Teams cache", format!("{}{}", human_bytes(size), if f.teams_running { " · Teams is running" } else { "" }))
            .with_detail("Clearing it is Microsoft's fix when Teams won't start, sign in or update. It's not for missing messages or chats: it deletes the logs needed to find out why.")
            .with_metric(size as f64 / 1_048_576.0, "MB", true);
        if size > 0 {
            row = row.with_action(crate::actions::offer("clear-teams-cache", None));
        }
        out.push(row);
    }
    if f.classic_teams_left {
        out.push(Finding::info("Classic Teams", "its folder is still in AppData\\Roaming\\Microsoft\\Teams").with_detail("Classic Teams is retired; the folder is left over and can be removed once new Teams works."));
    }
    if !f.broker_present && f.workstation {
        out.push(
            Finding::crit("Entra sign-in broker", "Microsoft.AAD.BrokerPlugin is missing").with_detail("Without it, Microsoft 365 apps can't sign in with the Windows account. Don't re-register it by script; follow Microsoft's guidance."),
        );
    }
    if !f.aad_errors.is_empty() {
        let last = f.aad_errors.iter().map(|(t, _)| *t).max().unwrap_or(now);
        let mut kinds: Vec<&str> = f.aad_errors.iter().map(|(_, e)| e.as_str()).collect();
        kinds.sort();
        let common = kinds.iter().copied().max_by_key(|k| kinds.iter().filter(|x| x == &k).count()).unwrap_or_default();
        let mut row = Finding::new(
            "Entra sign-in errors (24 h)",
            format!("{} error{} · last {}", f.aad_errors.len(), plural(f.aad_errors.len()), ago(now.saturating_sub(last))),
            if f.aad_errors.len() >= 10 { Severity::Warning } else { Severity::Info },
        )
        .with_detail(format!("Most common: {common}. Microsoft-Windows-AAD/Operational, last at {} UTC. A few a day is normal; many in a row, with Outlook or Teams asking for the password again and again, is the broken sign-in token Microsoft's article covers.", epoch_to_rfc3339(last)));
        row.kb = Some(KbLink { title: "Troubleshoot primary refresh token issues (Microsoft)".into(), url: PRT_ARTICLE.into() });
        out.push(row);
    }
    if out.is_empty() {
        out.push(Finding::info("Microsoft 365", format!("nothing found for {}", if f.user.is_empty() { "this user" } else { &f.user })));
    }
    out
}

/// "%USERPROFILE%\\OneDrive - Contoso\\Desktop" with the person's own profile
/// folder put in, compared case-insensitively against their OneDrive folder.
pub fn inside(folder: &str, profile: &str, onedrive: &str) -> bool {
    let expand = |s: &str| {
        let lower = s.to_ascii_lowercase();
        match lower.find("%userprofile%") {
            Some(i) => format!("{}{}{}", &s[..i], profile, &s[i + "%userprofile%".len()..]),
            None => s.to_string(),
        }
    };
    let (folder, onedrive) = (expand(folder).to_ascii_lowercase(), expand(onedrive).to_ascii_lowercase());
    let onedrive = onedrive.trim_end_matches('\\');
    !onedrive.is_empty() && (folder == onedrive || folder.starts_with(&format!("{onedrive}\\")))
}

/// The folder Microsoft says to empty to reset new Teams' cache, under a
/// profile folder.
pub const TEAMS_CACHE: &str = r"AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams";

#[cfg(windows)]
pub use imp::{clear_teams_cache, teams_cache_preview};

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::win::registry::{read_dword, read_string, read_string_unexpanded, HKLM};
    use crate::win::session::{person, running_in as running};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    pub fn gather(office_min: Option<(String, String)>) -> Result<Facts, String> {
        let who = person()?;
        let key = |k: &str| who.key(k);
        let local = who.profile.join(r"AppData\Local");
        let mut f = Facts { user: who.account.clone(), office_min, ..Facts::default() };

        // Outlook data files, and the limits a policy may set.
        let mut files = Vec::new();
        for dir in [local.join(r"Microsoft\Outlook"), who.profile.join(r"Documents\Outlook Files")] {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_ascii_lowercase();
                    if name.ends_with(".ost") || name.ends_with(".pst") {
                        if let Ok(meta) = e.metadata() {
                            files.push((e.path().display().to_string(), meta.len()));
                        }
                    }
                }
            }
        }
        files.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
        f.data_files = files;
        let limit = |name: &str| {
            read_dword(who.root, &key(r"Software\Policies\Microsoft\Office\16.0\Outlook\PST"), name)
                .or_else(|| read_dword(who.root, &key(r"Software\Microsoft\Office\16.0\Outlook\PST"), name))
        };
        let (max, warn) = (limit("MaxLargeFileSize"), limit("WarnLargeFileSize"));
        f.limits_from_policy = max.is_some() || warn.is_some();
        f.max_mb = max.map(u64::from).filter(|v| *v > 0).unwrap_or(office::DEFAULT_MAX_MB);
        f.warn_mb = warn.map(u64::from).filter(|v| *v > 0).unwrap_or(office::DEFAULT_WARN_MB).min(f.max_mb);

        // Click-to-Run.
        const C2R: &str = r"SOFTWARE\Microsoft\Office\ClickToRun\Configuration";
        f.office_version = read_string(HKLM, C2R, "VersionToReport");
        f.office_channel = read_string(HKLM, C2R, "UpdateChannel")
            .or_else(|| read_string(HKLM, C2R, "CDNBaseUrl"))
            .map(|url| office::channel(&url).map(str::to_string).unwrap_or(url));
        f.office_platform = read_string(HKLM, C2R, "Platform");

        // OneDrive and the known folders.
        f.onedrive_folder = read_string_unexpanded(who.root, &key(r"Software\Microsoft\OneDrive\Accounts\Business1"), "UserFolder");
        if let Some(od) = &f.onedrive_folder {
            let profile = who.profile.display().to_string();
            let shell = key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
            for (value, label) in [("Desktop", "Desktop"), ("Personal", "Documents"), ("My Pictures", "Pictures")] {
                if let Some(path) = read_string_unexpanded(who.root, &shell, value) {
                    f.known_folders.push((label, super::inside(&path, &profile, od)));
                }
            }
            f.onedrive_running = running("OneDrive.exe", who.session);
        }

        // Teams.
        let cache = who.profile.join(TEAMS_CACHE);
        let deadline = Instant::now() + Duration::from_secs(10);
        f.teams_cache = crate::triage::storage::measure(&cache, deadline, &|| false).map(|s| s.bytes);
        f.teams_running = running("ms-teams.exe", who.session);
        f.classic_teams_left = who.profile.join(r"AppData\Roaming\Microsoft\Teams").is_dir();

        // The sign-in broker and its log.
        f.broker_present = crate::win::dirs::windows().join(r"SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy").is_dir();
        f.workstation = read_string(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "InstallationType").is_some_and(|t| t.eq_ignore_ascii_case("Client"));
        const AAD: &str = "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
        if let Ok(rows) = crate::win::eventlog::query_xml("Microsoft-Windows-AAD/Operational", AAD, 100) {
            for xml in rows {
                let Some(system) = crate::parse::evtxml::parse_system(&xml) else { continue };
                let Some(at) = system.time_created.as_deref().and_then(crate::parse::time::iso8601_utc_to_epoch) else { continue };
                let data = crate::parse::evtxml::payload(&xml);
                let field = |n: &[&str]| crate::parse::blocks::field(&data, n).map(str::to_string);
                let what = match (field(&["Error"]), field(&["ErrorMessage"])) {
                    (Some(code), Some(msg)) => format!("{code} {}", msg.lines().next().unwrap_or_default().trim()),
                    (Some(code), None) => code,
                    (None, Some(msg)) => msg.lines().next().unwrap_or_default().trim().to_string(),
                    (None, None) => format!("event {}", system.event_id),
                };
                f.aad_errors.push((at, what.chars().take(160).collect()));
            }
        }
        Ok(f)
    }

    fn cache_dir() -> Result<(PathBuf, Option<u32>, String), String> {
        let who = person()?;
        Ok((who.profile.join(TEAMS_CACHE), who.session, who.account))
    }

    /// What clearing would remove, for the preview.
    pub fn teams_cache_preview() -> String {
        match cache_dir() {
            Err(e) => format!("couldn't find the cache: {e} Nothing was changed."),
            Ok((dir, session, who)) => {
                let size = crate::triage::storage::measure(&dir, Instant::now() + Duration::from_secs(10), &|| false).map(|s| s.bytes).unwrap_or(0);
                let blocked = if running("ms-teams.exe", session) { " It would refuse right now: Teams is running; quit it first." } else { "" };
                format!("would empty {} ({}) for {who}.{blocked} Nothing was changed.", dir.display(), human_bytes(size))
            }
        }
    }

    /// Empty the new Teams cache folder (not the folder itself), the way
    /// Microsoft's article says, refusing while Teams is running.
    pub fn clear_teams_cache() -> Result<String, String> {
        let (dir, session, who) = cache_dir()?;
        if running("ms-teams.exe", session) {
            return Err("Teams is running. Quit it (right-click its icon by the clock, Quit), then clear the cache.".into());
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(format!("{who} has no new Teams cache to clear.")),
            Err(e) => return Err(format!("Can't open {}: {e}", dir.display())),
        };
        let before = crate::triage::storage::measure(&dir, Instant::now() + Duration::from_secs(10), &|| false).map(|s| s.bytes).unwrap_or(0);
        let mut failed = 0usize;
        for e in entries.flatten() {
            let path = e.path();
            // A link is removed as a link; what it points at is left alone.
            let link = e.file_type().is_ok_and(|t| t.is_symlink());
            let gone = if path.is_dir() && !link { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path).or_else(|_| std::fs::remove_dir(&path)) };
            if gone.is_err() {
                failed += 1;
            }
        }
        let after = crate::triage::storage::measure(&dir, Instant::now() + Duration::from_secs(10), &|| false).map(|s| s.bytes).unwrap_or(0);
        let freed = human_bytes(before.saturating_sub(after));
        if failed > 0 {
            Err(format!("Cleared {freed} of {who}'s Teams cache, but {failed} item{} couldn't be removed (in use?). Restart the PC and try again.", plural(failed)))
        } else {
            Ok(format!("Cleared {freed} of {who}'s Teams cache. Teams rebuilds it the next time it starts, which takes a little longer than usual."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            user: "CORP\\jparker".into(),
            warn_mb: office::DEFAULT_WARN_MB,
            max_mb: office::DEFAULT_MAX_MB,
            broker_present: true,
            workstation: true,
            ..Facts::default()
        }
    }

    #[test]
    fn a_full_ost_and_an_old_office_are_flagged() {
        let gb = 1_073_741_824u64;
        let f = Facts {
            data_files: vec![(r"C:\Users\jparker\AppData\Local\Microsoft\Outlook\jparker@corp.example.org.ost".into(), 49 * gb)],
            office_version: Some("16.0.17928.20156".into()),
            office_channel: Some("Semi-Annual Enterprise Channel".into()),
            office_platform: Some("x64".into()),
            office_min: Some(("Microsoft 365 Apps".into(), "16.0.18129".into())),
            ..facts()
        };
        let rows = findings(&f, 1_794_600_000);
        let ost = rows.iter().find(|r| r.label == "Outlook data file: jparker@corp.example.org.ost").unwrap();
        assert_eq!(ost.severity, Severity::Warning);
        assert!(ost.detail.as_deref().unwrap().ends_with("(Outlook's defaults)"));
        let apps = rows.iter().find(|r| r.label == "Microsoft 365 Apps").unwrap();
        assert_eq!((apps.severity, apps.value.as_str()), (Severity::Warning, "16.0.17928.20156 · Semi-Annual Enterprise Channel · x64 · needs 16.0.18129 or later"));
    }

    #[test]
    fn known_folders_in_onedrive_without_onedrive_running_is_a_warning() {
        let f = Facts {
            onedrive_folder: Some(r"C:\Users\jparker\OneDrive - Contoso".into()),
            known_folders: vec![("Desktop", true), ("Documents", true), ("Pictures", false)],
            onedrive_running: false,
            ..facts()
        };
        let rows = findings(&f, 0);
        let od = rows.iter().find(|r| r.label == "OneDrive folder backup").unwrap();
        assert_eq!((od.severity, od.value.as_str()), (Severity::Warning, "Desktop, Documents are in OneDrive, but OneDrive isn't running"));
        let fine = findings(&Facts { onedrive_running: true, ..f.clone() }, 0);
        assert_eq!(fine.iter().find(|r| r.label == "OneDrive folder backup").unwrap().severity, Severity::Ok);
        assert_eq!(findings(&facts(), 0)[0].value, "OneDrive for work isn't set up for this user");
    }

    #[test]
    fn teams_cache_offers_its_fix_and_the_broker_and_aad_errors_are_graded() {
        let f = Facts { teams_cache: Some(734_003_200), teams_running: true, classic_teams_left: true, broker_present: false, aad_errors: vec![(100, "0xCAA2000C The request requires user interaction.".into()); 12], ..facts() };
        let rows = findings(&f, 160);
        let teams = rows.iter().find(|r| r.label == "Teams cache").unwrap();
        assert!(teams.value.ends_with("Teams is running") && teams.action.as_ref().unwrap().id == "clear-teams-cache");
        assert_eq!(rows.iter().find(|r| r.label == "Entra sign-in broker").unwrap().severity, Severity::Critical);
        let server = findings(&Facts { workstation: false, ..f.clone() }, 160);
        assert!(!server.iter().any(|r| r.label == "Entra sign-in broker"), "not expected on a server");
        let aad = rows.iter().find(|r| r.label == "Entra sign-in errors (24 h)").unwrap();
        assert_eq!((aad.severity, aad.value.as_str()), (Severity::Warning, "12 errors · last 1m ago"));
        assert!(aad.detail.as_deref().unwrap().starts_with("Most common: 0xCAA2000C"));
        assert_eq!(aad.kb.as_ref().unwrap().url, PRT_ARTICLE);
    }

    #[test]
    fn folders_are_matched_inside_onedrive_with_the_persons_own_profile() {
        let od = r"%USERPROFILE%\OneDrive - Contoso";
        assert!(inside(r"%USERPROFILE%\OneDrive - Contoso\Desktop", r"C:\Users\jparker", od));
        assert!(inside(r"C:\Users\jparker\OneDrive - Contoso\Documents", r"C:\Users\jparker", r"C:\Users\JParker\OneDrive - Contoso\"));
        assert!(!inside(r"%USERPROFILE%\Desktop", r"C:\Users\jparker", od));
        assert!(!inside(r"C:\Users\jparker\OneDrive - Contoso Old\Desktop", r"C:\Users\jparker", od), "a longer folder name isn't inside");
        assert!(!inside(r"C:\x", r"C:\Users\jparker", ""));
    }
}
