//! Watch mode: for "it froze around 2 yesterday". It runs unattended as the
//! signed-in user, keeps the last ten minutes of samples in memory, and when
//! something goes wrong saves them, with a few quick checks, as a report in
//! the run history, so the timeline and `--problem-at` line it up later.
//!
//! It's off unless the site profile turns it on (`[advanced] watch = true`),
//! and `--install-watch` (administrator, audited) is what makes it start at
//! sign-in: a scheduled task for the Users group on Windows, a systemd user
//! unit for everyone on Linux. Each capture says what it is and what it
//! holds. Captures are debounced to one per 15 minutes and kept within
//! `watch_max_mb` and `watch_keep_days`.
//!
//! Triggers (`watch_triggers`):
//! - `cpu`: the processor above the profile's CPU warning band for a minute;
//! - `gateway_loss`: the default gateway not answering three pings in a row
//!   (ten seconds apart), once it has answered at all;
//! - `app_paths`: a `[[require.application]]` server refusing TCP twice in a
//!   row (checked every minute);
//! - `app_hang`: Windows logging Application Hang (1002) or Application
//!   Error (1000).

use crate::investigate::recording::{Marker, Sample};
use std::collections::{HashMap, VecDeque};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trigger {
    Cpu,
    GatewayLoss,
    AppPaths,
    AppHang,
}

impl Trigger {
    pub fn parse(name: &str) -> Option<Trigger> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "cpu" => Trigger::Cpu,
            "gateway_loss" => Trigger::GatewayLoss,
            "app_paths" => Trigger::AppPaths,
            "app_hang" => Trigger::AppHang,
            _ => return None,
        })
    }
}

/// How long the CPU band has to stay crossed.
pub const CPU_SUSTAIN_SECS: u64 = 60;
/// Missed gateway pings in a row.
pub const GATEWAY_MISSES: u32 = 3;
/// Failed checks in a row for one application server.
pub const APP_FAILURES: u32 = 2;
/// At most one capture per this many seconds.
pub const DEBOUNCE_SECS: u64 = 15 * 60;
/// Seconds of samples kept in memory, and the gap between them.
pub const WINDOW_SECS: u64 = 600;
pub const INTERVAL_SECS: u64 = 5;

/// One thing seen while watching. Times are Unix seconds.
#[derive(Debug, Clone, PartialEq)]
pub enum Seen {
    Cpu { at: u64, pct: f32 },
    Gateway { at: u64, answered: bool },
    App { at: u64, label: String, ok: bool },
    Hang { at: u64, what: String },
}

/// Decides when to save a capture.
pub struct Watcher {
    triggers: Vec<Trigger>,
    cpu_band: f64,
    cpu_since: Option<u64>,
    gateway_misses: u32,
    /// A gateway that never answers ping (ICMP blocked) proves nothing by
    /// staying quiet: misses count only once it has answered.
    gateway_answers: bool,
    app_failures: HashMap<String, u32>,
    last_capture: Option<u64>,
    /// Problems seen while a capture was being held back.
    pub suppressed: usize,
}

impl Watcher {
    pub fn new(triggers: &[Trigger], cpu_band: f64) -> Self {
        Watcher { triggers: triggers.to_vec(), cpu_band, cpu_since: None, gateway_misses: 0, gateway_answers: false, app_failures: HashMap::new(), last_capture: None, suppressed: 0 }
    }

    fn on(&self, t: Trigger) -> bool {
        self.triggers.contains(&t)
    }

    /// Feed one observation; `Some(reason)` means save a capture now.
    pub fn see(&mut self, seen: &Seen) -> Option<String> {
        let (at, reason) = match seen {
            Seen::Cpu { at, pct } => {
                if f64::from(*pct) < self.cpu_band {
                    self.cpu_since = None;
                    return None;
                }
                let since = *self.cpu_since.get_or_insert(*at);
                if !self.on(Trigger::Cpu) || at.saturating_sub(since) < CPU_SUSTAIN_SECS {
                    return None;
                }
                self.cpu_since = None;
                (*at, format!("processor above {:.0}% for {} s", self.cpu_band, CPU_SUSTAIN_SECS))
            }
            Seen::Gateway { at, answered } => {
                if *answered {
                    self.gateway_misses = 0;
                    self.gateway_answers = true;
                    return None;
                }
                if !self.gateway_answers {
                    return None;
                }
                self.gateway_misses += 1;
                if !self.on(Trigger::GatewayLoss) || self.gateway_misses < GATEWAY_MISSES {
                    return None;
                }
                self.gateway_misses = 0;
                (*at, format!("the default gateway missed {GATEWAY_MISSES} pings in a row"))
            }
            Seen::App { at, label, ok } => {
                if *ok {
                    self.app_failures.remove(label);
                    return None;
                }
                let n = {
                    let n = self.app_failures.entry(label.clone()).or_insert(0);
                    *n += 1;
                    *n
                };
                if !self.on(Trigger::AppPaths) || n < APP_FAILURES {
                    return None;
                }
                self.app_failures.remove(label);
                (*at, format!("{label} didn't answer {APP_FAILURES} checks in a row"))
            }
            Seen::Hang { at, what } => {
                if !self.on(Trigger::AppHang) {
                    return None;
                }
                (*at, what.clone())
            }
        };
        if self.last_capture.is_some_and(|last| at.saturating_sub(last) < DEBOUNCE_SECS) {
            self.suppressed += 1;
            return None;
        }
        self.last_capture = Some(at);
        Some(reason)
    }
}

/// The samples kept in memory: the last [`WINDOW_SECS`].
pub struct Ring(VecDeque<Sample>);

impl Ring {
    pub fn new() -> Self {
        Ring(VecDeque::new())
    }
    pub fn push(&mut self, s: Sample) {
        let cutoff = s.at_ms.saturating_sub(WINDOW_SECS * 1000);
        self.0.push_back(s);
        while self.0.front().is_some_and(|f| f.at_ms < cutoff) {
            self.0.pop_front();
        }
    }
    pub fn samples(&self) -> Vec<Sample> {
        self.0.iter().cloned().collect()
    }
}

impl Default for Ring {
    fn default() -> Self {
        Self::new()
    }
}

/// What a capture tells whoever opens it, and the person whose PC it is.
pub fn privacy_notice(keep_days: u64, max_mb: u64) -> String {
    format!(
        "Watch mode is on because this PC's site profile turns it on. It keeps the last {} minutes of processor, memory, disk and network figures in memory, and saves them with a few quick checks when something above goes wrong. It doesn't record the screen, keystrokes, files or browsing. Captures stay in this account's run history for {keep_days} days, {max_mb} MB at most.",
        WINDOW_SECS / 60
    )
}

/// Is this a watch capture's file? (`…_watch.json`, `…_watch~2.txt`.)
pub fn is_capture_file(name: &str) -> bool {
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    let stem = stem.split_once('~').map(|(s, _)| s).unwrap_or(stem);
    stem.ends_with("_watch") && (name.ends_with(".json") || name.ends_with(".txt"))
}

/// Remove captures past the age limit, then the oldest until they fit the
/// size limit. Only capture files are touched. Returns how many went.
pub fn prune(dir: &Path, max_bytes: u64, keep_days: u64, now: u64) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let mut files: Vec<(std::path::PathBuf, u64, u64)> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| is_capture_file(&e.file_name().to_string_lossy()))
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            let modified = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            Some((e.path(), meta.len(), modified))
        })
        .collect();
    files.sort_by_key(|(path, _, modified)| (*modified, path.clone()));
    let mut removed = 0;
    let max_age = keep_days.saturating_mul(86_400);
    let mut total: u64 = files.iter().map(|(_, size, _)| size).sum();
    for (path, size, modified) in &files {
        let old = keep_days > 0 && now.saturating_sub(*modified) > max_age;
        if (old || total > max_bytes) && std::fs::remove_file(path).is_ok() {
            total = total.saturating_sub(*size);
            removed += 1;
        }
    }
    removed
}

/// `host:port` of an application URL, for a TCP check.
pub fn host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let default = match scheme.to_ascii_lowercase().as_str() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = after.strip_prefix(':').map(|p| p.parse().ok()).unwrap_or(Some(default))?;
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((authority.to_string(), default)),
    }
    .filter(|(h, _)| !h.is_empty())
}

/// "Application Hang: OUTLOOK.EXE stopped responding" from an Application
/// log event, or `None` for anything else.
pub fn hang_from_event(xml: &str) -> Option<(u64, String)> {
    let system = crate::parse::evtxml::parse_system(xml)?;
    let at = system.time_created.as_deref().and_then(crate::parse::time::iso8601_utc_to_epoch)?;
    // Application Error names it `AppName`; Application Hang's values have
    // no names, and the program is the first.
    let named = crate::parse::evtxml::event_data(xml).into_iter().find(|(k, _)| k.eq_ignore_ascii_case("AppName")).map(|(_, v)| v);
    let first = || {
        let body = &xml[xml.find("<EventData")?..];
        let data = &body[body.find("<Data")?..];
        let open = data.find('>')?;
        if data[..open].ends_with('/') {
            return None;
        }
        let close = data.find("</Data>")?;
        Some(data[open + 1..close].trim().replace("&amp;", "&"))
    };
    let app = named.or_else(first).filter(|v| !v.is_empty()).unwrap_or_else(|| "an app".into());
    let what = match (system.provider.as_str(), system.event_id) {
        ("Application Hang", 1002) => format!("{app} stopped responding (Application Hang 1002)"),
        ("Application Error", 1000) => format!("{app} crashed (Application Error 1000)"),
        _ => return None,
    };
    Some((at, what))
}

/// The capture's marker: when and why.
pub fn marker(at_secs: u64, reason: &str) -> Marker {
    Marker { at_ms: at_secs * 1000, label: format!("Watch: {reason}"), device: None }
}

/// Run until the session ends. Returns the exit code.
pub fn run(profile: &crate::profile::Profile, profile_source: &'static str, profile_name: Option<String>) -> i32 {
    let a = &profile.advanced;
    if !a.watch {
        eprintln!("itriage: watch mode is off. The site profile turns it on with [advanced] watch = true.");
        return 0;
    }
    let mut triggers = Vec::new();
    for name in &a.watch_triggers {
        match Trigger::parse(name) {
            Some(t) => triggers.push(t),
            None => eprintln!("itriage: ignoring unknown watch trigger `{name}`"),
        }
    }
    let Some(_lock) = lock::take() else {
        eprintln!("itriage: watch mode is already running for this account.");
        return 0;
    };
    let Some(history) = crate::report::history_dir() else {
        eprintln!("itriage: no folder for run history on this system.");
        return 1;
    };
    live::watch(profile, profile_source, profile_name, &triggers, &history);
    0
}

mod lock {
    /// One watcher per account: a lock file holding the process id, taken
    /// over when that process is gone.
    pub struct Lock(std::path::PathBuf);

    impl Drop for Lock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    pub fn take() -> Option<Lock> {
        let path = crate::paths::state_dir()?.join("watch.lock");
        let _ = std::fs::create_dir_all(path.parent()?);
        for _ in 0..2 {
            match std::fs::File::create_new(&path) {
                Ok(mut f) => {
                    use std::io::Write;
                    let _ = write!(f, "{}", std::process::id());
                    return Some(Lock(path));
                }
                Err(_) => {
                    let pid: Option<u32> = std::fs::read_to_string(&path).ok().and_then(|t| t.trim().parse().ok());
                    let mut sys = sysinfo::System::new();
                    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
                    let alive = pid.is_some_and(|p| sys.process(sysinfo::Pid::from_u32(p)).is_some_and(|proc| proc.name().to_string_lossy().to_ascii_lowercase().contains("itriage")));
                    if alive {
                        return None;
                    }
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        None
    }
}

mod live {
    use super::*;
    use std::time::{Duration, Instant};

    struct Next {
        gateway: Instant,
        apps: Instant,
        hangs: Instant,
    }

    pub fn watch(profile: &crate::profile::Profile, source: &'static str, name: Option<String>, triggers: &[Trigger], history: &Path) {
        let a = &profile.advanced;
        let mut watcher = Watcher::new(triggers, profile.thresholds.cpu_pct.warn);
        let mut ring = Ring::new();
        let mut sampler = crate::telemetry::Sampler::new();
        let now = Instant::now();
        let mut next = Next { gateway: now, apps: now + Duration::from_secs(30), hangs: now };
        let mut seen_hangs: Vec<String> = Vec::new();
        // An app that crashed before watching began isn't this session's.
        let began = crate::util::now_epoch();
        let apps: Vec<(String, String, u16)> = profile
            .require
            .application
            .iter()
            .filter_map(|p| host_port(&p.url).map(|(h, port)| (p.label.clone(), h, port)))
            .take(5)
            .collect();
        eprintln!("itriage: watching ({} trigger{})", triggers.len(), if triggers.len() == 1 { "" } else { "s" });
        loop {
            std::thread::sleep(Duration::from_secs(INTERVAL_SECS));
            let t = sampler.sample();
            let at = crate::util::now_epoch();
            ring.push(Sample {
                at_ms: crate::investigate::recording::now_ms(),
                cpu_pct: t.cpu,
                memory_pct: t.mem_pct,
                disk_read: t.disk_read,
                disk_write: t.disk_write,
                net_rx: t.net_rx,
                net_tx: t.net_tx,
                tcp_ms: None,
                tcp_error: None,
                dns_ms: None,
                dns_error: None,
                wifi: None,
                wifi_signal: None,
                wifi_bssid: None,
                clock_pct: t.clock_pct,
            });
            let mut seen = vec![Seen::Cpu { at, pct: t.cpu }];
            let now = Instant::now();
            if triggers.contains(&Trigger::GatewayLoss) && now >= next.gateway {
                next.gateway = now + Duration::from_secs(10);
                if let Some(gw) = crate::net::default_route().ok().and_then(|r| r.next_hop) {
                    let answered = crate::net::ping(gw, None, 1, Duration::from_secs(1)).is_ok_and(|p| p.received > 0);
                    seen.push(Seen::Gateway { at, answered });
                }
            }
            if triggers.contains(&Trigger::AppPaths) && now >= next.apps {
                next.apps = now + Duration::from_secs(60);
                for (label, host, port) in &apps {
                    let ok = crate::net::resolve(host).is_ok_and(|r| crate::net::tcp_check(&r.addresses, *port, Duration::from_secs(3)).connected().is_some());
                    seen.push(Seen::App { at, label: label.clone(), ok });
                }
            }
            if triggers.contains(&Trigger::AppHang) && now >= next.hangs {
                next.hangs = now + Duration::from_secs(15);
                for (when, what) in hangs().into_iter().filter(|(when, _)| *when >= began) {
                    let key = format!("{when}|{what}");
                    if !seen_hangs.contains(&key) {
                        seen_hangs.push(key);
                        seen.push(Seen::Hang { at: when, what });
                    }
                }
                if seen_hangs.len() > 200 {
                    seen_hangs.drain(..100);
                }
            }
            for s in &seen {
                if let Some(reason) = watcher.see(s) {
                    capture(profile, source, name.clone(), &ring, at, &reason);
                    prune(history, a.watch_max_mb.saturating_mul(1024 * 1024), a.watch_keep_days, crate::util::now_epoch());
                }
            }
        }
    }

    #[cfg(windows)]
    fn hangs() -> Vec<(u64, String)> {
        const RECENT: &str = "*[System[Provider[@Name='Application Hang' or @Name='Application Error'] and (EventID=1000 or EventID=1002) and TimeCreated[timediff(@SystemTime) <= 60000]]]";
        crate::win::eventlog::query_xml("Application", RECENT, 20).unwrap_or_default().iter().filter_map(|x| hang_from_event(x)).collect()
    }

    #[cfg(not(windows))]
    fn hangs() -> Vec<(u64, String)> {
        Vec::new()
    }

    fn capture(profile: &crate::profile::Profile, source: &'static str, name: Option<String>, ring: &Ring, at: u64, reason: &str) {
        let a = &profile.advanced;
        let samples = ring.samples();
        let started = samples.first().map(|s| crate::parse::time::epoch_to_rfc3339(s.at_ms / 1000)).unwrap_or_else(|| crate::parse::time::epoch_to_rfc3339(at));
        let recording = crate::investigate::recording::Recording {
            started,
            config: crate::investigate::recording::Config { seconds: WINDOW_SECS, interval_ms: INTERVAL_SECS * 1000 },
            target: None,
            samples,
            markers: vec![marker(at, reason)],
            stopped_early: false,
            gaps: Vec::new(),
        };
        let mut first = crate::investigate::recording::result(&recording);
        first.findings.insert(0, crate::model::Finding::info("Watch mode", format!("saved automatically: {reason}")).with_detail(privacy_notice(a.watch_keep_days, a.watch_max_mb)));
        let ctx = crate::module::RunContext::silent();
        let mut results = vec![first];
        results.extend(crate::module::run_selected(&["proc.top".into(), "system.memory".into(), "net.connectivity".into()], &ctx));
        let mut report = crate::report::Report::new(crate::host::host_context(), name, results, false).with_role(&profile.role);
        report.recording = Some(recording);
        report.watch = Some(reason.to_string());
        report.check_incidents(profile, source);
        match crate::report::save(&report, profile.history.keep) {
            Ok(p) => eprintln!("itriage: watch capture saved: {}", p.display()),
            Err(e) => eprintln!("itriage: couldn't save a watch capture: {e}"),
        }
    }
}

/// The program path the task or unit runs, when it's safe to put in one.
fn program() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Can't tell where ITriage is installed: {e}"))?;
    let text = exe.to_str().ok_or("ITriage's path isn't valid text.")?.to_string();
    if !exe.is_absolute() || text.chars().any(|c| c.is_control() || matches!(c, '"' | '<' | '>' | '&' | '%' | '\'')) {
        return Err(format!("ITriage's path ({text}) has characters a scheduled task can't carry safely."));
    }
    if cfg!(not(windows)) && text.chars().any(char::is_whitespace) {
        return Err(format!("ITriage's path ({text}) has spaces, which a systemd unit can't carry safely."));
    }
    Ok(text)
}

/// The Task Scheduler definition: at any sign-in, as that user (the Users
/// group), below normal priority, no time limit.
pub fn task_xml(program: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>ITriage watch mode: saves a capture to the signed-in user's run history when the PC misbehaves. Turned on by the site profile.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT1M</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Users">
      <GroupId>S-1-5-32-545</GroupId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Users">
    <Exec>
      <Command>{program}</Command>
      <Arguments>--watch</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// The systemd user unit, enabled for every user.
pub fn unit_text(program: &str) -> String {
    format!(
        "[Unit]\nDescription=ITriage watch mode (saves a capture to your run history when the PC misbehaves)\nAfter=graphical-session.target\n\n[Service]\nExecStart={program} --watch\nNice=10\nRestart=on-failure\nRestartSec=60\n\n[Install]\nWantedBy=default.target\n"
    )
}

pub const TASK_NAME: &str = "ITriage Watch";
pub const UNIT_PATH: &str = "/etc/systemd/user/itriage-watch.service";

fn require_admin() -> Result<(), String> {
    if crate::host::is_elevated() {
        Ok(())
    } else if cfg!(windows) {
        Err(crate::util::ADMIN_REQUIRED.to_string())
    } else {
        Err("Setting up watch mode for every user needs root (sudo itriage --install-watch).".into())
    }
}

/// Set watch mode to start at sign-in. Administrator/root.
pub fn install() -> Result<String, String> {
    require_admin()?;
    let program = program()?;
    imp::install(&program)
}

pub fn uninstall() -> Result<String, String> {
    require_admin()?;
    imp::uninstall()
}

#[cfg(windows)]
mod imp {
    use super::*;

    fn schtasks(args: &[&str]) -> Result<crate::util::CmdOutput, String> {
        let mut c = crate::util::cmd("schtasks");
        c.args(args);
        crate::util::capture_for(c, std::time::Duration::from_secs(60))
    }

    pub fn install(program: &str) -> Result<String, String> {
        let dir = crate::paths::state_dir().ok_or("No folder to write the task definition to.")?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let file = dir.join("watch-task.xml");
        // Task Scheduler reads its XML as UTF-16 with a byte-order mark.
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(task_xml(program).encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(&file, bytes).map_err(|e| format!("Can't write {}: {e}", file.display()))?;
        let path = file.to_str().ok_or("The task file's path isn't valid text.")?;
        let out = schtasks(&["/Create", "/TN", TASK_NAME, "/XML", path, "/F"]);
        let _ = std::fs::remove_file(&file);
        let out = out?;
        if out.success() {
            Ok(format!("Watch mode will start at each sign-in (scheduled task \"{TASK_NAME}\", as the signed-in user). It only watches while the site profile has [advanced] watch = true."))
        } else {
            Err(format!("schtasks couldn't create the task: {}", out.combined()))
        }
    }

    pub fn uninstall() -> Result<String, String> {
        // By exit code, not by schtasks' (translated) error text.
        if !schtasks(&["/Query", "/TN", TASK_NAME])?.success() {
            return Ok("Watch mode wasn't installed.".into());
        }
        let out = schtasks(&["/Delete", "/TN", TASK_NAME, "/F"])?;
        if out.success() {
            Ok(format!("Removed the scheduled task \"{TASK_NAME}\". Watchers already running stop at the next sign-out."))
        } else {
            Err(format!("schtasks couldn't remove the task: {}", out.combined()))
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    fn systemctl(args: &[&str]) -> Result<crate::util::CmdOutput, String> {
        let mut c = crate::util::cmd("systemctl");
        c.args(args);
        crate::util::capture_for(c, std::time::Duration::from_secs(30))
    }

    pub fn install(program: &str) -> Result<String, String> {
        std::fs::create_dir_all("/etc/systemd/user").map_err(|e| e.to_string())?;
        std::fs::write(UNIT_PATH, unit_text(program)).map_err(|e| format!("Can't write {UNIT_PATH}: {e}"))?;
        let out = systemctl(&["--global", "enable", "itriage-watch.service"])?;
        if out.success() {
            Ok(format!("Watch mode will start at each sign-in ({UNIT_PATH}, a systemd user unit enabled for every user). It only watches while the site profile has [advanced] watch = true."))
        } else {
            Err(format!("systemctl couldn't enable the unit: {}", out.combined()))
        }
    }

    pub fn uninstall() -> Result<String, String> {
        if !Path::new(UNIT_PATH).exists() {
            return Ok("Watch mode wasn't installed.".into());
        }
        let out = systemctl(&["--global", "disable", "itriage-watch.service"])?;
        std::fs::remove_file(UNIT_PATH).map_err(|e| format!("Can't remove {UNIT_PATH}: {e}"))?;
        if out.success() {
            Ok(format!("Removed {UNIT_PATH}. Watchers already running stop at the next sign-out."))
        } else {
            Ok(format!("Removed {UNIT_PATH} ({}).", out.combined()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_follow_each_trigger_and_the_debounce() {
        let all = [Trigger::Cpu, Trigger::GatewayLoss, Trigger::AppPaths, Trigger::AppHang];
        let mut w = Watcher::new(&all, 75.0);
        // CPU has to stay high for a minute.
        assert_eq!(w.see(&Seen::Cpu { at: 0, pct: 90.0 }), None);
        assert_eq!(w.see(&Seen::Cpu { at: 30, pct: 92.0 }), None);
        assert_eq!(w.see(&Seen::Cpu { at: 45, pct: 50.0 }), None, "a dip starts it over");
        assert_eq!(w.see(&Seen::Cpu { at: 50, pct: 90.0 }), None);
        assert_eq!(w.see(&Seen::Cpu { at: 110, pct: 90.0 }).as_deref(), Some("processor above 75% for 60 s"));
        // Within 15 minutes, nothing else is saved.
        w.see(&Seen::Gateway { at: 115, answered: true });
        for at in [120, 130, 140] {
            assert_eq!(w.see(&Seen::Gateway { at, answered: false }), None);
        }
        assert_eq!(w.suppressed, 1);
        // After that, three misses in a row (an answer resets the count).
        let later = 110 + DEBOUNCE_SECS;
        w.see(&Seen::Gateway { at: later, answered: true });
        w.see(&Seen::Gateway { at: later + 5, answered: false });
        w.see(&Seen::Gateway { at: later + 10, answered: true });
        w.see(&Seen::Gateway { at: later + 20, answered: false });
        w.see(&Seen::Gateway { at: later + 30, answered: false });
        assert!(w.see(&Seen::Gateway { at: later + 40, answered: false }).unwrap().starts_with("the default gateway missed 3"));

        let mut silent = Watcher::new(&all, 75.0);
        for at in (0..600).step_by(10) {
            assert_eq!(silent.see(&Seen::Gateway { at, answered: false }), None, "a gateway that never answers ping isn't lost");
        }

        let mut apps = Watcher::new(&all, 75.0);
        assert_eq!(apps.see(&Seen::App { at: 0, label: "EHR".into(), ok: false }), None);
        assert_eq!(apps.see(&Seen::App { at: 60, label: "Lab".into(), ok: false }), None, "counted per server");
        assert_eq!(apps.see(&Seen::App { at: 120, label: "EHR".into(), ok: false }).as_deref(), Some("EHR didn't answer 2 checks in a row"));
        let mut hang = Watcher::new(&[Trigger::AppHang], 75.0);
        assert_eq!(hang.see(&Seen::Hang { at: 5, what: "OUTLOOK.EXE stopped responding (Application Hang 1002)".into() }).as_deref(), Some("OUTLOOK.EXE stopped responding (Application Hang 1002)"));
        let mut off = Watcher::new(&[Trigger::AppHang], 75.0);
        for at in (0..300).step_by(10) {
            assert_eq!(off.see(&Seen::Cpu { at, pct: 99.0 }), None, "a trigger that's off never captures");
        }
        assert_eq!(Trigger::parse(" GATEWAY_LOSS "), Some(Trigger::GatewayLoss));
        assert_eq!(Trigger::parse("disk"), None);
    }

    #[test]
    fn the_ring_keeps_ten_minutes() {
        let mut ring = Ring::new();
        let sample = |at_ms: u64| Sample { at_ms, cpu_pct: 1.0, memory_pct: 1.0, disk_read: 0, disk_write: 0, net_rx: 0, net_tx: 0, tcp_ms: None, tcp_error: None, dns_ms: None, dns_error: None, wifi: None, wifi_signal: None, wifi_bssid: None, clock_pct: None };
        for i in 0..200u64 {
            ring.push(sample(1_000_000 + i * 5_000));
        }
        let kept = ring.samples();
        assert_eq!(kept.len(), 121);
        assert_eq!(kept.last().unwrap().at_ms - kept[0].at_ms, WINDOW_SECS * 1000);
    }

    #[test]
    fn pruning_touches_only_captures() {
        let dir = std::env::temp_dir().join(format!("itriage-watch-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["20261101T010000Z_WS-07_watch.json", "20261101T010000Z_WS-07_watch.txt", "20261102T010000Z_WS-07_watch~2.json", "20261103T010000Z_WS-07.json", "20261103T010000Z_WS-07_INC1.json"] {
            std::fs::write(dir.join(name), vec![b'x'; 1000]).unwrap();
        }
        assert!(is_capture_file("20261102T010000Z_WS-07_watch~2.json") && !is_capture_file("20261103T010000Z_WS-07_watchful.json"));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(prune(&dir, 10_000, 7, now), 0, "under both limits");
        assert_eq!(prune(&dir, 1_500, 7, now), 2, "the oldest go until they fit");
        assert_eq!(prune(&dir, 10_000, 7, now + 8 * 86_400), 1, "and anything past the age limit");
        let left: Vec<String> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left.len(), 2, "ordinary runs are never touched: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn urls_events_and_the_installers_text() {
        assert_eq!(host_port("https://ehr.example.org/app"), Some(("ehr.example.org".into(), 443)));
        assert_eq!(host_port("http://lab.example.org:8080/x?y"), Some(("lab.example.org".into(), 8080)));
        assert_eq!(host_port("https://[2001:db8::5]:8443/"), Some(("2001:db8::5".into(), 8443)));
        assert_eq!(host_port("ftp://x"), None);
        let xml = "<Event><System><Provider Name='Application Hang'/><EventID>1002</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-12T14:02:11.000Z'/></System><EventData><Data>OUTLOOK.EXE</Data><Data>16.0.17928.20156</Data></EventData></Event>";
        assert_eq!(hang_from_event(xml).unwrap().1, "OUTLOOK.EXE stopped responding (Application Hang 1002)");
        let error = "<Event><System><Provider Name='Application Error'/><EventID>1000</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-12T14:02:11.000Z'/></System><EventData><Data Name='AppName'>EpicClient.exe</Data><Data Name='AppVersion'>10.3</Data></EventData></Event>";
        assert_eq!(hang_from_event(error).unwrap().1, "EpicClient.exe crashed (Application Error 1000)");
        assert!(hang_from_event(&error.replace("1000", "1001")).is_none());
        let task = task_xml(r"C:\Program Files\ITriage\itriage.exe");
        assert!(task.contains("<GroupId>S-1-5-32-545</GroupId>") && task.contains("<Priority>7</Priority>") && task.contains("<Arguments>--watch</Arguments>"));
        assert!(unit_text("/usr/bin/itriage").contains("ExecStart=/usr/bin/itriage --watch\nNice=10"));
        assert!(privacy_notice(7, 200).contains("doesn't record the screen"));
        assert_eq!(marker(1_794_600_000, "x").label, "Watch: x");
    }
}
