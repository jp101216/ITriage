//! The command line: the same engine without the window, for remote shells,
//! scheduled tasks and RMM tools. `itriage.exe` (or `itriage` on Linux)
//! switches to it whenever it's given arguments.
//!
//! Exit codes follow the PowerShell toolkit: 0 finished (problems found still
//! count as finished), 1 nothing could run or bad arguments, 2 incomplete (a
//! module couldn't run, a change partly failed, or the run was cancelled),
//! and 3010 when changes need a restart (3 on Linux).

use crate::model::Target;
use crate::model::ModuleInfo;
use crate::module::{preset, registry, RunContext, PRESETS};
use crate::profile::{self, Profile};
use crate::report::{self, Report};
use crate::investigate::{baseline, bundle, guided, recording, timeline};
use std::path::PathBuf;

pub const USAGE: &str = "\
ITriage: IT triage and updates

USAGE
  itriage [OPTIONS] [MODULE...]

  With no modules, every read-only check runs. Modules that change the
  machine run only when named (or picked by a preset), and the site
  profile's policy still applies to them.

SELECTING
  --list                 List modules and presets, then exit
  --preset NAME          triage (Invoke-NetTriage), tuneup (Invoke-EndpointTuneUp),
                         updates (Invoke-UpdateSystem), lockout (why an account
                         keeps locking) or health (drives, crashes, security)
  --target HOST[:PORTS]  Test one destination (adds the Destination test);
                         e.g. --target fileserver01:445,3389
  --ports LIST           Ports for --target (default 443,80,445,3389)
  --runbook ID           Guided diagnostics: printing, vpn, sign-in, slow-app
  --record SECONDS       Record an intermittent issue (5–1800 seconds)
  --interval-ms MS       Recording interval (1000–10000; default 1000)

SAFETY
  --what-if              Preview: modules that change the machine say what
                         they would do and change nothing
  --remote-safe          Refuse anything that could drop a remote session or
                         restart the PC (--no-remote-safe overrides the profile)
  --redact-serial        Show REDACTED instead of the serial number

OUTPUT
  --ticket REF           The ticket this run is for: shown on the report,
                         added to its file name and written to the audit log
  --json                 Print the full JSON report instead of text
  --log                  Include each module's transcript in the text
  --out PATH             Also write the JSON report (or comparison) to PATH,
                         with the text beside it as PATH.txt
  --no-history           Don't save this run in the history folder
  --quiet                No progress lines on stderr

OTHER COMMANDS
  --fix ID [TARGET]      Run one one-click fix (restart-spooler, flush-dns,
                         restart-computer, cancel-restart, start-service NAME,
                         clear-saved-credentials, unlock-account NAME,
                         revert-tuneup…)
  --compare OLD NEW      Compare two saved reports from the same computer
  --baseline GOOD NOW    Compare configuration with a working PC's report
  --timeline REPORT      Show saved change / authentication events
  --problem-at UTC       Limit --timeline to +/- 1 hour of an ISO UTC time
  --bundle-preview FILE  Preview every file in a case made from a JSON report
  --bundle FILE --out ZIP  Export that case (refuses to overwrite)
  --include-logs         Include existing report logs in a case
  --no-redact            Explicitly keep identifiers in a case
  --trends               How each measurement has moved over this computer's
                         saved runs (with --json, every point)
  -h, --help             Show this help

EXIT CODES
  0     finished (including diagnostics that found problems)
  1     nothing could run, bad arguments, or --out couldn't be written
  2     incomplete: a module couldn't run, a change failed, or cancelled
  3010  changes finished and need a restart (3 on Linux)
";

#[derive(Debug, Default)]
struct Args {
    list: bool,
    help: bool,
    json: bool,
    logs: bool,
    quiet: bool,
    no_history: bool,
    what_if: bool,
    remote_safe: Option<bool>,
    redact_serial: bool,
    presets: Vec<String>,
    target: Option<String>,
    ports: Option<String>,
    out: Option<PathBuf>,
    ticket: Option<String>,
    trends: bool,
    fix: Option<(String, Option<String>)>,
    compare: Option<(PathBuf, PathBuf)>,
    baseline: Option<(PathBuf, PathBuf)>,
    timeline: Option<PathBuf>,
    problem_at: Option<String>,
    bundle: Option<PathBuf>,
    bundle_preview: Option<PathBuf>,
    include_logs: bool,
    no_redact: bool,
    runbook: Option<String>,
    record: Option<u64>,
    interval_ms: Option<u64>,
    modules: Vec<String>,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = argv.iter().peekable();
    let value = |it: &mut std::iter::Peekable<std::slice::Iter<String>>, flag: &str| -> Result<String, String> {
        it.next().cloned().ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(arg) = it.next() {
        // --flag=value works too.
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut take = |name: &str| -> Result<String, String> {
            match &inline {
                Some(v) => Ok(v.clone()),
                None => value(&mut it, name),
            }
        };
        match flag.as_str() {
            "-h" | "--help" | "/?" => a.help = true,
            "--list" => a.list = true,
            "--json" => a.json = true,
            "--text" => a.json = false,
            "--log" | "--logs" => a.logs = true,
            "--quiet" | "-q" => a.quiet = true,
            "--no-history" => a.no_history = true,
            "--what-if" | "--whatif" | "--dry-run" => a.what_if = true,
            "--remote-safe" => a.remote_safe = Some(true),
            "--no-remote-safe" => a.remote_safe = Some(false),
            "--redact-serial" => a.redact_serial = true,
            "--preset" => a.presets.push(take("--preset")?),
            "--target" => a.target = Some(take("--target")?),
            "--ports" => a.ports = Some(take("--ports")?),
            "--out" => a.out = Some(PathBuf::from(take("--out")?)),
            "--ticket" => a.ticket = Some(take("--ticket")?),
            "--trends" => a.trends = true,
            "--include-logs" => a.include_logs = true,
            "--no-redact" => a.no_redact = true,
            "--runbook" => a.runbook = Some(take("--runbook")?),
            "--record" => a.record = Some(take("--record")?.parse().map_err(|_|"--record needs a duration in seconds")?),
            "--interval-ms" => a.interval_ms = Some(take("--interval-ms")?.parse().map_err(|_|"--interval-ms needs milliseconds")?),
            "--bundle" => a.bundle = Some(PathBuf::from(take("--bundle")?)),
            "--bundle-preview" => a.bundle_preview = Some(PathBuf::from(take("--bundle-preview")?)),
            "--timeline" => a.timeline = Some(PathBuf::from(take("--timeline")?)),
            "--problem-at" => a.problem_at = Some(take("--problem-at")?),
            "--baseline" => {
                let good = take("--baseline")?; let now = value(&mut it,"--baseline")?;
                a.baseline = Some((PathBuf::from(good),PathBuf::from(now)));
            }
            "--fix" => {
                let id = take("--fix")?;
                let target = it.next_if(|n| !n.starts_with("--")).cloned();
                a.fix = Some((id, target));
            }
            "--compare" => {
                let old = take("--compare")?;
                let new = value(&mut it, "--compare")?;
                a.compare = Some((PathBuf::from(old), PathBuf::from(new)));
            }
            f if f.starts_with('-') => return Err(format!("unknown option {f} (try --help)")),
            _ => a.modules.push(arg.clone()),
        }
    }
    let modes = [a.fix.is_some(),a.compare.is_some(),a.baseline.is_some(),a.timeline.is_some(),a.bundle.is_some(),a.bundle_preview.is_some(),a.runbook.is_some(),a.record.is_some(),a.trends];
    if modes.iter().filter(|v|**v).count() > 1 { return Err("Choose one command mode at a time.".into()); }
    if modes.iter().any(|v|*v) && (!a.modules.is_empty() || !a.presets.is_empty()) { return Err("A command mode cannot be combined with module or preset selections.".into()); }
    if a.record.is_some_and(|v|!(5..=1800).contains(&v)) || a.interval_ms.is_some_and(|v|!(1000..=10000).contains(&v)) { return Err("Recording needs 5–1800 seconds and an interval of 1000–10000 ms.".into()); }
    if a.interval_ms.is_some() && a.record.is_none() { return Err("--interval-ms needs --record.".into()); }
    if a.problem_at.is_some() && a.timeline.is_none() { return Err("--problem-at needs --timeline.".into()); }
    if (a.include_logs || a.no_redact) && a.bundle.is_none() && a.bundle_preview.is_none() { return Err("Case privacy options need --bundle or --bundle-preview.".into()); }
    Ok(a)
}

/// Run the command line. Returns the process exit code.
pub fn main(argv: Vec<String>) -> i32 {
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("itriage: {e}");
            return 1;
        }
    };
    if args.help {
        print!("{USAGE}");
        return 0;
    }
    let loaded = profile::load();
    let mut profile = loaded.profile.clone();
    if args.redact_serial {
        profile.privacy.redact_serial = true;
    }
    let remote_safe = args.remote_safe.unwrap_or(profile.policy.remote_safe);

    if args.list {
        list(&profile, remote_safe);
        return 0;
    }
    if let Some((old, new)) = &args.compare {
        return compare(old, new, args.json, args.out.as_deref());
    }
    if args.baseline.is_some() || args.timeline.is_some() || args.bundle.is_some() || args.bundle_preview.is_some() {
        return match case_command(&args) { Ok(())=>0,Err(e)=>{ eprintln!("itriage: {e}"); 1 } };
    }
    if args.trends {
        return trends(args.json);
    }
    if let Some((id, target)) = &args.fix {
        return match crate::actions::run_for(id, target.as_deref(), &profile, remote_safe, args.ticket.as_deref()) {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(e) => {
                eprintln!("itriage: {e}");
                1
            }
        };
    }

    // --- What to run ---
    let target = match &args.target {
        Some(t) => {
            let mut text = t.clone();
            if let Some(p) = &args.ports {
                text = format!("{t} {p}");
            }
            match Target::parse(&text, &profile.network.target_ports) {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("itriage: {e}");
                    return 1;
                }
            }
        }
        None => None,
    };
    let mut wanted: Vec<String> = args.modules.clone();
    for name in &args.presets {
        match preset(name) {
            Some(p) => wanted.extend(p.modules.iter().map(|m| m.to_string())),
            None => {
                eprintln!(
                    "itriage: unknown preset `{name}` (one of: {})",
                    PRESETS.iter().map(|p| p.id).collect::<Vec<_>>().join(", ")
                );
                return 1;
            }
        }
    }
    if target.is_some() && !wanted.iter().any(|m| m == "net.target") {
        wanted.push("net.target".into());
    }
    let explicit = !wanted.is_empty();
    let os = std::env::consts::OS;
    let all = registry();
    let unknown: Vec<&String> = wanted.iter().filter(|w| !all.iter().any(|m| m.info().id == **w)).collect();
    let modules: Vec<_> = all
        .into_iter()
        .filter(|m| {
            let i = m.info();
            let here = i.platforms.contains(&os);
            if explicit {
                if wanted.contains(&i.id) && !here && !args.quiet {
                    eprintln!("skipping {} ({} only)", i.id, i.platforms.join("/"));
                }
                wanted.contains(&i.id) && here
            } else {
                !i.mutating && here && (!i.takes_target || target.is_some())
            }
        })
        .collect();
    if !unknown.is_empty() {
        eprintln!(
            "itriage: unknown module{} {} (try --list)",
            if unknown.len() == 1 { "" } else { "s" },
            unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
        return 1;
    }
    if modules.is_empty() {
        eprintln!("itriage: nothing to run (try --list)");
        return 1;
    }

    // --- Run ---
    let host = crate::host_context();
    let status = &loaded.status;
    if !args.quiet {
        eprintln!(
            "ITriage · {} · {} · {} · profile: {} ({}){}{}",
            host.hostname,
            host.os,
            if host.elevated { "elevated" } else { "standard user" },
            status.name,
            status.source,
            if args.what_if { " · PREVIEW" } else { "" },
            if remote_safe { " · REMOTE-SAFE" } else { "" },
        );
        if let Some(e) = &status.error {
            eprintln!("profile problem: {e}");
        }
    }
    let quiet = args.quiet;
    let log = move |line: &str| {
        if !quiet {
            eprintln!("    · {line}");
        }
    };
    let ticket = args.ticket.as_deref().and_then(report::clean_ticket);
    let mut ctx = RunContext::new(&log)
        .with_profile(&profile)
        .preview(args.what_if)
        .remote_safe(remote_safe)
        .with_ticket(ticket.as_deref());
    if let Some(t) = &target {
        ctx = ctx.with_target(t);
    }
    let (results, trace, capture) = if let Some(id) = &args.runbook {
        match guided::run_for(id,target.is_some(),|m,_,_,reason| { if !quiet { eprintln!("▶ {} · {reason}",m.info().title); } Some(m.run(&ctx)) }) {
            Ok((results,trace))=>(results,Some(trace),None),
            Err(e)=>{ eprintln!("itriage: {e}"); return 1; }
        }
    } else if let Some(seconds) = args.record {
        let config = recording::Config { seconds,interval_ms:args.interval_ms.unwrap_or(1000) };
        match recording::record(config,target.as_ref(),&ctx,&std::sync::Mutex::new(Vec::new()),|_|{}) {
            Ok(capture)=>(vec![recording::result(&capture)],None,Some(capture)),
            Err(e)=>{ eprintln!("itriage: {e}"); return 1; }
        }
    } else {
        let mut results = Vec::new();
        for m in &modules { if !quiet { eprintln!("▶ {}",m.info().title); } results.push(m.run(&ctx)); }
        (results,None,None)
    };
    crate::audit::run_finished(&results, false, ticket.as_deref());

    let profile_name = (status.source != "built-in").then(|| status.name.clone());
    let mut report = Report::new(host, profile_name, results, false).with_ticket(ticket.as_deref()).with_role(&profile.role);
    report.runbook = trace; report.recording = capture;
    let ids: Vec<String> = report.results.iter().map(|r| r.module_id.clone()).collect();
    let diff = report::previous(&report.host.hostname, &report.generated, &ids).map(|old| report::diff(&old, &report));
    let mut code = report.exit_code.unwrap_or(1);

    if !args.no_history {
        match report::save(&report, profile.history.keep) {
            Ok(p) if !args.quiet => eprintln!("saved: {}", p.display()),
            Ok(_) => {}
            Err(e) => eprintln!("itriage: couldn't save to history: {e}"),
        }
    }
    if let Some(out) = &args.out {
        let json = serde_json::to_string_pretty(&report).expect("report serializes");
        let text = report::render_text(&report, diff.as_ref(), true);
        let txt = out.with_extension("txt");
        let written = std::fs::write(out, json).and_then(|_| if txt != *out { std::fs::write(&txt, text) } else { Ok(()) });
        match written {
            Ok(()) if !args.quiet => eprintln!("written: {} and {}", out.display(), txt.display()),
            Ok(()) => {}
            Err(e) => {
                eprintln!("itriage: couldn't write {}: {e}", out.display());
                code = 1;
            }
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).expect("report serializes"));
    } else {
        println!("{}", report::render_text(&report, diff.as_ref(), args.logs));
    }
    code
}

fn list(profile: &Profile, remote_safe: bool) {
    let os = std::env::consts::OS;
    for m in registry() {
        let i: ModuleInfo = m.info();
        let mut tags = Vec::new();
        if i.mutating {
            tags.push("changes the machine".to_string());
        }
        if i.requires_admin {
            tags.push("admin".to_string());
        }
        if i.disruptive {
            tags.push(if remote_safe { "locked by remote-safe".into() } else { "can drop the session".to_string() });
        }
        if i.takes_target {
            tags.push("needs --target".to_string());
        }
        if !i.platforms.contains(&os) {
            tags.push(format!("{} only", i.platforms.join("/")));
        }
        if profile.block_reason(&i).is_some() {
            tags.push("blocked by profile".to_string());
        }
        let tags = if tags.is_empty() { String::new() } else { format!("  [{}]", tags.join(", ")) };
        println!("{:<18} {}{tags}", i.id, i.title);
    }
    println!();
    println!("Presets:");
    for p in PRESETS {
        let script = if p.script.is_empty() { String::new() } else { format!(" ({})", p.script) };
        println!("  --preset {:<8} {}{script}: {}", p.id, p.title, p.modules.join(" "));
    }
    println!("\nGuided troubleshooting (read-only):");
    for book in guided::RUNBOOKS { println!("  --runbook {:<10} {}",book.id,book.title); }
}

/// How each measurement has moved over this computer's saved runs.
fn trends(json: bool) -> i32 {
    let host = crate::host_context().hostname;
    let series = report::trends(&host);
    if json {
        println!("{}", serde_json::to_string_pretty(&series).expect("trends serialize"));
        return 0;
    }
    if series.is_empty() {
        println!("No trends yet for {host}: a measurement needs at least two saved runs.");
        return 0;
    }
    println!("Trends for {host}, oldest to newest");
    for s in &series {
        let (first, last) = (&s.points[0], &s.points[s.points.len() - 1]);
        let word = match report::movement(&s.unit, s.higher_is_worse, first.value, last.value) {
            report::Trend::Same => "about the same",
            report::Trend::Worse => "worse",
            report::Trend::Better => "better",
        };
        println!(
            "{:<28} {:<34} {} → {} over {} runs ({word})",
            s.module,
            s.label,
            report::metric_text(first.value, &s.unit),
            report::metric_text(last.value, &s.unit),
            s.points.len()
        );
    }
    0
}

/// Compare-NetTriage: two saved runs of one computer, as text (or JSON),
/// and with `--out` as a JSON file with the text beside it.
fn case_command(args: &Args) -> Result<(), String> {
    let text = if let Some((good, now)) = &args.baseline {
        serde_json::to_string_pretty(&baseline::compare(&report::load(good)?, &report::load(now)?)?).map_err(|e| e.to_string())?
    } else if let Some(path) = args.bundle.as_ref().or(args.bundle_preview.as_ref()) {
        let report = report::load(path)?;
        let prepared = bundle::prepare(
            &report,
            &bundle::Options {
                include_logs: args.include_logs,
                redact_identifiers: !args.no_redact,
                custom_terms: Vec::new(),
            },
        )?;
        if args.bundle.is_some() {
            let path = args
                .out
                .as_ref()
                .ok_or("--bundle requires --out CASE.zip. Use --bundle-preview first to review the contents.")?;
            prepared.write_new(path)?;
            println!("Case saved: {}", path.display());
            return Ok(());
        }
        serde_json::to_string_pretty(&prepared.preview).map_err(|e| e.to_string())?
    } else if let Some(path) = &args.timeline {
        let report = report::load(path)?;
        let rows = if let Some(at) = &args.problem_at {
            let at = timeline::problem_time(at)?;
            timeline::near(&report, at, 3600)
        } else {
            timeline::rows(&report)
        };
        serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
    } else {
        return Err("No case command selected.".into());
    };
    if let Some(path) = &args.out {
        std::fs::write(path, &text).map_err(|e| format!("Can't write {}: {e}", path.display()))?;
    }
    println!("{text}");
    Ok(())
}

fn compare(old: &std::path::Path, new: &std::path::Path, json: bool, out: Option<&std::path::Path>) -> i32 {
    let load = |p: &std::path::Path| report::load(p);
    let (a, b) = match (load(old), load(new)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("itriage: {e}");
            return 1;
        }
    };
    let d = match report::compare(&a, &b) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("itriage: {e}");
            return 1;
        }
    };
    let as_json = serde_json::to_string_pretty(&d).expect("diff serializes");
    let as_text = report::render_diff(&d, &a.host.hostname);
    let mut code = 0;
    if let Some(out) = out {
        let txt = out.with_extension("txt");
        let written = std::fs::write(out, &as_json).and_then(|_| if txt != out { std::fs::write(&txt, &as_text) } else { Ok(()) });
        if let Err(e) = written {
            eprintln!("itriage: couldn't write {}: {e}", out.display());
            code = 1;
        }
    }
    println!("{}", if json { &as_json } else { &as_text });
    code
}

/// Windows release builds are GUI programs, which start without a console.
/// When one is run from a command prompt with arguments, write to that
/// prompt's console (unless output is already redirected to a file or pipe).
#[cfg(windows)]
pub fn attach_console() {
    use windows::Win32::System::Console::{AttachConsole, GetStdHandle, ATTACH_PARENT_PROCESS, STD_OUTPUT_HANDLE};
    // SAFETY: plain Win32 calls; failure just means there's no console to use.
    unsafe {
        let redirected = GetStdHandle(STD_OUTPUT_HANDLE).is_ok_and(|h| !h.is_invalid() && !h.0.is_null());
        if !redirected {
            let _ = AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

#[cfg(not(windows))]
pub fn attach_console() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Args {
        parse(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn case_command_modes_cannot_silently_ignore_other_work() {
        for argv in [vec!["--runbook","vpn","--record","5"],vec!["--record","4"],vec!["--record","10","--interval-ms","0"],vec!["--runbook","printing","fix.dns"],vec!["--bundle","report.json","--preset","tuneup"],vec!["--interval-ms","1000"],vec!["--no-redact"],vec!["--problem-at","2026-11-10T12:00:00Z"]] {
            let values=argv.iter().map(|s|s.to_string()).collect::<Vec<_>>();assert!(parse(&values).is_err(),"{argv:?}");
        }
        assert_eq!(args(&["--record","5","--interval-ms","2000"]).record,Some(5));
        assert_eq!(args(&["--baseline","good.json","now.json"]).baseline.unwrap().0,PathBuf::from("good.json"));
    }

    #[test]
    fn parses_the_command_line() {
        let a = args(&["--preset", "triage", "--target=fileserver01:445", "--what-if", "--json", "desk.time"]);
        assert_eq!(a.presets, vec!["triage"]);
        assert_eq!(a.target.as_deref(), Some("fileserver01:445"));
        assert!(a.what_if && a.json);
        assert_eq!(a.modules, vec!["desk.time"]);
        let f = args(&["--fix", "start-service", "Spooler"]);
        assert_eq!(f.fix, Some(("start-service".into(), Some("Spooler".into()))));
        let f = args(&["--fix", "flush-dns", "--quiet"]);
        assert_eq!(f.fix, Some(("flush-dns".into(), None)));
        assert!(f.quiet);
        let c = args(&["--compare", "a.json", "b.json"]);
        assert_eq!(c.compare.unwrap().1, PathBuf::from("b.json"));
        assert_eq!(args(&["--no-remote-safe"]).remote_safe, Some(false));
        assert_eq!(args(&["--ticket", "INC0012345", "--trends"]).ticket.as_deref(), Some("INC0012345"));
        assert!(args(&["--ticket=INC1", "--trends"]).trends);
        assert!(parse(&["--bogus".to_string()]).is_err());
        assert!(parse(&["--target".to_string()]).is_err());
    }

    #[test]
    fn bad_input_exits_1() {
        let run = |a: &[&str]| main(a.iter().map(|s| s.to_string()).collect());
        assert_eq!(run(&["--help"]), 0);
        assert_eq!(run(&["--no-such-flag"]), 1);
        assert_eq!(run(&["--quiet", "--no-history", "no.such.module"]), 1);
        assert_eq!(run(&["--quiet", "--no-history", "--preset", "nope"]), 1);
        assert_eq!(run(&["--quiet", "--no-history", "--target", "bad host;x"]), 1);
        assert_eq!(run(&["--compare", "missing-a.json", "missing-b.json"]), 1);
    }

    #[test]
    fn compares_two_saved_runs_and_writes_the_comparison() {
        use crate::model::{Category, Finding, ModuleResult};
        let dir = std::env::current_dir().unwrap().join("target").join(format!("itriage-cli-compare-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let run_at = |when: &str, ms: f64| {
            let finding = if ms > 20.0 { Finding::warn("Gateway round trip", format!("avg {ms} ms")) } else { Finding::ok("Gateway round trip", format!("avg {ms} ms")) };
            let result = ModuleResult {
                module_id: "net.latency".into(),
                title: "Latency & packet loss".into(),
                category: Category::Network,
                findings: vec![finding.with_metric(ms, "ms", true)],
                summary: String::new(),
                error: None,
                duration_ms: 1,
                log: Vec::new(),
                restart_required: false,
                preview: false,
            };
            let mut r = Report::new(crate::host_context(), None, vec![result], false);
            r.generated = when.into();
            serde_json::to_string(&r).unwrap()
        };
        let (before, after, out) = (dir.join("before.json"), dir.join("after.json"), dir.join("comparison.json"));
        std::fs::write(&before, run_at("2026-11-01T10:00:00Z", 38.0)).unwrap();
        std::fs::write(&after, run_at("2026-11-02T10:00:00Z", 3.0)).unwrap();
        let path = |p: &std::path::Path| p.display().to_string();
        let code = main(vec!["--compare".into(), path(&after), path(&before), "--out".into(), path(&out)]);
        assert_eq!(code, 0);
        let diff: crate::report::ReportDiff = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(diff.resolved, 1, "the older run is the baseline, whichever order they're given");
        let text = std::fs::read_to_string(out.with_extension("txt")).unwrap();
        assert!(text.contains("38 ms → 3 ms"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn previews_change_nothing_and_finish() {
        let code = main(
            ["--quiet", "--no-history", "--what-if", "fix.temp", "fix.dns"].iter().map(|s| s.to_string()).collect(),
        );
        assert_eq!(code, 0, "a preview of mutating modules finishes cleanly");
    }
}
