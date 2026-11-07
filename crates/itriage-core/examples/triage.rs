//! Headless runner for itriage-core. Useful on boxes without a desktop, over
//! SSH or a remote shell, and for exercising modules while developing.
//!
//!   cargo run -p itriage-core --example triage -- --list
//!   cargo run -p itriage-core --example triage                  # every read-only module
//!   cargo run -p itriage-core --example triage -- proc.services desk.printers
//!   cargo run -p itriage-core --example triage -- --json > report.json
//!
//! `--json` prints a full report (the same format the app saves to its
//! history), so a run on a remote machine can be opened and compared in the
//! app with "Open report". The site profile is found the same way the app
//! finds it; set ITRIAGE_PROFILE=<file> to try one. Mutating modules only run
//! when named explicitly, and the profile's policy still applies to them.

use itriage_core::{host_context, profile, registry, report::Report, RunContext};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let loaded = profile::load();

    if args.iter().any(|a| a == "--list") {
        for m in registry() {
            let i = m.info();
            let mut tags = Vec::new();
            if i.mutating {
                tags.push("mutating".to_string());
            }
            if i.requires_admin {
                tags.push("admin".to_string());
            }
            if !i.platforms.contains(&std::env::consts::OS) {
                tags.push(format!("{} only", i.platforms.join("/")));
            }
            if loaded.profile.block_reason(&i).is_some() {
                tags.push("blocked by profile".to_string());
            }
            let tags = if tags.is_empty() { String::new() } else { format!("  [{}]", tags.join(", ")) };
            println!("{:<18} {}{tags}", i.id, i.title);
        }
        return;
    }

    let ids: Vec<String> = args.iter().filter(|a| !a.starts_with("--")).cloned().collect();
    let modules: Vec<_> = registry()
        .into_iter()
        .filter(|m| {
            let i = m.info();
            if ids.is_empty() {
                !i.mutating && i.platforms.contains(&std::env::consts::OS)
            } else {
                ids.contains(&i.id)
            }
        })
        .collect();
    if modules.is_empty() {
        eprintln!("No matching modules. Try --list.");
        std::process::exit(2);
    }

    let host = host_context();
    let status = &loaded.status;
    eprintln!(
        "itriage · {} · {} · {} · profile: {} ({})",
        host.hostname,
        host.os,
        if host.elevated { "elevated" } else { "standard user" },
        status.name,
        status.source
    );
    if let Some(e) = &status.error {
        eprintln!("profile problem: {e}");
    }

    let log = |line: &str| eprintln!("    · {line}");
    let ctx = RunContext::new(&log).with_profile(&loaded.profile);
    let mut results = Vec::new();
    for m in &modules {
        eprintln!("▶ {}", m.info().title);
        results.push(m.run(&ctx));
    }

    if json {
        let profile_name = (status.source != "built-in").then(|| status.name.clone());
        let report = Report::new(host, profile_name, results, false);
        println!("{}", serde_json::to_string_pretty(&report).expect("report serializes"));
        return;
    }

    println!();
    for r in &results {
        let status = format!("{:?}", r.status()).to_uppercase();
        let summary = match &r.error {
            Some(_) => "FAILED",
            None => r.summary.as_str(),
        };
        println!("[{status}] {} ({} ms): {summary}", r.title, r.duration_ms);
        if let Some(e) = &r.error {
            println!("    error: {e}");
        }
        for f in &r.findings {
            println!("    {:<9} {}: {}", format!("{:?}", f.severity).to_lowercase(), f.label, f.value);
            if let Some(d) = &f.detail {
                println!("              {d}");
            }
            if let Some(a) = &f.action {
                println!("              fix available: {}", a.label);
            }
            if let Some(kb) = &f.kb {
                println!("              KB: {} <{}>", kb.title, kb.url);
            }
        }
        println!();
    }
}
